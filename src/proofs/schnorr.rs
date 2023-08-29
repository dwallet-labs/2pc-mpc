// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, ConcatMixed, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::{Error, Result, TranscriptProtocol};
use crate::{group, group::GroupElement, traits::Samplable, ComputationalSecuritySizedNumber};

// For a batch size $N_B$, the challenge space should be $[0,N_B \cdot 2^{\kappa + 2})$.
// Setting it to be 64-bit larger than the computational security parameter $\kappa$ allows us to
// practically use any batch size (Rust does not allow a vector larger than $2^64$ elements,
// as does 64-bit architectures in which the memory won't even be addressable.)
type ChallengeSizedNumber = <ComputationalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput;

/// A Schnorr Zero-Knowledge Proof Language
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof`
/// As defined in Appendix B. Schnorr Protocols in the paper
pub trait Language<
    // The upper bound for the scalar size of the witness group
    const WITNESS_SCALAR_LIMBS: usize,
    // The upper bound for the scalar size of the associated public-value space group
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    // An element of the witness space $(\HH_\pp, +)$
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable,
    // An element in the associated public-value space $(\GG_\pp, \cdot)$,
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
>
{
    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$
    ///
    /// Used for language-specific parameters (e.g., the public parameters of the commitment scheme
    /// used for proving knowledge of decommitment - the bases $g$, $h$ in the case of Pedersen).
    ///
    /// Group public parameters are encoded separately in
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `PublicValueSpaceGroupElement::PublicParameters`.
    type PublicParameters: Serialize + PartialEq;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// A group homomorphism $\phi:\HH\to\GG$  from $(\HH_\pp, +)$, the witness space,
    /// to $(\GG_\pp,\cdot)$, the statement space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
    ) -> group::Result<PublicValueSpaceGroupElement>;
}

/// An Enhanced Batched Schnorr Zero-Knowledge Proof.
/// Implements Appendix B. Schnorr Protocols in the paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
    Lang,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext,
> {
    statement_mask: PublicValueSpaceGroupElement::Value,
    response: WitnessSpaceGroupElement::Value,

    _language_choice: PhantomData<Lang>,
    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        L: Language<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
        >,
        ProtocolContext: Serialize,
    >
    Proof<
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        WitnessSpaceGroupElement,
        PublicValueSpaceGroupElement,
        L,
        ProtocolContext,
    >
{
    fn new(
        statement_mask: PublicValueSpaceGroupElement,
        response: WitnessSpaceGroupElement,
    ) -> Self {
        Self {
            statement_mask: statement_mask.value(),
            response: response.value(),
            _language_choice: PhantomData,
            _protocol_context_choice: PhantomData,
        }
    }

    /// Prove an enhanced batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: ProtocolContext,
        language_public_parameters: &L::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        witnesses_and_statements: Vec<(WitnessSpaceGroupElement, PublicValueSpaceGroupElement)>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if witnesses_and_statements.is_empty() {
            return Err(Error::InvalidParameters());
        }

        let batch_size = witnesses_and_statements.len();

        let (witnesses, statements): (
            Vec<WitnessSpaceGroupElement>,
            Vec<PublicValueSpaceGroupElement>,
        ) = witnesses_and_statements.iter().cloned().unzip();

        let mut transcript = Self::setup_protocol(
            &protocol_context,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
            statements,
        )?;

        let randomizer = WitnessSpaceGroupElement::sample(rng);

        let statement_mask = L::group_homomorphism(
            &randomizer,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
        )
        .map_err(|_| Error::InvalidParameters())?;

        let challenges: Vec<ChallengeSizedNumber> =
            Self::compute_challenges(&statement_mask.value(), batch_size, &mut transcript)?;

        // TODO: do I need to handle the e < 0 case? if not, please update the paper
        let response = randomizer
            + witnesses
                .into_iter()
                .zip(challenges)
                .map(|(witness, challenge)| witness.scalar_mul(&challenge))
                .reduce(|a, b| a + b)
                .unwrap();

        Ok(Self::new(statement_mask, response))
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof
    pub fn verify(
        &self,
        _protocol_context: ProtocolContext,
        _language_public_parameters: &L::PublicParameters,
        _witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        _public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        _statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<()> {
        todo!()
    }

    fn setup_protocol(
        protocol_context: &ProtocolContext,
        language_public_parameters: &L::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(L::NAME.as_bytes());

        // TODO: now that the challenge space is hard-coded U192, we don't need to anything about it
        // right?

        transcript
            .serialize_to_transcript_as_json(b"protocol context", protocol_context)
            .map_err(|_e| Error::InvalidParameters())?;

        transcript
            .serialize_to_transcript_as_json(
                b"language public parameters",
                language_public_parameters,
            )
            .map_err(|_e| Error::InvalidParameters())?;

        transcript
            .serialize_to_transcript_as_json(
                b"witness space public parameters",
                witness_space_public_parameters,
            )
            .map_err(|_e| Error::InvalidParameters())?;

        transcript
            .serialize_to_transcript_as_json(
                b"public value space public parameters",
                public_value_space_public_parameters,
            )
            .map_err(|_e| Error::InvalidParameters())?;

        if statements
            .iter()
            .map(|statement| {
                transcript.serialize_to_transcript_as_json(b"statement value", &statement.value())
            })
            .any(|res| res.is_err())
        {
            return Err(Error::InvalidParameters());
        }

        Ok(transcript)
    }

    fn compute_challenges(
        statement_mask_value: &PublicValueSpaceGroupElement::Value,
        batch_size: usize,
        transcript: &mut Transcript,
    ) -> Result<Vec<ChallengeSizedNumber>> {
        transcript
            .serialize_to_transcript_as_json(b"randomizer public value", statement_mask_value)
            .map_err(|_e| Error::InvalidParameters())?;

        Ok((1..=batch_size)
            .map(|_| {
                let challenge = transcript.challenge(b"challenge");

                // we don't have to do this because Merlin uses a PRF behind the scenes,
                // but we do it anyways as a security best-practice
                transcript.append_uint(b"challenge", &challenge);

                challenge
            })
            .collect())
    }
}
