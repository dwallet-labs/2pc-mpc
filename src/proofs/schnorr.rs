// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

pub mod commitment_of_discrete_log;

pub mod knowledge_of_discrete_log;

pub mod knowledge_of_decommitment;

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, ConcatMixed, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::{Error, Result, TranscriptProtocol};
use crate::{
    group,
    group::{GroupElement, Samplable},
    ComputationalSecuritySizedNumber,
};

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
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable<WITNESS_SCALAR_LIMBS>,
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
    /// to $(\GG_\pp,\cdot)$, the public-value space space.
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
        WitnessSpaceGroupElement: Samplable<WITNESS_SCALAR_LIMBS>,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        Lang: Language<
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
        Lang,
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
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        witnesses_and_statements: Vec<(WitnessSpaceGroupElement, PublicValueSpaceGroupElement)>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if witnesses_and_statements.is_empty() {
            return Err(Error::InvalidParameters);
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

        let randomizer = WitnessSpaceGroupElement::sample(rng, witness_space_public_parameters);

        let statement_mask = Lang::group_homomorphism(
            &randomizer,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
        )?;

        let challenges: Vec<ChallengeSizedNumber> =
            Self::compute_challenges(&statement_mask.value(), batch_size, &mut transcript)?;

        // Using the "small exponents" method for batching;
        // the exponents actually need to account for the batch size.
        // We added 64-bit for that, which is fine for sampling randmoness,
        // but in practice the exponentiation (i.e. `scalar_mul`) could use
        // the real bound: `128 + log2(BatchSize)+2 < 192` to increase performance.
        // We leave that as future work in case this becomes a bottleneck.
        let response = randomizer
            + witnesses
                .into_iter()
                .zip(challenges)
                .map(|(witness, challenge)| witness.scalar_mul(&challenge))
                .reduce(|a, b| a + b)
                .unwrap();

        Ok(Self::new(statement_mask, response))
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: ProtocolContext,
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<()> {
        let batch_size = statements.len();

        let mut transcript = Self::setup_protocol(
            &protocol_context,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
            statements.clone(),
        )?;

        let challenges: Vec<ChallengeSizedNumber> =
            Self::compute_challenges(&self.statement_mask, batch_size, &mut transcript)?;

        let response =
            WitnessSpaceGroupElement::new(self.response.clone(), witness_space_public_parameters)?;

        let statement_mask = PublicValueSpaceGroupElement::new(
            self.statement_mask.clone(),
            public_value_space_public_parameters,
        )?;

        let response_statement: PublicValueSpaceGroupElement = Lang::group_homomorphism(
            &response,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
        )?;

        let reconstructed_response_statement: PublicValueSpaceGroupElement = statement_mask
            + statements
                .into_iter()
                .zip(challenges)
                .map(|(statement, challenge)| statement.scalar_mul(&challenge))
                .reduce(|a, b| a + b)
                .unwrap();

        if response_statement == reconstructed_response_statement {
            return Ok(());
        }
        Err(Error::ProofVerificationError)
    }

    fn setup_protocol(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(Lang::NAME.as_bytes());

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        transcript.serialize_to_transcript_as_json(
            b"language public parameters",
            language_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"witness space public parameters",
            witness_space_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"public value space public parameters",
            public_value_space_public_parameters,
        )?;

        if statements.iter().any(|statement| {
            transcript
                .serialize_to_transcript_as_json(b"statement value", &statement.value())
                .is_err()
        }) {
            return Err(Error::InvalidParameters);
        }

        Ok(transcript)
    }

    fn compute_challenges(
        statement_mask_value: &PublicValueSpaceGroupElement::Value,
        batch_size: usize,
        transcript: &mut Transcript,
    ) -> Result<Vec<ChallengeSizedNumber>> {
        transcript
            .serialize_to_transcript_as_json(b"randomizer public value", statement_mask_value)?;

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
