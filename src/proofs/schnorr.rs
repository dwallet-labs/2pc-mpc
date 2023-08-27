// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;

use crypto_bigint::rand_core::CryptoRngCore;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::Result;
use crate::{
    group::GroupElement,
    marker::Marker,
    proofs::{Error, TranscriptProtocol},
    ComputationalSecuritySizedNumber,
};

/// A Schnorr Zero-Knowledge Proof Language
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof`
/// As defined in Appendix B. Schnorr Protocols in the paper
pub trait Language<
    // The upper bound for the scalar size of the witness group
    const WITNESS_SCALAR_LIMBS: usize,
    // The upper bound for the scalar size of the associated public-value space group
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    // An element of the witness space $(\HH, +)$
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    // An element in the associated public-value space $(\GG, \cdot)$
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
>
{
    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$
    ///
    /// Must uniquely identify the witness and statement spaces,
    /// as well as including all public parameters of the language
    /// (e.g., the public parameters of the commitment scheme used for proving knowledge of
    /// decommitment - the bases $g$, $h$ in the case of Pedersen)
    ///
    /// By restricting `Borrow` here we assure that `PublicParameters` encodes both
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `PublicValueSpaceGroupElement::PublicParameters`, which restricts implementors to hold
    /// copies of these values inside the struct they use for `PublicParameters`.
    type PublicParameters: Serialize
        + PartialEq
        + Borrow<WitnessSpaceGroupElement::PublicParameters>
        + Borrow<PublicValueSpaceGroupElement::PublicParameters>;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// $\phi:\HH\to\GG$ a group homomorphism from $(\HH_\pp, +)$, the witness space, to $(\GG_\pp,
    /// \cdot)$, the statement space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
    ) -> PublicValueSpaceGroupElement;
}

/// An Enhanced Batched Schnorr Zero-Knowledge Proof
/// Implements Appendix B. Schnorr Protocols in the paper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
    L,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext,
> {
    statement_mask: PublicValueSpaceGroupElement::Value,
    response: WitnessSpaceGroupElement::Value,

    _language_choice: Marker<L>,
    _protocol_context_choice: Marker<ProtocolContext>,
}

impl<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
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
            _language_choice: Marker::<L>::new(),
            _protocol_context_choice: Marker::<ProtocolContext>::new(),
        }
    }

    /// Prove an enhanced batched Schnorr zero-knowledge claim
    /// Returns the zero-knowledge proof
    pub fn prove(
        protocol_context: &ProtocolContext,
        public_parameters: &L::PublicParameters,
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

        let mut transcript = Self::setup_protocol(protocol_context, public_parameters, statements)?;

        let randomizer = WitnessSpaceGroupElement::sample(rng);

        let statement_mask = L::group_homomorphism(&randomizer, public_parameters);

        let challenges: Vec<ComputationalSecuritySizedNumber> =
            Self::compute_challenges(&statement_mask.value(), batch_size, &mut transcript)?;

        let response = randomizer
            + witnesses
                .into_iter()
                .zip(challenges)
                .map(|(witness, challenge)| witness.scalar_mul(challenge))
                .reduce(|a, b| a + b)
                .unwrap();

        Ok(Self::new(statement_mask, response))
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof
    pub fn verify(
        &self,
        _protocol_context: &ProtocolContext,
        _public_parameters: &L::PublicParameters,
        _statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<()> {
        todo!()
    }

    fn setup_protocol(
        protocol_context: &ProtocolContext,
        public_parameters: &L::PublicParameters,
        statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(L::NAME.as_bytes());

        // TODO: should we add anything on the challenge space E? Even though it's hardcoded U128?

        transcript
            .serialize_to_transcript_as_json(b"protocol context", protocol_context)
            .map_err(|_e| Error::InvalidParameters())?;

        transcript
            .serialize_to_transcript_as_json(b"public parameters", public_parameters)
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
    ) -> Result<Vec<ComputationalSecuritySizedNumber>> {
        transcript
            .serialize_to_transcript_as_json(b"randomizer public value", statement_mask_value)
            .map_err(|_e| Error::InvalidParameters())?;

        Ok((1..=batch_size)
            .map(|_| {
                // The `.challenge` method mutates `transcript` by adding the label to it.
                // Although the same label is used for all values,
                // each value will be a digest of different values
                // (i.e. it will hold different `multiple` of the label inside the digest),
                // and will therefore be unique.
                transcript.challenge(b"challenge")

                // TODO: should we also add the challenge to the transcript?
            })
            .collect())
    }
}
