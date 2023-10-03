// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

pub mod enhanced;

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, ConcatMixed, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    group::{GroupElement, Samplable},
    proofs,
    proofs::{
        schnorr::{
            language,
            language::{
                PublicParameters, StatementSpaceGroupElement, StatementSpaceValue,
                WitnessSpaceGroupElement, WitnessSpaceValue,
            },
        },
        Error, TranscriptProtocol,
    },
    ComputationalSecuritySizedNumber,
};

// For a batch size $N_B$, the challenge space should be $[0,N_B \cdot 2^{\kappa + 2})$.
// Setting it to be 64-bit larger than the computational security parameter $\kappa$ allows us to
// practically use any batch size (Rust does not allow a vector larger than $2^64$ elements,
// as does 64-bit architectures in which the memory won't even be addressable.)

// TODO: we said we don't need the +64 anymore right?
// pub(super) type ChallengeSizedNumber =
//     <ComputationalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput;

pub(super) type ChallengeSizedNumber = ComputationalSecuritySizedNumber;

/// A Batched Schnorr Zero-Knowledge Proof.
/// Implements Appendix B. Schnorr Protocols in the paper.
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof<
    // The language we are proving
    Language: language::Language,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    pub(super) statement_mask: StatementSpaceValue<Language>,
    pub(super) response: WitnessSpaceValue<Language>,

    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<Language: language::Language, ProtocolContext: Clone + Serialize>
    Proof<Language, ProtocolContext>
{
    fn new(
        statement_mask: StatementSpaceGroupElement<Language>,
        response: WitnessSpaceGroupElement<Language>,
    ) -> Self {
        Self {
            statement_mask: statement_mask.value(),
            response: response.value(),
            _protocol_context_choice: PhantomData,
        }
    }

    /// Prove a batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        witnesses: Vec<WitnessSpaceGroupElement<Language>>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self, Vec<StatementSpaceGroupElement<Language>>)> {
        let statements: proofs::Result<Vec<StatementSpaceGroupElement<Language>>> = witnesses
            .iter()
            .map(|witness| Language::group_homomorphism(witness, language_public_parameters))
            .collect();
        let statements = statements?;

        Self::prove_with_statements(
            protocol_context,
            language_public_parameters,
            witnesses,
            statements.clone(),
            rng,
        )
        .map(|proof| (proof, statements))
    }

    fn prove_with_statements(
        protocol_context: &ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        witnesses: Vec<WitnessSpaceGroupElement<Language>>,
        statements: Vec<StatementSpaceGroupElement<Language>>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<Self> {
        if witnesses.is_empty() {
            return Err(Error::InvalidParameters);
        }

        let batch_size = witnesses.len();

        let mut transcript = Self::setup_protocol(
            protocol_context,
            language_public_parameters,
            statements.clone(),
        )?;

        let randomizer = WitnessSpaceGroupElement::<Language>::sample(
            rng,
            &language_public_parameters
                .as_ref()
                .witness_space_public_parameters,
        )?;

        let statement_mask = Language::group_homomorphism(&randomizer, language_public_parameters)?;

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

    /// Verify a batched Schnorr zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        statements: Vec<StatementSpaceGroupElement<Language>>,
    ) -> proofs::Result<()> {
        let batch_size = statements.len();

        let mut transcript = Self::setup_protocol(
            protocol_context,
            language_public_parameters,
            statements.clone(),
        )?;

        let challenges: Vec<ChallengeSizedNumber> =
            Self::compute_challenges(&self.statement_mask, batch_size, &mut transcript)?;

        let response = WitnessSpaceGroupElement::<Language>::new(
            self.response.clone(),
            &language_public_parameters
                .as_ref()
                .witness_space_public_parameters,
        )?;

        let statement_mask = StatementSpaceGroupElement::<Language>::new(
            self.statement_mask.clone(),
            &language_public_parameters
                .as_ref()
                .statement_space_public_parameters,
        )?;

        let response_statement: StatementSpaceGroupElement<Language> =
            Language::group_homomorphism(&response, language_public_parameters)?;

        let reconstructed_response_statement: StatementSpaceGroupElement<Language> = statement_mask
            + statements
                .into_iter()
                .zip(challenges)
                .map(|(statement, challenge)| statement.scalar_mul(&challenge))
                .reduce(|a, b| a + b)
                .unwrap();

        if response_statement == reconstructed_response_statement {
            return Ok(());
        }
        Err(Error::ProofVerification)
    }

    fn setup_protocol(
        protocol_context: &ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        statements: Vec<StatementSpaceGroupElement<Language>>,
    ) -> proofs::Result<Transcript> {
        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        transcript.serialize_to_transcript_as_json(
            b"language public parameters",
            language_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"witness space public parameters",
            &language_public_parameters
                .as_ref()
                .witness_space_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"statement space public parameters",
            &language_public_parameters
                .as_ref()
                .statement_space_public_parameters,
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
        statement_mask_value: &StatementSpaceValue<Language>,
        batch_size: usize,
        transcript: &mut Transcript,
    ) -> proofs::Result<Vec<ChallengeSizedNumber>> {
        transcript
            .serialize_to_transcript_as_json(b"statement mask value", statement_mask_value)?;

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
