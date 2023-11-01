// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod enhanced;

use std::{array, marker::PhantomData};

use crypto_bigint::{rand_core::CryptoRngCore, ConcatMixed, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{GroupElement, Samplable},
    helpers::flat_map_results,
    proofs,
    proofs::{
        schnorr::{
            language,
            language::{StatementSpaceValue, WitnessSpaceValue},
        },
        Error, TranscriptProtocol,
    },
    ComputationalSecuritySizedNumber, COMPUTATIONAL_SECURITY_PARAMETERS,
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
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The language we are proving
    Language: language::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    #[serde(with = "crate::helpers::const_generic_array_serialization")]
    pub(super) statement_masks: [StatementSpaceValue<REPETITIONS, Language>; REPETITIONS],
    #[serde(with = "crate::helpers::const_generic_array_serialization")]
    pub(super) responses: [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS],

    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > Proof<REPETITIONS, Language, ProtocolContext>
{
    pub(super) fn new(
        statement_masks: &[Language::StatementSpaceGroupElement; REPETITIONS],
        responses: &[Language::WitnessSpaceGroupElement; REPETITIONS],
    ) -> Self {
        // TODO: this is the second time, after adding to transcript, that we call `.value()` for
        // statement masks. Also, maybe get the values as parameter directly
        Self {
            statement_masks: statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
            responses: responses.clone().map(|response| response.value()),
            _protocol_context_choice: PhantomData,
        }
    }

    /// Prove a batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self, Vec<Language::StatementSpaceGroupElement>)> {
        let statements: proofs::Result<Vec<Language::StatementSpaceGroupElement>> = witnesses
            .iter()
            .map(|witness| Language::group_homomorphism(witness, language_public_parameters))
            .collect();
        let statements = statements?;

        // TODOs
        // 1. the challenge size in bits should be a (public) parameter (of the language). This also
        //    means we need a "scalar_mul_bounded" trait
        // 3. repetations (use const-generics):
        //     - sample r randomizers -> statement-mask
        //     - add all of them to the transcript.
        //     - compute r vectors of batch_size challenges
        //     - then for each such vector compute the response, the proof has r such responses + r
        //       statement masks => array of R normal proofs.
        // So maybe, we can use the same code just have one shared transcript for it
        // verifying is the same, but again need to have the shared transcript.
        // 4. range check - no need to check response is smaller than upper bound if we set the
        //    witness size to a group of the specific size that we prove the range for.
        // gap is for the prover not the verifier i.e. the verifier know that the witness is of
        // witness size, i.e. response size, but prover had to have the witness even smaller than
        // that
        // 5. aggregation
        // 6. randomizer should be bigger than the witness max size by 128-bit + challenge size.
        //    witness max size should be defined in the public paramters, and then randomizer size
        //    is bigger than that using above formula and is also dynamic. so the sampling should be
        //    bounded. And then it doesn't need to be the phi(n) bullshit, we just need to have the
        //    witness group be of size range claim upper bound + 128 + challenge size.
        // language: (w, r) -> g^r*h^w (meaning a normal pedersen commitment, )
        // 7. if we don't use multiplies of LIMB we need to do the range check.
        // number of parties also need to be accounted for in aggregation for the size of the
        // witness of the language. or we take an upper bound for it.

        Self::prove_with_statements(
            protocol_context,
            language_public_parameters,
            witnesses,
            statements.clone(),
            rng,
        )
        .map(|proof| (proof, statements))
    }

    pub(super) fn prove_with_statements(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        statements: Vec<Language::StatementSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<Self> {
        let (randomizers, statement_masks) =
            Self::sample_randomizers_and_statement_masks(language_public_parameters, rng)?;

        Self::prove_inner(
            protocol_context,
            language_public_parameters,
            witnesses,
            statements.clone(),
            randomizers,
            statement_masks,
        )
    }

    pub(super) fn prove_inner(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        statements: Vec<Language::StatementSpaceGroupElement>,
        randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
        statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    ) -> proofs::Result<Self> {
        if witnesses.is_empty() {
            return Err(Error::InvalidParameters);
        }

        let batch_size = witnesses.len();

        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
        )?;

        // TODO: maybe sample should also return the value, so no expensive conversion is necessairy
        // with `.value()`?

        let challenges: [Vec<ChallengeSizedNumber>; REPETITIONS] =
            Self::compute_challenges(batch_size, &mut transcript);

        // Another: TODO: these don't go through modulation and we can do them not in the group

        // Using the "small exponents" method for batching;
        // the exponents actually need to account for the batch size.
        // We added 64-bit for that, which is fine for sampling randmoness,
        // but in practice the exponentiation (i.e. `scalar_mul`) could use
        // the real bound: `128 + log2(BatchSize)+2 < 192` to increase performance.
        // We leave that as future work in case this becomes a bottleneck.

        // TODO: update comment now that it isn't necessairly 128 bit
        // TODO: scalar_mul_bounded

        let responses = randomizers
            .into_iter()
            .zip(challenges)
            .map(|(randomizer, challenges_for_iteration)| {
                randomizer
                    + witnesses
                        .clone()
                        .into_iter()
                        .zip(challenges_for_iteration)
                        .map(|(witness, challenge)| witness.scalar_mul(&challenge))
                        .reduce(|a, b| a + b)
                        .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| proofs::Error::Conversion)?;

        Ok(Self::new(&statement_masks, &responses))
    }

    /// Verify a batched Schnorr zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<Language::StatementSpaceGroupElement>,
    ) -> proofs::Result<()> {
        let batch_size = statements.len();

        // TODO: maybe here we can get statements as values already, esp. if we sample them this
        // way?
        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &self.statement_masks,
        )?;

        let challenges: [Vec<ChallengeSizedNumber>; REPETITIONS] =
            Self::compute_challenges(batch_size, &mut transcript);

        let responses = flat_map_results(self.responses.map(|response| {
            Language::WitnessSpaceGroupElement::new(
                response,
                &language_public_parameters
                    .as_ref()
                    .witness_space_public_parameters,
            )
        }))?;

        let statement_masks = flat_map_results(self.statement_masks.map(|statement_mask| {
            Language::StatementSpaceGroupElement::new(
                statement_mask,
                &language_public_parameters
                    .as_ref()
                    .statement_space_public_parameters,
            )
        }))?;

        let response_statements: [Language::StatementSpaceGroupElement; REPETITIONS] =
            flat_map_results(responses.map(|response| {
                Language::group_homomorphism(&response, language_public_parameters)
            }))?;

        // TODO: helper function that zips
        // TODO: scalar_mul_bounded
        let reconstructed_response_statements: [Language::StatementSpaceGroupElement; REPETITIONS] =
            statement_masks
                .into_iter()
                .zip(challenges)
                .map(|(statement_mask, challenges_for_iteration)| {
                    statement_mask
                        + statements
                            .clone()
                            .into_iter()
                            .zip(challenges_for_iteration)
                            .map(|(statement, challenge)| statement.scalar_mul(&challenge))
                            .reduce(|a, b| a + b)
                            .unwrap()
                })
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| proofs::Error::Conversion)?;

        if response_statements == reconstructed_response_statements {
            return Ok(());
        }
        Err(Error::ProofVerification)
    }

    pub(super) fn sample_randomizers_and_statement_masks(
        language_public_parameters: &Language::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        [Language::WitnessSpaceGroupElement; REPETITIONS],
        [Language::StatementSpaceGroupElement; REPETITIONS],
    )> {
        let randomizers = flat_map_results(array::from_fn(|_| {
            Language::WitnessSpaceGroupElement::sample(
                rng,
                &language_public_parameters
                    .as_ref()
                    .witness_space_public_parameters,
            )
        }))?;

        let statement_masks = flat_map_results(randomizers.clone().map(|randomizer| {
            Language::group_homomorphism(&randomizer, language_public_parameters)
        }))?;

        Ok((randomizers, statement_masks))
    }

    pub(super) fn setup_transcript(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<group::Value<Language::StatementSpaceGroupElement>>,
        statement_masks_values: &[group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
    ) -> proofs::Result<Transcript> {
        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        // TODO: replace `Serialize` with `Into<Vec<u8>>` and comment this back in, this is slower
        // than originally imagined.

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
                .serialize_to_transcript_as_json(b"statement value", &statement)
                .is_err()
        }) {
            return Err(Error::InvalidParameters);
        }

        if statement_masks_values.iter().any(|statement_mask| {
            transcript
                .serialize_to_transcript_as_json(b"statement mask value", &statement_mask)
                .is_err()
        }) {
            return Err(Error::InvalidParameters);
        }

        Ok(transcript)
    }

    fn compute_challenges(
        batch_size: usize,
        transcript: &mut Transcript,
    ) -> [Vec<ChallengeSizedNumber>; REPETITIONS] {
        array::from_fn(|_| {
            (1..=batch_size)
                .map(|_| {
                    let challenge = transcript.challenge(b"challenge");

                    // we don't have to do this because Merlin uses a PRF behind the scenes,
                    // but we do it anyways as a security best-practice
                    transcript.append_uint(b"challenge", &challenge);

                    challenge
                })
                .collect()
        })
    }
}
