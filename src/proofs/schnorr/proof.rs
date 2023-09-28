// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, ConcatMixed, Encoding, Uint, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, GroupElement, Samplable},
    proofs,
    proofs::{
        range::RangeProof,
        schnorr::{
            language,
            language::{
                enhanced, PublicParameters, StatementSpaceGroupElement, StatementSpaceValue, WitnessSpaceGroupElement,
                WitnessSpaceValue,
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
pub(super) type ChallengeSizedNumber = <ComputationalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput;

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
    statement_mask: StatementSpaceValue<Language>,
    response: WitnessSpaceValue<Language>,

    _protocol_context_choice: PhantomData<ProtocolContext>,
}

/// An Enhanced Batched Schnorr Zero-Knowledge Proof.
/// Implements Appendix B. Schnorr Protocols in the paper.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnhancedProof<
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims
    const RANGE_CLAIM_LIMBS: usize,
    // The size of the witness mask. Must be equal to RANGE_CLAIM_LIMBS + ComputationalSecuritySizedNumber::LIMBS +
    // StatisticalSecuritySizedNumber::LIMBS
    const WITNESS_MASK_LIMBS: usize,
    // The enhanced language we are proving
    Language: enhanced::EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    schnorr_proof: Proof<Language, ProtocolContext>,
    range_proof: enhanced::RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Language>,
}

impl<Language: language::Language, ProtocolContext: Clone + Serialize> Proof<Language, ProtocolContext> {
    fn new(statement_mask: StatementSpaceGroupElement<Language>, response: WitnessSpaceGroupElement<Language>) -> Self {
        Self {
            statement_mask: statement_mask.value(),
            response: response.value(),
            _protocol_context_choice: PhantomData,
        }
    }

    /// Prove a batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        witnesses_and_statements: Vec<(WitnessSpaceGroupElement<Language>, StatementSpaceGroupElement<Language>)>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<Self> {
        if witnesses_and_statements.is_empty() {
            return Err(Error::InvalidParameters);
        }

        let batch_size = witnesses_and_statements.len();

        let (witnesses, statements): (Vec<WitnessSpaceGroupElement<Language>>, Vec<StatementSpaceGroupElement<Language>>) =
            witnesses_and_statements.into_iter().unzip();

        let mut transcript = Self::setup_protocol(&protocol_context, language_public_parameters, statements)?;

        let randomizer =
            WitnessSpaceGroupElement::<Language>::sample(rng, &language_public_parameters.as_ref().witness_space_public_parameters)?;

        let statement_mask = Language::group_homomorphism(&randomizer, language_public_parameters)?;

        let challenges: Vec<ChallengeSizedNumber> = Self::compute_challenges(&statement_mask.value(), batch_size, &mut transcript)?;

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
        protocol_context: ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        statements: Vec<StatementSpaceGroupElement<Language>>,
    ) -> proofs::Result<()> {
        let batch_size = statements.len();

        let mut transcript = Self::setup_protocol(&protocol_context, language_public_parameters, statements.clone())?;

        let challenges: Vec<ChallengeSizedNumber> = Self::compute_challenges(&self.statement_mask, batch_size, &mut transcript)?;

        let response = WitnessSpaceGroupElement::<Language>::new(
            self.response.clone(),
            &language_public_parameters.as_ref().witness_space_public_parameters,
        )?;

        let statement_mask = StatementSpaceGroupElement::<Language>::new(
            self.statement_mask.clone(),
            &language_public_parameters.as_ref().statement_space_public_parameters,
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

        transcript.serialize_to_transcript_as_json(b"language public parameters", language_public_parameters)?;

        transcript.serialize_to_transcript_as_json(
            b"witness space public parameters",
            &language_public_parameters.as_ref().witness_space_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"statement space public parameters",
            &language_public_parameters.as_ref().statement_space_public_parameters,
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
        transcript.serialize_to_transcript_as_json(b"statement mask value", statement_mask_value)?;

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

impl<
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Language: enhanced::EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS>,
        ProtocolContext: Clone + Serialize,
    > EnhancedProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Language, ProtocolContext>
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    /// Prove an enhanced batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        range_proof_public_parameters: &enhanced::RangeProofPublicParameters<
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Language,
        >,
        witnesses_and_statements: Vec<(WitnessSpaceGroupElement<Language>, StatementSpaceGroupElement<Language>)>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<Self> {
        let schnorr_proof = Proof::<Language, ProtocolContext>::prove(
            protocol_context,
            language_public_parameters,
            witnesses_and_statements.clone(),
            rng,
        )?;

        let (witnesses, statements): (Vec<WitnessSpaceGroupElement<Language>>, Vec<StatementSpaceGroupElement<Language>>) =
            witnesses_and_statements.into_iter().unzip();

        let (constrained_witnesses, commitment_randomnesses): (
            Vec<[power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
            Vec<
                enhanced::RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
                    NUM_RANGE_CLAIMS,
                    RANGE_CLAIM_LIMBS,
                    WITNESS_MASK_LIMBS,
                    Language,
                >,
            >,
        ) = witnesses
            .into_iter()
            .map(|witness| {
                let (constrained_witness, commitment_randomness, _) = witness.into();

                let constrained_witness: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>; NUM_RANGE_CLAIMS] =
                    constrained_witness.into();

                let constrained_witness: [power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS] =
                    constrained_witness.map(|witness_part| {
                        let witness_part_value: Uint<WITNESS_MASK_LIMBS> = witness_part.into();
                        // TODO: should I return an error upon overflow or just let the proof fail?
                        let witness_part_range_claim_value: Uint<RANGE_CLAIM_LIMBS> = (&witness_part_value).into();
                        // power_of_two_moduli performs no checks, TODO: this is coupling
                        power_of_two_moduli::GroupElement::<RANGE_CLAIM_LIMBS>::new(witness_part_range_claim_value, &()).unwrap()
                    });

                (constrained_witness, commitment_randomness)
            })
            .unzip();

        let commitments: Vec<
            enhanced::RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
                NUM_RANGE_CLAIMS,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                Language,
            >,
        > = statements
            .into_iter()
            .map(|statement| {
                let (commitment, _) = statement.into();

                commitment
            })
            .collect();

        // TODO: are we sure we want to take just one for the entire batch?
        let commitment_randomness = commitment_randomnesses.first().ok_or(Error::InvalidParameters)?;
        let commitment = commitments.first().ok_or(Error::InvalidParameters)?;

        let range_proof = enhanced::RangeProof::<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Language>::prove(
            range_proof_public_parameters,
            constrained_witnesses,
            commitment_randomness,
            commitment,
            rng,
        )?;

        Ok(EnhancedProof {
            schnorr_proof,
            range_proof,
        })
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        range_proof_public_parameters: &enhanced::RangeProofPublicParameters<
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Language,
        >,
        statements: Vec<StatementSpaceGroupElement<Language>>,
    ) -> proofs::Result<()> {
        // TODO: here we should validate all the sizes are good etc. for example WITNESS_MASK_LIMBS and RANGE_CLAIM_LIMBS and
        // the message space thingy

        let commitments: Vec<
            enhanced::RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
                NUM_RANGE_CLAIMS,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                Language,
            >,
        > = statements
            .clone()
            .into_iter()
            .map(|statement| {
                let (commitment, _) = statement.into();

                commitment
            })
            .collect();

        // TODO: are we sure we want to take just one for the entire batch?
        let commitment = commitments.first().ok_or(Error::InvalidParameters)?;

        self.schnorr_proof
            .verify(protocol_context, language_public_parameters, statements)
            .and(self.range_proof.verify(range_proof_public_parameters, commitment))
    }
}
