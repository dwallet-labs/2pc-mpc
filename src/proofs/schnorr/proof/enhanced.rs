// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use language::PublicParameters;
use serde::{Deserialize, Serialize};

use crate::{
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, BoundedGroupElement},
    proofs,
    proofs::{
        range::RangeProof,
        schnorr::{
            language,
            language::{StatementSpaceGroupElement, WitnessSpaceGroupElement},
        },
        Error, Transcript, TranscriptProtocol,
    },
    StatisticalSecuritySizedNumber,
};

/// An Enhanced Batched Schnorr Zero-Knowledge Proof.
/// Implements Appendix B. Schnorr Protocols in the paper.
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof<
    // The range proof commitment scheme's message space scalar size in limbs
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims
    const RANGE_CLAIM_LIMBS: usize,
    // The size of the witness mask. Must be equal to RANGE_CLAIM_LIMBS +
    // ComputationalSecuritySizedNumber::LIMBS + StatisticalSecuritySizedNumber::LIMBS
    const WITNESS_MASK_LIMBS: usize,
    // The enhanced language we are proving
    Language: language::enhanced::EnhancedLanguage<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
    >,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    schnorr_proof: super::Proof<Language, ProtocolContext>,
    range_proof: language::enhanced::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Language,
    >,
}

impl<
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Language: language::enhanced::EnhancedLanguage<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
        >,
        ProtocolContext: Clone + Serialize,
    >
    Proof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Language,
        ProtocolContext,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    /// Prove an enhanced batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        range_proof_public_parameters: &language::enhanced::RangeProofPublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Language,
        >,
        witnesses: Vec<WitnessSpaceGroupElement<Language>>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self, Vec<StatementSpaceGroupElement<Language>>)> {
        let mut transcript =
            Self::setup_range_proof(protocol_context, range_proof_public_parameters)?;

        let (constrained_witnesses, commitment_randomnesses): (
            Vec<[Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
            Vec<
                language::enhanced::RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
                    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    NUM_RANGE_CLAIMS,
                    RANGE_CLAIM_LIMBS,
                    WITNESS_MASK_LIMBS,
                    Language,
                >,
            >,
        ) = witnesses
            .clone()
            .into_iter()
            .map(|witness| {
                let (constrained_witness, commitment_randomness, _) = witness.into();

                let constrained_witness: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>;
                    NUM_RANGE_CLAIMS] = constrained_witness.into();

                let constrained_witness: [Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS] =
                    constrained_witness.map(|witness_part| {
                        let witness_part_value: Uint<WITNESS_MASK_LIMBS> = witness_part.into();

                        (&witness_part_value).into()
                    });

                (constrained_witness, commitment_randomness)
            })
            .unzip();

        // TODO: commitments are being computed twice. In order to avoid this, I would need to
        // somehow partially compute the group homomorphism, which is problematic..
        let (range_proof, _) = language::enhanced::RangeProof::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Language,
        >::prove(
            range_proof_public_parameters,
            constrained_witnesses,
            commitment_randomnesses,
            &mut transcript,
            rng,
        )?;

        let (schnorr_proof, statements) = super::Proof::<Language, ProtocolContext>::prove(
            protocol_context,
            language_public_parameters,
            witnesses,
            rng,
        )?;

        Ok((
            Proof {
                schnorr_proof,
                range_proof,
            },
            statements,
        ))
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        language_public_parameters: &PublicParameters<Language>,
        range_proof_public_parameters: &language::enhanced::RangeProofPublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Language,
        >,
        statements: Vec<StatementSpaceGroupElement<Language>>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<()> {
        // TODO: here we should validate all the sizes are good etc. for example WITNESS_MASK_LIMBS
        // and RANGE_CLAIM_LIMBS and the message space thingy

        let mut transcript =
            Self::setup_range_proof(protocol_context, range_proof_public_parameters)?;

        let commitments: Vec<
            language::enhanced::RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
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

        // TODO: make sure I did the range test

        self.schnorr_proof
            .verify(protocol_context, language_public_parameters, statements)
            .and(self.range_proof.verify(
                range_proof_public_parameters,
                commitments,
                &mut transcript,
                rng,
            ))
    }

    fn setup_range_proof(
        protocol_context: &ProtocolContext,
        range_proof_public_parameters: &language::enhanced::RangeProofPublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Language,
        >,
    ) -> proofs::Result<Transcript> {
        // TODO: choice of parameters, batching conversation in airport.
        // if WITNESS_MASK_LIMBS
        //     != RANGE_CLAIM_LIMBS
        //         + super::ChallengeSizedNumber::LIMBS
        //         + StatisticalSecuritySizedNumber::LIMBS
        //     || WITNESS_MASK_LIMBS > RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
        //     || Uint::<RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(
        //         &Uint::<WITNESS_MASK_LIMBS>::MAX,
        //     ) >= language::enhanced::RangeProofCommitmentSchemeMessageSpaceGroupElement::<
        //       RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS,
        //       RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Language,
        //     >::scalar_lower_bound_from_public_parameters(
        //         &range_proof_public_parameters
        //             .as_ref()
        //             .as_ref()
        //             .message_space_public_parameters,
        //     )
        // {
        //     // TODO: the lower bound check fails
        //     // TODO: dedicated error?
        //     return Err(Error::InvalidParameters);
        // }

        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        transcript.append_message(
            b"range proof used for the enhanced Schnorr proof",
            language::enhanced::RangeProof::<
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                Language,
            >::NAME
                .as_bytes(),
        );

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        Ok(transcript)
    }
}
