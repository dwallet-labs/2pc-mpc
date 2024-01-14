// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::array;
use std::collections::HashMap;

use bulletproofs::{BulletproofGens, PedersenGens};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Random, Uint};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    commitments,
    commitments::GroupsPublicParametersAccessors as _,
    group,
    group::{GroupElement as _, Samplable},
    proofs,
    proofs::{
        range,
        range::{
            CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement,
            PublicParametersAccessors,
        },
        schnorr::{
            enhanced,
            enhanced::{EnhanceableLanguage, EnhancedPublicParameters},
            language,
            language::{
                enhanced::{
                    EnhancedLanguage, EnhancedLanguageStatementAccessors,
                    EnhancedLanguageWitnessAccessors,
                },
                GroupsPublicParametersAccessors as _, Language,
            },
            proof::flat_map_results,
        },
        transcript_protocol::TranscriptProtocol,
    },
    StatisticalSecuritySizedNumber,
};

/// An Enhanced Batched Schnorr Zero-Knowledge Proof.
/// Implements Appendix B. Schnorr Protocols in the paper.
pub type Proof<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // The range proof commitment scheme's message space scalar size in limbs
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The corresponding range proof
    RangeProof: range::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    // The unbounded witness group element
    UnboundedWitnessSpaceGroupElement: Samplable,
    // The enhanceable language we are proving
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone + Serialize,
> = private::Proof<
    super::Proof<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >,
    RangeProof,
>;

mod private {
    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Proof<SchnorrProof, RangeProof> {
        pub(crate) schnorr_proof: SchnorrProof,
        pub(crate) range_proof: RangeProof,
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: range::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    >
    Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    /// Prove an enhanced batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        witnesses: Vec<
            enhanced::WitnessSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Self,
        Vec<
            enhanced::StatementSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    )> {
        let mut transcript = Self::setup_range_proof(
            protocol_context,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )?;

        let (commitment_messages, commitment_randomnesses): (Vec<_>, Vec<_>) = witnesses
            .clone()
            .into_iter()
            .map(|witness| {
                (
                    witness.range_proof_commitment_message().clone(),
                    witness.range_proof_commitment_randomness().clone(),
                )
            })
            .unzip();

        // TODO: commitments are being computed twice. In order to avoid this, I would need to
        // somehow partially compute the group homomorphism, which is problematic..
        // TODO: perhaps introduce a "prove_inner()" function
        let (range_proof, _) = RangeProof::prove(
            &enhanced_language_public_parameters.range_proof_public_parameters,
            commitment_messages,
            commitment_randomnesses,
            transcript,
            rng,
        )?;

        let batch_size = witnesses.len();

        let (randomizers, statement_masks) = Self::sample_randomizers_and_statement_masks(
            0,
            batch_size,
            enhanced_language_public_parameters,
            rng,
        )?;

        let (schnorr_proof, statements) = super::Proof::<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
            ProtocolContext,
        >::prove_with_randomizers(
            None,
            protocol_context,
            enhanced_language_public_parameters,
            witnesses,
            randomizers,
            statement_masks,
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
        number_of_parties: Option<usize>,
        protocol_context: &ProtocolContext,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        statements: Vec<
            enhanced::StatementSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<()> {
        // TODO: here we should validate all the sizes are good etc. for example WITNESS_MASK_LIMBS
        // and RANGE_CLAIM_LIMBS and the message space thingy

        let mut transcript = Self::setup_range_proof(
            protocol_context,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )?;

        let commitments: Vec<_> = statements
            .clone()
            .into_iter()
            .map(|statement| statement.range_proof_commitment().clone())
            .collect();

        // TODO: make sure I did the range test

        self.schnorr_proof
            .verify(
                number_of_parties,
                protocol_context,
                &enhanced_language_public_parameters,
                statements,
            )
            .and(self.range_proof.verify(
                &enhanced_language_public_parameters.range_proof_public_parameters,
                commitments,
                transcript,
                rng,
            ))
    }

    pub(crate) fn setup_range_proof(
        protocol_context: &ProtocolContext,
        range_proof_public_parameters: &range::PublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
    ) -> proofs::Result<Transcript> {
        // TODO: choice of parameters, batching conversation in airport.
        // if WITNESS_MASK_LIMBS
        //     != RANGE_CLAIM_LIMBS
        //         + super::ChallengeSizedNumber::LIMBS
        //         + StatisticalSecuritySizedNumber::LIMBS
        //     || WITNESS_MASK_LIMBS > COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
        //     || Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(
        //         &Uint::<WITNESS_MASK_LIMBS>::MAX,
        //     ) >= language::enhanced::RangeProofCommitmentSchemeMessageSpaceGroupElement::<
        //       COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS,
        //         Language,
        //     >::lower_bound_from_public_parameters(
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
            RangeProof::NAME.as_bytes(),
        );

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        Ok(transcript)
    }

    pub(crate) fn sample_randomizers_and_statement_masks(
        number_of_parties: usize,
        batch_size: usize,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        [enhanced::WitnessSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >; REPETITIONS],
        [enhanced::StatementSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >; REPETITIONS],
    )> {
        let commitment_messages: [CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >; REPETITIONS] = flat_map_results(array::from_fn(|_| {
            // TODO
            // let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
            // + ComputationalSecuritySizedNumber::BITS
            // + StatisticalSecuritySizedNumber::BITS;

            // TODO: check that this is < SCALAR_LIMBS?

            // TODO: formula + challenge : in lightning its 1, in bp 128
            let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
                + StatisticalSecuritySizedNumber::BITS
                + EnhancedLanguage::<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Language,
                >::challenge_bits(number_of_parties, batch_size);

            // TODO: verify
            let mask = Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::MAX
                >> (Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS - sampling_bit_size);

            flat_map_results(array::from_fn(|_| {
                let value = (Uint::<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>::random(rng)
                    & mask)
                    .into();

                RangeProof::RangeClaimGroupElement::new(
                    value,
                    &enhanced_language_public_parameters
                        .range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .message_space_public_parameters()
                        .public_parameters,
                )
            }))
            .map(|decomposed_witness| decomposed_witness.into())
        }))?;

        let unbounded_witnesses: [_; REPETITIONS] = flat_map_results(array::from_fn(|_| {
            UnboundedWitnessSpaceGroupElement::sample(
                enhanced_language_public_parameters.unbounded_witness_public_parameters(),
                rng,
            )
        }))?;

        let commitment_randomnesses: [_; REPETITIONS] = flat_map_results(array::from_fn(|_| {
            CommitmentSchemeRandomnessSpaceGroupElement::<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >::sample(
                enhanced_language_public_parameters
                    .range_proof_public_parameters
                    .commitment_scheme_public_parameters()
                    .randomness_space_public_parameters(),
                rng,
            )
        }))?;

        let randomizers: [_; REPETITIONS] = commitment_messages
            .into_iter()
            .zip(commitment_randomnesses.into_iter())
            .zip(unbounded_witnesses.into_iter())
            .map(
                |((commitment_message, commitment_randomness), unbounded_witness)| {
                    (commitment_message, commitment_randomness, unbounded_witness).into()
                },
            )
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| proofs::Error::InternalError)?;

        let statement_masks = flat_map_results(randomizers.clone().map(|randomizer| {
            EnhancedLanguage::<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >::group_homomorphism(&randomizer, enhanced_language_public_parameters)
        }))?;

        Ok((randomizers, statement_masks))
    }
}

// TODO: DRY these tests code, perhaps using a trait for a Proof.

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::{array, iter, marker::PhantomData};

    use crypto_bigint::{Random, Wrapping, U128, U256};
    use rand_core::OsRng;

    use super::*;
    use crate::{
        group::{ristretto, secp256k1},
        proofs::{
            range,
            range::{bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RangeProof},
            schnorr::{
                aggregation, enhanced, language,
                language::enhanced::tests::enhanced_language_public_parameters,
            },
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    #[allow(dead_code)]
    pub(crate) fn valid_proof_verifies<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let witnesses = EnhancedLanguage::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            range::bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >::generate_witnesses(
            witnesses, &enhanced_language_public_parameters, &mut OsRng
        )
        .unwrap();

        let (proof, statements) = enhanced::Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            range::bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::prove(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses,
            &mut OsRng,
        )
        .unwrap();

        assert!(
            proof
                .verify(
                    None,
                    &PhantomData,
                    &enhanced_language_public_parameters,
                    statements,
                    &mut OsRng,
                )
                .is_ok(),
            "valid enhanced proofs should verify",
        );
    }

    #[allow(dead_code)]
    pub(crate) fn proof_with_out_of_range_witness_fails<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let witnesses = vec![enhanced::WitnessSpaceGroupElement::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            range::bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >::sample(
            enhanced_language_public_parameters.witness_space_public_parameters(),
            &mut OsRng,
        )
        .unwrap()];

        let (proof, statements) = enhanced::Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            range::bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::prove(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses,
            &mut OsRng,
        )
        .unwrap(); // TODO: actually, this already should fail. Need to test verify seperately

        assert!(
            matches!(
                proof
                    .verify(
                        None,
                        &PhantomData,
                        &enhanced_language_public_parameters,
                        statements,
                        &mut OsRng,
                    )
                    .err()
                    .unwrap(),
                proofs::Error::Range(range::Error::Bulletproofs(
                    range::bulletproofs::Error::Bulletproofs(
                        bulletproofs::ProofError::VerificationError
                    )
                ))
            ),
            "out of range error should fail on range verification"
        );
    }

    #[allow(dead_code)]
    pub(crate) fn aggregates<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Vec<Lang::WitnessSpaceGroupElement>>,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let witnesses: Vec<_> = witnesses
            .into_iter()
            .map(|witnesses| {
                EnhancedLanguage::<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
                    range::bulletproofs::RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Lang,
                >::generate_witnesses(
                    witnesses, &enhanced_language_public_parameters, &mut OsRng
                )
                .unwrap()
            })
            .collect();

        let number_of_parties: u16 = witnesses.len().try_into().unwrap();

        let number_of_witnesses: usize = witnesses.first().unwrap().len() * NUM_RANGE_CLAIMS;

        let range_proof_public_parameters =
            range::bulletproofs::PublicParameters::<NUM_RANGE_CLAIMS>::default();

        let commitment_round_parties: HashMap<_, _> = witnesses
            .clone()
            .into_iter()
            .enumerate()
            .map(|(party_id, witnesses)| {
                let party_id: u16 = (party_id + 1).try_into().unwrap();

                (
                    party_id,
                    <range::bulletproofs::RangeProof as range::RangeProof<
                        { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
                    >>::new_enhanced_session::<
                        REPETITIONS,
                        NUM_RANGE_CLAIMS,
                        UnboundedWitnessSpaceGroupElement,
                        Lang,
                        PhantomData<()>,
                    >(
                        party_id,
                        number_of_parties,
                        number_of_parties,
                        enhanced_language_public_parameters.clone(),
                        PhantomData,
                        witnesses.clone(),
                    ),
                )
            })
            .collect();

        let (proof, statements) = aggregation::tests::aggregates_internal(commitment_round_parties);

        assert!(
            proof
                .verify(
                    None,
                    &PhantomData,
                    &enhanced_language_public_parameters,
                    statements,
                    &mut OsRng,
                )
                .is_ok(),
            "valid aggregated enhanced proofs should verify"
        );
    }

    // TODO: a test that checks a valid range proof but on commitment that is different from the
    // aggregated commitment.
}
