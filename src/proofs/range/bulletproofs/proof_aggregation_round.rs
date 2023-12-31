use core::{array, iter};
use std::{collections::HashMap, marker::PhantomData};

use bulletproofs::range_proof_mpc::{
    dealer::{
        DealerAwaitingBitCommitments, DealerAwaitingPolyCommitments, DealerAwaitingProofShares,
    },
    messages,
    messages::PolyCommitment,
    party::{PartyAwaitingBitChallenge, PartyAwaitingPolyChallenge},
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{ristretto, ristretto::SCALAR_LIMBS},
    proofs,
    proofs::{
        range,
        range::{
            bulletproofs::{
                commitment_round, decommitment_round, flat_map_results, proof_share_round,
                proof_share_round::ProofShare, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            },
            Samplable,
        },
        schnorr::{
            aggregation,
            aggregation::{proof_aggregation_round, ProofAggregationRoundParty},
            enhanced,
            enhanced::{EnhanceableLanguage, EnhancedLanguage, EnhancedLanguageStatementAccessors},
            language,
        },
    },
    PartyID,
};

pub struct Party<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> {
    pub(super) proof_aggregation_round_party: proof_aggregation_round::Party<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            super::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >,
    pub(super) aggregation_commitments: Vec<ristretto::GroupElement>,
    pub(super) dealer_awaiting_proof_shares: DealerAwaitingProofShares,
}

// TODO: use range's output
pub type Output<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = (
    enhanced::Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        super::RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >,
    Vec<
        enhanced::StatementSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            super::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
    >,
);

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    >
    ProofAggregationRoundParty<
        Output<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >,
    >
    for Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    type ProofShare = ProofShare<
        aggregation::proof_share_round::ProofShare<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
                super::RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    >;

    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<
        Output<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >,
    > {
        // TODO: handle this someway that doesn't expose this member in the party struct
        let number_of_schnorr_parties = self.proof_aggregation_round_party.number_of_parties;

        let (schnorr_proof_shares, mut bulletproofs_proof_shares): (Vec<(_, _)>, Vec<(_, _)>) =
            proof_shares
                .into_iter()
                .map(|(party_id, message)| {
                    (
                        (party_id, message.schnorr_proof_share),
                        (party_id, message.bulletproofs_proof_shares),
                    )
                })
                .unzip();

        let schnorr_proof_shares: HashMap<_, _> = schnorr_proof_shares.into_iter().collect();

        let (schnorr_proof, statements) = self
            .proof_aggregation_round_party
            .aggregate_proof_shares(schnorr_proof_shares, rng)?;

        bulletproofs_proof_shares.sort_by_key(|(party_id, _)| *party_id);

        let bulletproofs_proof_shares: Vec<_> = bulletproofs_proof_shares
            .into_iter()
            .flat_map(|(_, bulletproofs_proof_shares)| bulletproofs_proof_shares)
            .collect();

        // TODO: note that we create a `GroupElement` here without checking it is in the group.
        // We need to make sure bulletproofs make that check for it to be safe.
        let bulletproofs_commitments: Vec<_> = self
            .dealer_awaiting_proof_shares
            .bit_commitments
            .iter()
            .map(|vc| {
                vc.V_j
                    .decompress()
                    .map(ristretto::GroupElement)
                    .ok_or(proofs::Error::InvalidParameters)
            })
            .collect::<Result<Vec<_>, _>>()?;

        if bulletproofs_commitments != self.aggregation_commitments {
            if bulletproofs_commitments != self.aggregation_commitments {
                // TODO: make sure this is guranteed actually
                return Err(proofs::Error::InternalError);
            }

            let number_of_witnesses = statements
                .len()
                .checked_mul(NUM_RANGE_CLAIMS)
                .ok_or(proofs::Error::InternalError)?;

            let mut iter = bulletproofs_commitments
                .into_iter()
                .zip(self.aggregation_commitments.clone().into_iter());

            let parties_commitments = iter::repeat_with(|| {
                iter::repeat_with(|| iter.next().ok_or(proofs::Error::InternalError))
                    .take(number_of_schnorr_parties.into())
                    .collect::<proofs::Result<Vec<_>>>()
            })
            .take(number_of_witnesses)
            .collect::<proofs::Result<Vec<_>>>()?;

            // TODO: use actual party id!!!! This should be for the whole of bulletproofs
            let malicious_parties = parties_commitments
                .into_iter()
                .enumerate()
                .filter(|(_, commitments)| {
                    commitments
                        .into_iter()
                        .any(|(bulletproof_commitment, schnorr_commitment)| {
                            bulletproof_commitment != schnorr_commitment
                        })
                })
                .map(|(party_id, _)| party_id.try_into().unwrap()) // TODO: no unwrap when using actual pid
                .collect();

            return Err(super::Error::RangeProofSchnorrMismatch(malicious_parties))
                .map_err(range::bulletproofs::Error::from)
                .map_err(range::Error::from)?;
        }

        let proof = self
            .dealer_awaiting_proof_shares
            .receive_shares_with_rng(&bulletproofs_proof_shares, rng)
            .map_err(bulletproofs::ProofError::from)
            .map_err(range::bulletproofs::Error::from)
            .map_err(range::Error::from)?;

        let range_proof = super::RangeProof::new_aggregated(proof, self.aggregation_commitments);

        let proof = enhanced::Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            super::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        > {
            schnorr_proof,
            range_proof,
        };

        // TODO: need to do some verifications of the enhanced proof or smth? the individual proofs
        // were already verified in the aggregation itself.

        Ok((proof, statements))
    }
}
