use std::{collections::HashMap, marker::PhantomData};

use bulletproofs::range_proof_mpc::{
    dealer::{DealerAwaitingBitCommitments, DealerAwaitingPolyCommitments},
    messages,
    messages::PolyCommitment,
    party::{PartyAwaitingBitChallenge, PartyAwaitingPolyChallenge},
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    proofs,
    proofs::{
        range,
        range::{
            bulletproofs::{
                commitment_round, decommitment_round, decommitment_round::Decommitment,
                proof_aggregation_round, proof_share_round,
            },
            Samplable,
        },
        schnorr::{
            aggregation,
            aggregation::ProofShareRoundParty,
            enhanced::{EnhanceableLanguage, EnhancedLanguage},
            language,
        },
    },
    PartyID,
};

pub struct Party<
    'a,
    'b,
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
    pub(super) proof_share_round_party: aggregation::proof_share_round::Party<
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
    pub(super) dealer_awaiting_poly_commitments: DealerAwaitingPolyCommitments<'a, 'b>,
    pub(super) parties_awaiting_poly_challenge: Vec<PartyAwaitingPolyChallenge>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProofShare<Share> {
    pub(super) schnorr_proof_share: Share,
    pub(super) bulletproofs_proof_shares: Vec<messages::ProofShare>,
}

impl<
        'a,
        'b,
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
    >
    ProofShareRoundParty<
        super::Output<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >,
    >
    for Party<
        'a,
        'b,
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    type Decommitment = Decommitment<
        aggregation::decommitment_round::Decommitment<
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

    type ProofAggregationRoundParty = proof_aggregation_round::Party<
        'a,
        'b,
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >;

    fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Self::Decommitment>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self::ProofShare, Self::ProofAggregationRoundParty)> {
        let (decommitments, mut poly_commitments): (Vec<(_, _)>, Vec<(_, _)>) = decommitments
            .into_iter()
            .map(|(party_id, message)| {
                (
                    (party_id, message.decommitment),
                    (party_id, message.poly_commitments),
                )
            })
            .unzip();

        let decommitments: HashMap<_, _> = decommitments.into_iter().collect();

        let (schnorr_proof_share, proof_aggregation_round_party) = self
            .proof_share_round_party
            .generate_proof_share(decommitments, rng)
            .unwrap();

        poly_commitments.sort_by_key(|(party_id, _)| *party_id);

        let poly_commitments = poly_commitments
            .into_iter()
            .flat_map(|(_, poly_commitments)| poly_commitments)
            .collect();

        let (dealer_awaiting_proof_shares, poly_challenge) = self
            .dealer_awaiting_poly_commitments
            .receive_poly_commitments(poly_commitments)
            .map_err(bulletproofs::ProofError::from)
            .map_err(range::Error::from)?;

        let bulletproofs_proof_shares: Vec<_> = self
            .parties_awaiting_poly_challenge
            .into_iter()
            .map(|party| {
                party
                    .apply_challenge(&poly_challenge)
                    .map_err(bulletproofs::ProofError::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(range::Error::from)?;

        let finalization_round_party = proof_aggregation_round::Party {
            proof_aggregation_round_party,
            dealer_awaiting_proof_shares,
        };

        let message = ProofShare {
            schnorr_proof_share,
            bulletproofs_proof_shares,
        };

        Ok((message, finalization_round_party))
    }
}
