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
                commitment_round, decommitment_and_poly_commitment_round, proof_aggregation_round,
                proof_share_round,
            },
            Samplable,
        },
        schnorr::{
            aggregation,
            aggregation::{
                decommitment_round, decommitment_round::Decommitment, ProofShareRoundParty,
            },
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
pub struct Message<const REPETITIONS: usize, Language: language::Language<REPETITIONS>> {
    pub(super) schnorr_proof_share:
        aggregation::proof_share_round::ProofShare<REPETITIONS, Language>,
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
    Party<
        'a,
        'b,
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    pub fn generate_proof_shares(
        self,
        messages: HashMap<
            PartyID,
            decommitment_and_poly_commitment_round::Message<
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
        >,
    ) -> proofs::Result<(
        Message<
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
        proof_aggregation_round::Party<
            'a,
            'b,
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >,
    )> {
        let (decommitments, mut poly_commitments): (Vec<(_, _)>, Vec<(_, _)>) = messages
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
            .generate_proof_share(decommitments)
            .unwrap();

        poly_commitments.sort_by_key(|(party_id, _)| *party_id);

        let poly_commitments = poly_commitments
            .into_iter()
            .flat_map(|(_, poly_commitments)| poly_commitments)
            .collect();

        let (dealer_awaiting_proof_shares, bit_challenge) = self
            .dealer_awaiting_poly_commitments
            .receive_poly_commitments(poly_commitments)
            .map_err(bulletproofs::ProofError::from)
            .map_err(range::Error::from)?;

        let bulletproofs_proof_shares: Vec<_> = self
            .parties_awaiting_poly_challenge
            .into_iter()
            .map(|party| {
                party
                    .apply_challenge(&bit_challenge)
                    .map_err(bulletproofs::ProofError::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(range::Error::from)?;

        let finalization_round_party = proof_aggregation_round::Party {
            proof_aggregation_round_party,
            dealer_awaiting_proof_shares,
        };

        let message = Message {
            schnorr_proof_share,
            bulletproofs_proof_shares,
        };

        Ok((message, finalization_round_party))
    }
}
