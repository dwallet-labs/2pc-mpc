use std::collections::HashMap;

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
        range::bulletproofs::{
            commitment_round, decommitment_and_poly_commitment_round, proof_aggregation_round,
            proof_share_round, RANGE_CLAIM_LIMBS, SCALAR_LIMBS,
        },
        schnorr::{
            aggregation,
            aggregation::{decommitment_round, decommitment_round::Decommitment},
            language, EnhancedLanguage,
        },
    },
    PartyID,
};

pub struct Party<
    'a,
    'b,
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const WITNESS_MASK_LIMBS: usize,
    Language: EnhancedLanguage<
        REPETITIONS,
        { SCALAR_LIMBS },
        NUM_RANGE_CLAIMS,
        { RANGE_CLAIM_LIMBS },
        WITNESS_MASK_LIMBS,
        RangeProof = super::RangeProof,
    >,
    ProtocolContext: Clone,
> where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    pub(super) proof_share_round_party:
        aggregation::proof_share_round::Party<REPETITIONS, Language, ProtocolContext>,
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
        const WITNESS_MASK_LIMBS: usize,
        Language: EnhancedLanguage<
            REPETITIONS,
            { SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            RangeProof = super::RangeProof,
        >,
        ProtocolContext: Clone + Serialize,
    > Party<'a, 'b, REPETITIONS, NUM_RANGE_CLAIMS, WITNESS_MASK_LIMBS, Language, ProtocolContext>
where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    pub fn generate_proof_shares(
        self,
        messages: HashMap<
            PartyID,
            decommitment_and_poly_commitment_round::Message<REPETITIONS, Language>,
        >,
    ) -> proofs::Result<(
        Message<REPETITIONS, Language>,
        proof_aggregation_round::Party<
            'a,
            'b,
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            WITNESS_MASK_LIMBS,
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
            .map_err(bulletproofs::ProofError::from)?;

        let bulletproofs_proof_shares: Vec<_> = self
            .parties_awaiting_poly_challenge
            .into_iter()
            .map(|party| {
                party
                    .apply_challenge(&bit_challenge)
                    .map_err(bulletproofs::ProofError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;

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
