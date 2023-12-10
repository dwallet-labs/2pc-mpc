use std::collections::HashMap;

use bulletproofs::range_proof_mpc::{
    dealer::DealerAwaitingBitCommitments, messages::PolyCommitment,
    party::PartyAwaitingBitChallenge,
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    proofs,
    proofs::{
        range::bulletproofs::{
            commitment_round, proof_share_round, RANGE_CLAIM_LIMBS, SCALAR_LIMBS,
        },
        schnorr::{
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
    pub(super) decommitment_round_party:
        decommitment_round::Party<REPETITIONS, Language, ProtocolContext>,
    pub(super) dealer_awaiting_bit_commitments: DealerAwaitingBitCommitments<'a, 'b>,
    pub(super) parties_awaiting_bit_challenge: Vec<PartyAwaitingBitChallenge<'b>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message<const REPETITIONS: usize, Language: language::Language<REPETITIONS>> {
    pub(super) decommitment: Decommitment<REPETITIONS, Language>,
    pub(super) poly_commitments: Vec<PolyCommitment>,
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
    pub fn decommit_statements_and_generate_poly_commitments(
        self,
        messages: HashMap<PartyID, commitment_round::Message>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Message<REPETITIONS, Language>,
        proof_share_round::Party<
            'a,
            'b,
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            WITNESS_MASK_LIMBS,
            Language,
            ProtocolContext,
        >,
    )> {
        let (commitments, mut bit_commitments): (Vec<(_, _)>, Vec<(_, _)>) = messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    (party_id, message.commitment),
                    (party_id, message.bit_commitments),
                )
            })
            .unzip();

        let commitments: HashMap<_, _> = commitments.into_iter().collect();

        let (decommitment, proof_share_round_party) = self
            .decommitment_round_party
            .decommit_statements_and_statement_mask(commitments)
            .unwrap();

        bit_commitments.sort_by_key(|(party_id, _)| *party_id);

        let bit_commitments = bit_commitments
            .into_iter()
            .flat_map(|(_, bit_commitments)| bit_commitments)
            .collect();

        let (dealer_awaiting_poly_commitments, bit_challenge) = self
            .dealer_awaiting_bit_commitments
            .receive_bit_commitments(bit_commitments)
            .map_err(bulletproofs::ProofError::from)?;

        let (parties_awaiting_poly_challenge, poly_commitments): (Vec<_>, Vec<_>) = self
            .parties_awaiting_bit_challenge
            .into_iter()
            .map(|party| party.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let third_round_party = proof_share_round::Party {
            proof_share_round_party,
            dealer_awaiting_poly_commitments,
            parties_awaiting_poly_challenge,
        };

        let message = Message {
            decommitment,
            poly_commitments,
        };

        Ok((message, third_round_party))
    }
}
