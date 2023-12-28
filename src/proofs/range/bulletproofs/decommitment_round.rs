use std::{collections::HashMap, marker::PhantomData};

use bulletproofs::range_proof_mpc::{
    dealer::DealerAwaitingBitCommitments, messages::PolyCommitment,
    party::PartyAwaitingBitChallenge,
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    group::Samplable,
    proofs,
    proofs::{
        range,
        range::bulletproofs::{commitment_round, commitment_round::Commitment, proof_share_round},
        schnorr::{
            aggregation::{decommitment_round, DecommitmentRoundParty},
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
    pub(super) decommitment_round_party: decommitment_round::Party<
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
    pub(super) dealer_awaiting_bit_commitments: DealerAwaitingBitCommitments<'a, 'b>,
    pub(super) parties_awaiting_bit_challenge: Vec<PartyAwaitingBitChallenge<'b>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Decommitment<Decom> {
    pub(super) decommitment: Decom,
    pub(super) poly_commitments: Vec<PolyCommitment>,
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
    DecommitmentRoundParty<
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
    type Commitment = Commitment;

    type Decommitment = Decommitment<
        decommitment_round::Decommitment<
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

    type ProofShareRoundParty = proof_share_round::Party<
        'a,
        'b,
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >;

    fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, commitment_round::Commitment>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self::Decommitment, Self::ProofShareRoundParty)> {
        let (commitments, mut bit_commitments): (Vec<(_, _)>, Vec<(_, _)>) = commitments
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
            .decommit_statements_and_statement_mask(commitments, rng)
            .unwrap();

        bit_commitments.sort_by_key(|(party_id, _)| *party_id);

        let bit_commitments = bit_commitments
            .into_iter()
            .flat_map(|(_, bit_commitments)| bit_commitments)
            .collect();

        let (dealer_awaiting_poly_commitments, bit_challenge) = self
            .dealer_awaiting_bit_commitments
            .receive_bit_commitments(bit_commitments)
            .map_err(bulletproofs::ProofError::from)
            .map_err(range::bulletproofs::Error::from)
            .map_err(range::Error::from)?;

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

        let message = Decommitment {
            decommitment,
            poly_commitments,
        };

        Ok((message, third_round_party))
    }
}
