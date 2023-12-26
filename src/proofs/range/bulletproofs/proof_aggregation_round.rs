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
    group::{ristretto, ristretto::SCALAR_LIMBS},
    proofs,
    proofs::{
        range,
        range::{
            bulletproofs::{
                commitment_round, decommitment_round, proof_share_round,
                proof_share_round::ProofShare,
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
    pub(super) dealer_awaiting_proof_shares: DealerAwaitingProofShares<'a, 'b>,
}

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
        'a,
        'b,
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

        let schnorr_range_proof_commitments: Vec<_> = statements
            .clone()
            .into_iter()
            .flat_map(|statement| {
                <[_; NUM_RANGE_CLAIMS]>::from(statement.range_proof_commitment().clone())
            })
            .map(|x: ristretto::GroupElement| x.0)
            .collect();

        let bulletproofs_range_proof_commitments: Vec<_> = self
            .dealer_awaiting_proof_shares
            .bit_commitments
            .iter()
            .map(|vc| vc.V_j.decompress().ok_or(proofs::Error::InvalidParameters))
            .collect::<Result<Vec<_>, _>>()?;

        if schnorr_range_proof_commitments != bulletproofs_range_proof_commitments {
            // TODO: ask dolev what to do here, because I need to blame somebody.
            // maybe this whole thing wasn't even ncessairy?
            todo!()
        }

        let range_proof = super::RangeProof(
            self.dealer_awaiting_proof_shares
                .receive_shares_with_rng(&bulletproofs_proof_shares, rng)
                .map_err(bulletproofs::ProofError::from)
                .map_err(range::Error::from)?,
        );

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

        // TODO: need to do some verifications of the enhanced proof or smth? the inidividual proofs
        // were already verified in the aggregation itself.

        Ok((proof, statements))
    }
}
