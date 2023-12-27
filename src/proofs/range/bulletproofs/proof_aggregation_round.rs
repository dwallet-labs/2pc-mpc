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

        let schnorr_range_proof_commitments: Vec<_> = statements
            .clone()
            .into_iter()
            .map(|statement| statement.range_proof_commitment().clone())
            .collect();

        let bulletproofs_commitments: Vec<_> = self
            .dealer_awaiting_proof_shares
            .bit_commitments
            .iter()
            .map(|vc| vc.V_j.decompress().ok_or(proofs::Error::InvalidParameters))
            .collect::<Result<Vec<_>, _>>()?;

        let number_of_witnesses = schnorr_range_proof_commitments
            .len()
            .checked_mul(number_of_schnorr_parties.into())
            .ok_or(proofs::Error::InternalError)?;

        // TODO: note that we create a `GroupElement` here without checking it is in the group.
        // We need to make sure bulletproofs make that check for it to be safe.
        let mut bulletproofs_commitments_iter = bulletproofs_commitments
            .into_iter()
            .map(|point| ristretto::GroupElement(point));

        let bulletproofs_commitments = iter::repeat_with(|| {
            flat_map_results(array::from_fn(|_| {
                bulletproofs_commitments_iter
                    .next()
                    .ok_or(proofs::Error::InternalError)
            }))
            .map(
                range::CommitmentSchemeCommitmentSpaceGroupElement::<
                    { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
                    NUM_RANGE_CLAIMS,
                    range::bulletproofs::RangeProof,
                >::from,
            )
        })
        .take(number_of_witnesses)
        .collect::<proofs::Result<Vec<_>>>()?;

        // TODO: proper error handling with all the options here, proper errors.
        let bulletproofs_commitments = (0..schnorr_range_proof_commitments.len())
            .map(|i| {
                (0..number_of_schnorr_parties.into())
                    .map(|j: usize| {
                        j.checked_mul(schnorr_range_proof_commitments.len())
                            .and_then(|index| index.checked_add(i))
                            .and_then(|index| bulletproofs_commitments.get(index).cloned())
                            .ok_or(proofs::Error::InternalError)
                    })
                    .collect::<proofs::Result<Vec<_>>>()
            })
            .collect::<proofs::Result<Vec<_>>>()?;

        let bulletproofs_commitments: Vec<_> = bulletproofs_commitments
            .into_iter()
            .map(|v| {
                v.into_iter()
                    .reduce(|a, b| a + b)
                    .ok_or(proofs::Error::InternalError)
            })
            .collect::<proofs::Result<Vec<_>>>()?;

        if schnorr_range_proof_commitments != bulletproofs_commitments {
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
