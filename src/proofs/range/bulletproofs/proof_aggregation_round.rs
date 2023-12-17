use std::collections::HashMap;

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
    group::ristretto,
    proofs,
    proofs::{
        range::bulletproofs::{
            commitment_round, decommitment_and_poly_commitment_round, proof_share_round,
            RANGE_CLAIM_LIMBS, SCALAR_LIMBS,
        },
        schnorr::{
            aggregation::{
                decommitment_round, decommitment_round::Decommitment, proof_aggregation_round,
            },
            enhanced, language,
            language::enhanced::EnhancedLanguageStatementAccessors,
            EnhancedLanguage,
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
    pub(super) proof_aggregation_round_party:
        proof_aggregation_round::Party<REPETITIONS, Language, ProtocolContext>,
    pub(super) dealer_awaiting_proof_shares: DealerAwaitingProofShares<'a, 'b>,
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
    pub fn aggregate_proof_shares(
        self,
        messages: HashMap<PartyID, proof_share_round::Message<REPETITIONS, Language>>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        enhanced::Proof<
            REPETITIONS,
            { SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language,
            ProtocolContext,
        >,
        Vec<Language::StatementSpaceGroupElement>,
    )> {
        let (schnorr_proof_shares, mut bulletproofs_proof_shares): (Vec<(_, _)>, Vec<(_, _)>) =
            messages
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
            .aggregate_proof_shares(schnorr_proof_shares)?;

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
                .map_err(bulletproofs::ProofError::from)?,
        );

        let proof = enhanced::Proof::<
            REPETITIONS,
            { SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language,
            ProtocolContext,
        > {
            schnorr_proof,
            range_proof,
        };

        Ok((proof, statements))
    }
}
