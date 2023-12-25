// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
// pub mod commitment_round;
// pub mod decommitment_and_poly_commitment_round;
// pub mod proof_aggregation_round;
// pub mod proof_share_round;

use std::{array, iter};

use bulletproofs::{BulletproofGens, PedersenGens};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint, U256, U64};
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    commitments,
    commitments::{multipedersen::MultiPedersen, pedersen, GroupsPublicParameters, Pedersen},
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, ristretto, self_product,
        self_product::Value,
    },
    helpers::flat_map_results,
    proofs,
    proofs::range,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RangeProof(bulletproofs::RangeProof);

impl PartialEq for RangeProof {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

pub const RANGE_CLAIM_BITS: usize = 32;

pub const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize = { ristretto::SCALAR_LIMBS };

impl super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS> for RangeProof {
    const NAME: &'static str = "Bulletproofs over the Ristretto group";

    type RangeClaimGroupElement = ristretto::Scalar;

    // TODO: change to multipedersen.
    type CommitmentScheme<const NUM_RANGE_CLAIMS: usize> = MultiPedersen<
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        ristretto::Scalar,
        ristretto::GroupElement,
    >;

    const RANGE_CLAIM_BITS: usize = RANGE_CLAIM_BITS;

    type PublicParameters<const NUM_RANGE_CLAIMS: usize> = PublicParameters<NUM_RANGE_CLAIMS>;

    fn prove<const NUM_RANGE_CLAIMS: usize>(
        _public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        witnesses: Vec<
            commitments::MessageSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
        commitments_randomness: Vec<
            commitments::RandomnessSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Self,
        Vec<
            commitments::CommitmentSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
    )> {
        let number_of_witnesses = witnesses.len();

        // TODO: do I want to check that witnesses are in range and return error here, or just let
        // the proof fail?
        let witnesses: Vec<u64> = witnesses
            .into_iter()
            .map(|witness| <[_; NUM_RANGE_CLAIMS]>::from(witness))
            .flatten()
            .map(|witness: ristretto::Scalar| U64::from(&U256::from(witness)).into())
            .collect();

        let commitments_randomness: Vec<curve25519_dalek::scalar::Scalar> = commitments_randomness
            .into_iter()
            .flat_map(|multicommitment_randomness| {
                <[ristretto::Scalar; NUM_RANGE_CLAIMS]>::from(multicommitment_randomness)
            })
            .map(|randomness| randomness.0)
            .collect();

        // TODO: above operation keeps order right?

        let padded_witnesses_length = witnesses.len().next_power_of_two();
        let mut iter = witnesses.into_iter();
        let witnesses: Vec<u64> = iter::repeat_with(|| iter.next().unwrap_or_else(|| 0u64))
            .take(padded_witnesses_length)
            .collect();

        let mut iter = commitments_randomness.into_iter();
        let commitments_randomness: Vec<curve25519_dalek::scalar::Scalar> =
            iter::repeat_with(|| {
                iter.next()
                    .unwrap_or_else(|| curve25519_dalek::scalar::Scalar::zero())
            })
            .take(padded_witnesses_length)
            .collect();

        let bulletproofs_generators = BulletproofGens::new(
            <Self as super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RANGE_CLAIM_BITS,
            witnesses.len(),
        );
        let commitment_generators = PedersenGens::default();

        let (proof, commitments) = bulletproofs::RangeProof::prove_multiple_with_rng(
            &bulletproofs_generators,
            &commitment_generators,
            transcript,
            witnesses.as_slice(),
            commitments_randomness.as_slice(),
            <Self as super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RANGE_CLAIM_BITS,
            rng,
        )?;

        let commitments: proofs::Result<Vec<curve25519_dalek::ristretto::RistrettoPoint>> =
            commitments
                .into_iter()
                .map(|compressed_commitment| {
                    compressed_commitment
                        .decompress()
                        .ok_or(proofs::Error::InvalidParameters)
                })
                .collect();

        // TODO: note that we create a `GroupElement` here without checking it is in the group.
        // We need to make sure bulletproofs make that check for it to be safe.
        let mut commitments_iter = commitments?
            .into_iter()
            .map(|point| ristretto::GroupElement(point));

        let commitments: proofs::Result<
            Vec<
                commitments::CommitmentSpaceGroupElement<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
                >,
            >,
        > = iter::repeat_with(|| {
            flat_map_results(array::from_fn(|_| {
                commitments_iter
                    .next()
                    .ok_or(proofs::Error::InvalidParameters)
            }))
            .map(
                commitments::CommitmentSpaceGroupElement::<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
                >::from,
            )
        })
        .take(number_of_witnesses)
        .collect();

        Ok((RangeProof(proof), commitments?))
    }

    fn verify<const NUM_RANGE_CLAIMS: usize>(
        &self,
        _public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        commitments: Vec<
            commitments::CommitmentSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> crate::proofs::Result<()> {
        let commitments: Vec<curve25519_dalek::ristretto::RistrettoPoint> = commitments
            .into_iter()
            .flat_map(|multicommitment| {
                <[ristretto::GroupElement; NUM_RANGE_CLAIMS]>::from(multicommitment)
            })
            .map(|commitment| commitment.0)
            .collect();

        let padded_commitments_length = commitments.len().next_power_of_two();
        let mut iter = commitments.into_iter();
        let compressed_commitments: Vec<curve25519_dalek::ristretto::CompressedRistretto> =
            iter::repeat_with(|| {
                iter.next()
                    .unwrap_or_else(|| curve25519_dalek::ristretto::RistrettoPoint::identity())
            })
            .take(padded_commitments_length)
            .map(|commtiment| commtiment.compress())
            .collect();

        let bulletproofs_generators = BulletproofGens::new(
            <Self as super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RANGE_CLAIM_BITS,
            compressed_commitments.len(),
        );
        let commitment_generators = PedersenGens::default();

        // TODO: convert their verification error to our range proof error?
        Ok(self.0.verify_multiple_with_rng(
            &bulletproofs_generators,
            &commitment_generators,
            transcript,
            compressed_commitments.as_slice(),
            <Self as super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RANGE_CLAIM_BITS,
            rng,
        )?)
    }
}

// TODO: anything else? bullet proofs generators is a nice idea but we cannot access it.. also the
// code will hardcodedly call new()
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<const NUM_RANGE_CLAIMS: usize> {
    pub commitment_scheme_public_parameters: commitments::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        MultiPedersen<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            ristretto::Scalar,
            ristretto::GroupElement,
        >,
    >,
    pub number_of_range_claims: usize,
    // TODO: number of parties?
    // TODO: range claims? i.e. number of bits to actually prove
}

impl<const NUM_RANGE_CLAIMS: usize> Default for PublicParameters<NUM_RANGE_CLAIMS> {
    fn default() -> Self {
        let scalar_public_parameters = ristretto::scalar::PublicParameters::default();
        let group_public_parameters = ristretto::group_element::PublicParameters::default();

        let commitment_generators = PedersenGens::default();

        let commitment_scheme_public_parameters = commitments::PublicParameters::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MultiPedersen<
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                ristretto::Scalar,
                ristretto::GroupElement,
            >,
        >::new::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            ristretto::Scalar,
            ristretto::GroupElement,
        >(
            scalar_public_parameters,
            group_public_parameters,
            ristretto::GroupElement(commitment_generators.B),
            ristretto::GroupElement(commitment_generators.B_blinding),
        );

        Self {
            commitment_scheme_public_parameters,
            number_of_range_claims: NUM_RANGE_CLAIMS,
        }
    }
}

impl<const NUM_RANGE_CLAIMS: usize>
    AsRef<
        commitments::PublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MultiPedersen<
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                ristretto::Scalar,
                ristretto::GroupElement,
            >,
        >,
    > for PublicParameters<NUM_RANGE_CLAIMS>
{
    fn as_ref(
        &self,
    ) -> &commitments::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        MultiPedersen<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            ristretto::Scalar,
            ristretto::GroupElement,
        >,
    > {
        &self.commitment_scheme_public_parameters
    }
}

// TODO: is this still needed
// impl<const NUM_RANGE_CLAIMS: usize, const WITNESS_MASK_LIMBS: usize>
//     From<self_product::Value<NUM_RANGE_CLAIMS, Uint<WITNESS_MASK_LIMBS>>>
//     for commitments::MessageSpaceValue<
//         COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//         range::CommitmentScheme<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS,
// RangeProof>,     >
// where
//     Uint<WITNESS_MASK_LIMBS>: Encoding,
// {
//     fn from(value: Value<NUM_RANGE_CLAIMS, Uint<WITNESS_MASK_LIMBS>>) -> Self {
//         let value: [Uint<WITNESS_MASK_LIMBS>; NUM_RANGE_CLAIMS] = value.into();
//
//         // TODO: need to specify when this is safe? for WITNESS_MASK_LIMBS <
// COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS         // perhaps return result
//
//         value
//             .map(|v|
// ristretto::Scalar::from(Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(&v)))
//             .map(|scalar| [scalar].into())
//             .into()
//     }
// }

// TODO: do I want the aggregation code?
//
// #[cfg(test)]
// pub(crate) mod tests {
//     use std::collections::HashMap;
//
//     use rand_core::OsRng;
//
//     use super::*;
//     use crate::{
//         proofs,
//         proofs::schnorr::{aggregation, Language, Proof},
//         Commitment, PartyID,
//     };
//
//     #[allow(dead_code)]
//     pub(crate) fn aggregates_internal<
//         const REPETITIONS: usize,
//         const NUM_RANGE_CLAIMS: usize,
//         const WITNESS_MASK_LIMBS: usize,
//         Language: EnhancedLanguage<
//             REPETITIONS,
//             { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
//             NUM_RANGE_CLAIMS,
//             { RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             RangeProof = super::RangeProof,
//         >,
//         ProtocolContext: Clone + Serialize,
//     >(
//         commitment_round_parties: HashMap<
//             PartyID,
//             commitment_round::Party<
//                 REPETITIONS,
//                 NUM_RANGE_CLAIMS,
//                 WITNESS_MASK_LIMBS,
//                 Language,
//                 ProtocolContext,
//             >,
//         >,
//     ) -> proofs::Result<(
//         enhanced::Proof<
//             REPETITIONS,
//             { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
//             NUM_RANGE_CLAIMS,
//             { RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Language,
//             ProtocolContext,
//         >,
//         Vec<Lang::StatementSpaceGroupElement>,
//     )> {
//         let commitments_and_decommitment_round_parties: HashMap<
//             PartyID,
//             (
//                 Commitment,
//                 decommitment_and_poly_commitment_round::Party<REPETITIONS, Lang,
// ProtocolContext>,             ),
//         > = commitment_round_parties .into_iter() .map(|(party_id, party)| { ( party_id, party
//         > .commit_statements_and_statement_mask(&mut OsRng) .unwrap(), ) }) .collect();
//
//         let commitments: HashMap<PartyID, Commitment> =
// commitments_and_decommitment_round_parties             .iter()
//             .map(|(party_id, (commitment, _))| (*party_id, *commitment))
//             .collect();
//
//         let decommitments_and_proof_share_round_parties: HashMap<
//             PartyID,
//             (
//                 aggregation::decommitment_round::Decommitment<REPETITIONS, Lang>,
//                 proof_share_round::Party<REPETITIONS, Lang, ProtocolContext>,
//             ),
//         > = commitments_and_decommitment_round_parties .into_iter() .map(|(party_id, (_, party))|
//         > { ( party_id, party .decommit_statements_and_statement_mask(commitments.clone())
//         > .unwrap(), ) }) .collect();
//
//         let decommitments: HashMap<
//             PartyID,
//             aggregation::decommitment_round::Decommitment<REPETITIONS, Lang>,
//         > = decommitments_and_proof_share_round_parties .iter() .map(|(party_id, (decommitment,
//         > _))| (*party_id, decommitment.clone())) .collect();
//
//         let proof_shares_and_proof_aggregation_round_parties: HashMap<
//             PartyID,
//             (
//                 ProofShare<REPETITIONS, Lang>,
//                 proof_aggregation_round::Party<REPETITIONS, Lang, ProtocolContext>,
//             ),
//         > = decommitments_and_proof_share_round_parties .into_iter() .map(|(party_id, (_,
//         > party))| { ( party_id, party.generate_proof_share(decommitments.clone()).unwrap(), ) })
//         > .collect();
//
//         let proof_shares: HashMap<PartyID, ProofShare<REPETITIONS, Lang>> =
//             proof_shares_and_proof_aggregation_round_parties
//                 .iter()
//                 .map(|(party_id, (proof_share, _))| (*party_id, proof_share.clone())) // TODO:
// why can't copy                 .collect();
//
//         let (_, (_, proof_aggregation_round_party)) =
//             proof_shares_and_proof_aggregation_round_parties
//                 .into_iter()
//                 .next()
//                 .unwrap();
//
//         proof_aggregation_round_party.aggregate_proof_shares(proof_shares.clone())
//     }
//
//     #[allow(dead_code)]
//     pub(crate) fn aggregates<
//         const REPETITIONS: usize,
//         const NUM_RANGE_CLAIMS: usize,
//         const WITNESS_MASK_LIMBS: usize,
//         Language: EnhancedLanguage<
//             REPETITIONS,
//             { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
//             NUM_RANGE_CLAIMS,
//             { RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             RangeProof = super::RangeProof,
//         >,
//     >(
//         language_public_parameters: &Lang::PublicParameters,
//         witnesses: Vec<Vec<Lang::WitnessSpaceGroupElement>>,
//     ) {
//         let number_of_parties = witnesses.len().try_into().unwrap();
//
//         let commitment_round_parties: HashMap<
//             PartyID,
//             commitment_round::Party<REPETITIONS, Lang, ()>,
//         > = witnesses .into_iter() .enumerate() .map(|(party_id, witnesses)| { let party_id: u16
//         > = (party_id + 1).try_into().unwrap(); let schnorr_commitment_round_party =
//         > aggregation::commitment_round::Party { party_id, threshold: number_of_parties,
//         > number_of_parties, language_public_parameters: language_public_parameters.clone(),
//         > protocol_context: (), witnesses, };
//
//                 (
//                     party_id,
//                     commitment_round::Party {
//                         schnorr_commitment_round_party,
//                     },
//                 )
//             })
//             .collect();
//
//         let res = aggregates_internal(commitment_round_parties);
//
//         assert!(
//             res.is_ok(),
//             "valid proof aggregation sessions should yield verifiable aggregated proofs, instead
// got error: {:?}",             res.err()
//         );
//     }
// }
