// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_aggregation_round;
pub mod proof_share_round;

use std::{array, iter};

pub use bulletproofs::ProofError;
use bulletproofs::{BulletproofGens, PedersenGens};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint, U256, U64};
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
pub use proof_aggregation_round::Output;
use serde::{Deserialize, Serialize};

use crate::{
    commitment,
    commitment::{multipedersen::MultiPedersen, pedersen, GroupsPublicParameters, Pedersen},
    group,
    group::{ristretto, self_product, self_product::Value},
    helpers::FlatMapResults,
    proofs,
    proofs::{
        range,
        range::{
            CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement,
            Samplable,
        },
        schnorr::{
            enhanced,
            enhanced::{EnhanceableLanguage, EnhancedPublicParameters},
        },
    },
    PartyID,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("the aggregated commitment of the bulletproofs range proof did not match the concatenation of players individual commitment")]
    AggregatedCommitmentsMismatch,

    // TODO: name
    #[error("parties {:?} maliciously attempted to bypass the range proof by proving range on statements that do not match their Schnorr ones", .0)]
    RangeProofSchnorrMismatch(Vec<PartyID>),

    #[error("bulletproofs error")]
    Bulletproofs(#[from] ProofError),
}

/// A wrapper around `bulletproofs::RangeProof` that optionally adds the `aggregation_commitments`
/// for aggregated range proofs.
///
/// Whilst bulletproofs claim to have a constant-size proof and support
/// aggregation, these claims are false: the commitment aren't aggregated but are instead
/// concatenated, so that the commitment for the aggregated proofs is O(n) in the number of parties
/// and so is the verification time.
///
/// This breaks our `range::RangeProof` and `proofs::aggregation` interfaces, but since this is due
/// to the fact bulletproofs aren't actually aggregatable, we decided to think of the aggregated
/// proof as a (non-constant) struct that holds both what bulletproofs says is the proof and the
/// commitment.
///
/// This allows `RangeProof::verify()` to get the actual aggregated commitment as the parameter
/// (e.g. from an aggregated `schnorr::enhanced` language) and compare them to the non-aggregated
/// `aggregation_commitments`, whilst still allowing for the implementation to use the individual
/// commitment of each of the players in order to verify the proof.
///
/// For non-aggregated commitment, the commitment generated by bulletproofs are valid and
/// `aggregation_commitments` can remain empty.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RangeProof {
    proof: bulletproofs::RangeProof,
    aggregation_commitments: Vec<ristretto::GroupElement>,
}

pub const RANGE_CLAIM_BITS: usize = 32;

pub const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize = { ristretto::SCALAR_LIMBS };

impl super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS> for RangeProof {
    const NAME: &'static str = "Bulletproofs over the Ristretto group";

    type RangeClaimGroupElement = ristretto::Scalar;

    type CommitmentScheme<const NUM_RANGE_CLAIMS: usize> = MultiPedersen<
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        ristretto::Scalar,
        ristretto::GroupElement,
    >;

    const RANGE_CLAIM_BITS: usize = RANGE_CLAIM_BITS;

    type PublicParameters<const NUM_RANGE_CLAIMS: usize> = PublicParameters<NUM_RANGE_CLAIMS>;

    type AggregationCommitmentRoundParty<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    > = commitment_round::Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >;

    fn prove<const NUM_RANGE_CLAIMS: usize>(
        _public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        witnesses: Vec<
            commitment::MessageSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
        commitments_randomness: Vec<
            commitment::RandomnessSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
        transcript: Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Self,
        Vec<
            commitment::CommitmentSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
    )> {
        let number_of_witnesses = witnesses.len();

        let witnesses: Vec<_> = witnesses
            .into_iter()
            .map(|witness| <[_; NUM_RANGE_CLAIMS]>::from(witness))
            .flatten()
            .map(|witness: ristretto::Scalar| U256::from(witness))
            .collect();

        if witnesses
            .iter()
            .any(|witness| witness > &(&U64::MAX).into())
        {
            return Err(range::Error::OutOfRange)?;
        }

        let witnesses: Vec<u64> = witnesses
            .into_iter()
            .map(|witness| U64::from(&witness).into())
            .collect();

        let commitments_randomness: Vec<_> = commitments_randomness
            .into_iter()
            .flat_map(|multicommitment_randomness| {
                <[_; NUM_RANGE_CLAIMS]>::from(multicommitment_randomness)
            })
            .map(|randomness| randomness.0)
            .collect();

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
            bulletproofs_generators,
            commitment_generators,
            transcript,
            witnesses.as_slice(),
            commitments_randomness.as_slice(),
            <Self as super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RANGE_CLAIM_BITS,
            rng,
        ).map_err(range::bulletproofs::Error::from).map_err(range::Error::from)?;

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

        let commitments: proofs::Result<Vec<_>> = iter::repeat_with(|| {
            array::from_fn(|_| {
                commitments_iter
                    .next()
                    .ok_or(proofs::Error::InvalidParameters)
            })
            .flat_map_results()
            .map(
                commitment::CommitmentSpaceGroupElement::<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
                >::from,
            )
        })
        .take(number_of_witnesses)
        .collect();

        Ok((RangeProof::new(proof), commitments?))
    }

    fn new_enhanced_session<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    >(
        party_id: PartyID,
        threshold: PartyID,
        number_of_parties: PartyID,
        language_public_parameters: EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            Self,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        protocol_context: ProtocolContext,
        witnesses: Vec<
            enhanced::WitnessSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    ) -> Self::AggregationCommitmentRoundParty<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    > {
        commitment_round::Party {
            party_id,
            threshold,
            number_of_parties,
            language_public_parameters,
            protocol_context,
            witnesses,
        }
    }

    fn verify<const NUM_RANGE_CLAIMS: usize>(
        &self,
        _public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        commitments: Vec<
            commitment::CommitmentSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
        transcript: Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<()> {
        let commitments = if (self.aggregation_commitments.is_empty()) {
            commitments
                .into_iter()
                .flat_map(|multicommitment| {
                    <[ristretto::GroupElement; NUM_RANGE_CLAIMS]>::from(multicommitment)
                })
                .collect()
        } else {
            self.aggregation_commitments_match_aggregated_commitments(commitments.clone())?;

            self.aggregation_commitments.clone()
        };

        let commitments: Vec<_> = commitments
            .into_iter()
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
        let mut transcript = transcript;
        Ok(self.proof.verify_multiple_with_rng(
            &bulletproofs_generators,
            &commitment_generators,
            &mut transcript,
            compressed_commitments.as_slice(),
            <Self as super::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RANGE_CLAIM_BITS,
            rng,
        ).map_err(range::bulletproofs::Error::from).map_err(range::Error::from)?)
    }
}

// TODO: anything else? bullet proofs generators is a nice idea but we cannot access it.. also the
// code will hardcodedly call new()
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<const NUM_RANGE_CLAIMS: usize> {
    pub commitment_scheme_public_parameters: commitment::PublicParameters<
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

        let commitment_scheme_public_parameters = commitment::PublicParameters::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            Pedersen<
                1,
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
            [ristretto::GroupElement(commitment_generators.B)],
            ristretto::GroupElement(commitment_generators.B_blinding),
        )
        .into();

        Self {
            commitment_scheme_public_parameters,
            number_of_range_claims: NUM_RANGE_CLAIMS,
        }
    }
}

impl<const NUM_RANGE_CLAIMS: usize>
    AsRef<
        commitment::PublicParameters<
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
    ) -> &commitment::PublicParameters<
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

impl RangeProof {
    fn new(proof: bulletproofs::RangeProof) -> Self {
        Self {
            proof,
            aggregation_commitments: vec![],
        }
    }

    fn new_aggregated(
        proof: bulletproofs::RangeProof,
        aggregation_commitments: Vec<ristretto::GroupElement>,
    ) -> Self {
        Self {
            proof,
            aggregation_commitments,
        }
    }

    fn aggregation_commitments_match_aggregated_commitments<const NUM_RANGE_CLAIMS: usize>(
        &self,
        aggregated_commitments: Vec<
            commitment::CommitmentSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                range::CommitmentScheme<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    NUM_RANGE_CLAIMS,
                    RangeProof,
                >,
            >,
        >,
    ) -> crate::proofs::Result<()> {
        if aggregated_commitments
            .len()
            .checked_mul(NUM_RANGE_CLAIMS)
            .and_then(|x| self.aggregation_commitments.len().checked_rem(x))
            .ok_or(Error::AggregatedCommitmentsMismatch)
            .map_err(range::Error::from)?
            != 0
        {
            return Err(Error::AggregatedCommitmentsMismatch).map_err(range::Error::from)?;
        }

        let number_of_parties = aggregated_commitments
            .len()
            .checked_mul(NUM_RANGE_CLAIMS)
            .and_then(|x| self.aggregation_commitments.len().checked_div(x))
            .ok_or(proofs::Error::InternalError)?;

        let number_of_witnesses = aggregated_commitments
            .len()
            .checked_mul(number_of_parties)
            .ok_or(proofs::Error::InternalError)?;

        let mut bulletproofs_commitments_iter = self.aggregation_commitments.clone().into_iter();

        let bulletproofs_aggregated_commitments = iter::repeat_with(|| {
            array::from_fn(|_| {
                bulletproofs_commitments_iter
                    .next()
                    .ok_or(proofs::Error::InternalError)
            })
            .flat_map_results()
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

        let bulletproofs_aggregated_commitments = (0..aggregated_commitments.len())
            .map(|i| {
                (0..number_of_parties.into())
                    .map(|j: usize| {
                        j.checked_mul(aggregated_commitments.len())
                            .and_then(|index| index.checked_add(i))
                            .and_then(|index| {
                                bulletproofs_aggregated_commitments.get(index).cloned()
                            })
                            .ok_or(proofs::Error::InternalError)
                    })
                    .collect::<proofs::Result<Vec<_>>>()
            })
            .collect::<proofs::Result<Vec<_>>>()?;

        let bulletproofs_aggregated_commitments: Vec<_> = bulletproofs_aggregated_commitments
            .into_iter()
            .map(|v| {
                v.into_iter()
                    .reduce(|a, b| a + b)
                    .ok_or(proofs::Error::InternalError)
            })
            .collect::<proofs::Result<Vec<_>>>()?;

        if aggregated_commitments == bulletproofs_aggregated_commitments {
            Ok(())
        } else {
            Err(Error::AggregatedCommitmentsMismatch).map_err(range::Error::from)?
        }
    }
}
