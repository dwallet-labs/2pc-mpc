// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{array, iter};

use bulletproofs::{self, BulletproofGens, PedersenGens};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint, U64};
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use ristretto::SCALAR_LIMBS;
use serde::{Deserialize, Serialize};

use crate::{
    commitments,
    commitments::{multicommitment::MultiCommitment, pedersen, GroupsPublicParameters, Pedersen},
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, ristretto, self_product,
        self_product::Value,
    },
    helpers::flat_map_results,
    proofs,
    proofs::{
        range,
        schnorr::language::{enhanced, enhanced::ConstrainedWitnessValue},
    },
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RangeProof(bulletproofs::RangeProof);

impl PartialEq for RangeProof {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

pub const RANGE_CLAIM_LIMBS: usize = U64::LIMBS;

impl super::RangeProof<SCALAR_LIMBS, RANGE_CLAIM_LIMBS> for RangeProof {
    const NAME: &'static str = "Bulletproofs over the Ristretto group";

    type CommitmentScheme<const NUM_RANGE_CLAIMS: usize> = MultiCommitment<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, ristretto::Scalar, ristretto::GroupElement>,
    >;

    const RANGE_CLAIM_BITS: usize = 32;

    type PublicParameters<const NUM_RANGE_CLAIMS: usize> = PublicParameters<NUM_RANGE_CLAIMS>;

    fn prove<const NUM_RANGE_CLAIMS: usize>(
        _public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        witnesses: Vec<[Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
        commitments_randomness: Vec<
            commitments::RandomnessSpaceGroupElement<
                SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Self,
        Vec<
            commitments::CommitmentSpaceGroupElement<
                SCALAR_LIMBS,
                Self::CommitmentScheme<NUM_RANGE_CLAIMS>,
            >,
        >,
    )> {
        let number_of_witnesses = witnesses.len();

        let witnesses: Vec<u64> = witnesses
            .into_iter()
            .flatten()
            .map(|witness| witness.into())
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
            <Self as super::RangeProof<SCALAR_LIMBS, RANGE_CLAIM_LIMBS>>::RANGE_CLAIM_BITS,
            witnesses.len(),
        );
        let commitment_generators = PedersenGens::default();

        let (proof, commitments) = bulletproofs::RangeProof::prove_multiple_with_rng(
            &bulletproofs_generators,
            &commitment_generators,
            transcript,
            witnesses.as_slice(),
            commitments_randomness.as_slice(),
            <Self as super::RangeProof<SCALAR_LIMBS, RANGE_CLAIM_LIMBS>>::RANGE_CLAIM_BITS,
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
                    SCALAR_LIMBS,
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
                    SCALAR_LIMBS,
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
                SCALAR_LIMBS,
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
            <Self as super::RangeProof<SCALAR_LIMBS, RANGE_CLAIM_LIMBS>>::RANGE_CLAIM_BITS,
            compressed_commitments.len(),
        );
        let commitment_generators = PedersenGens::default();

        // TODO: convert their verification error to our range proof error?
        Ok(self.0.verify_multiple_with_rng(
            &bulletproofs_generators,
            &commitment_generators,
            transcript,
            compressed_commitments.as_slice(),
            <Self as super::RangeProof<SCALAR_LIMBS, RANGE_CLAIM_LIMBS>>::RANGE_CLAIM_BITS,
            rng,
        )?)
    }
}

// TODO: anything else? bullet proofs generators is a nice idea but we cannot access it.. also the
// code will hardcodedly call new()
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<const NUM_RANGE_CLAIMS: usize> {
    pub commitment_scheme_public_parameters: commitments::PublicParameters<
        SCALAR_LIMBS,
        MultiCommitment<
            NUM_RANGE_CLAIMS,
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, ristretto::Scalar, ristretto::GroupElement>,
        >,
    >,
    pub number_of_range_claims: usize,
    // TODO: number of parties?
    // TODO: range claims? i.e. number of bits to actually prove
}

impl<const NUM_RANGE_CLAIMS: usize> Default for PublicParameters<NUM_RANGE_CLAIMS> {
    fn default() -> Self {
        let scalar_public_parameters = ristretto::scalar::PublicParameters::default();
        let group_element_public_parameters = ristretto::group_element::PublicParameters::default();

        let pedersen_message_space_public_parameters =
            self_product::PublicParameters::<1, ristretto::scalar::PublicParameters>::new(
                scalar_public_parameters.clone(),
            );

        let pedersen_groups_public_parameters = GroupsPublicParameters {
            message_space_public_parameters: pedersen_message_space_public_parameters,
            randomness_space_public_parameters: scalar_public_parameters,
            commitment_space_public_parameters: group_element_public_parameters,
        };

        let commitment_generators = PedersenGens::default();

        let pedersen_public_parameters = pedersen::PublicParameters {
            groups_public_parameters: pedersen_groups_public_parameters,
            message_generators: [ristretto::GroupElement(commitment_generators.B)],
            randomness_generator: ristretto::GroupElement(commitment_generators.B_blinding),
        };

        let commitment_scheme_public_parameters = commitments::PublicParameters::<
            SCALAR_LIMBS,
            MultiCommitment<
                NUM_RANGE_CLAIMS,
                SCALAR_LIMBS,
                Pedersen<1, SCALAR_LIMBS, ristretto::Scalar, ristretto::GroupElement>,
            >,
        >::new(pedersen_public_parameters);

        Self {
            commitment_scheme_public_parameters,
            number_of_range_claims: NUM_RANGE_CLAIMS,
        }
    }
}

impl<const NUM_RANGE_CLAIMS: usize>
    AsRef<
        commitments::PublicParameters<
            SCALAR_LIMBS,
            MultiCommitment<
                NUM_RANGE_CLAIMS,
                SCALAR_LIMBS,
                Pedersen<1, SCALAR_LIMBS, ristretto::Scalar, ristretto::GroupElement>,
            >,
        >,
    > for PublicParameters<NUM_RANGE_CLAIMS>
{
    fn as_ref(
        &self,
    ) -> &commitments::PublicParameters<
        SCALAR_LIMBS,
        MultiCommitment<
            NUM_RANGE_CLAIMS,
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, ristretto::Scalar, ristretto::GroupElement>,
        >,
    > {
        &self.commitment_scheme_public_parameters
    }
}

impl<const NUM_RANGE_CLAIMS: usize, const WITNESS_MASK_LIMBS: usize>
    From<self_product::Value<NUM_RANGE_CLAIMS, Uint<WITNESS_MASK_LIMBS>>>
    for range::CommitmentSchemeMessageSpaceValue<
        SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >
where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    fn from(value: Value<NUM_RANGE_CLAIMS, Uint<WITNESS_MASK_LIMBS>>) -> Self {
        let value: [Uint<WITNESS_MASK_LIMBS>; NUM_RANGE_CLAIMS] = value.into();

        // TODO: need to specify when this is safe? for WITNESS_MASK_LIMBS < SCALAR_LIMBS
        // perhaps return result

        value
            .map(|v| ristretto::Scalar::from(Uint::<SCALAR_LIMBS>::from(&v)))
            .map(|scalar| [scalar].into())
            .into()
    }
}
