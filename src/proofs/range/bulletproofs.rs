// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use bulletproofs::{self, BulletproofGens, PedersenGens};
use crypto_bigint::{rand_core::CryptoRngCore, Uint, U256, U64};
use ristretto::SCALAR_LIMBS;
use serde::{Deserialize, Serialize};

use crate::{
    commitments,
    commitments::{multicommitment::MultiCommitment, pedersen, GroupsPublicParameters, Pedersen},
    group,
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, ristretto, self_product},
    proofs::{Error, Transcript},
};

const RANGE_CLAIM_LIMBS: usize = U64::LIMBS;

impl<const NUM_RANGE_CLAIMS: usize>
    super::RangeProof<SCALAR_LIMBS, NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>
    for bulletproofs::RangeProof
{
    const NAME: &'static str = "Bulletproofs over the Ristretto group";

    type CommitmentScheme = MultiCommitment<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, ristretto::Scalar, ristretto::GroupElement>,
    >;
    type PublicParameters = PublicParameters<NUM_RANGE_CLAIMS>;

    fn prove(
        public_parameters: &Self::PublicParameters,
        witnesses: Vec<[Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
        commitments_randomness: Vec<
            commitments::RandomnessSpaceGroupElement<SCALAR_LIMBS, Self::CommitmentScheme>,
        >,
        commitments: Vec<
            commitments::CommitmentSpaceGroupElement<SCALAR_LIMBS, Self::CommitmentScheme>,
        >,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> crate::proofs::Result<Self> {
        let commitment_generators = PedersenGens::default();

        let bulletproofs_generators = BulletproofGens::new(64, 1);

        let compressed_commitments: Vec<curve25519_dalek::ristretto::CompressedRistretto> =
            commitments
                .into_iter()
                .map(|multicommitment| {
                    <[ristretto::GroupElement; NUM_RANGE_CLAIMS]>::from(multicommitment)
                })
                .flatten()
                .map(|commitment| commitment.0.compress())
                .collect();

        let witnesses: Vec<u64> = witnesses
            .into_iter()
            .flatten()
            .map(|witness| witness.into())
            .collect();

        let commitments_randomness: Vec<curve25519_dalek::scalar::Scalar> = commitments_randomness
            .into_iter()
            .map(|multicommitment_randomness| {
                <[ristretto::Scalar; NUM_RANGE_CLAIMS]>::from(multicommitment_randomness)
            })
            .flatten()
            .map(|randomness| randomness.0)
            .collect();

        // TODO: above operation keeps order right?

        // TODO: the commitments here are being double computed? ...
        let (proof, proof_commitments) = bulletproofs::RangeProof::prove_multiple_with_rng(
            &bulletproofs_generators,
            &commitment_generators,
            transcript,
            witnesses.as_slice().into(),
            commitments_randomness.as_slice().into(),
            64,
            rng,
        )?;

        if proof_commitments != compressed_commitments {
            return Err(Error::InvalidParameters);
        }

        Ok(proof)
    }

    fn verify(
        &self,
        public_parameters: &Self::PublicParameters,
        commitments: Vec<
            commitments::CommitmentSpaceGroupElement<SCALAR_LIMBS, Self::CommitmentScheme>,
        >,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> crate::proofs::Result<()> {
        let commitment_generators = PedersenGens::default();

        let bulletproofs_generators = BulletproofGens::new(64, 1);

        let compressed_commitments: Vec<curve25519_dalek::ristretto::CompressedRistretto> =
            commitments
                .into_iter()
                .map(|multicommitment| {
                    <[ristretto::GroupElement; NUM_RANGE_CLAIMS]>::from(multicommitment)
                })
                .flatten()
                .map(|commitment| commitment.0.compress())
                .collect();

        Ok(self.verify_multiple_with_rng(
            &bulletproofs_generators,
            &commitment_generators,
            transcript,
            compressed_commitments.as_slice().into(),
            64,
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
