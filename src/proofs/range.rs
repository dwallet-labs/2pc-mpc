// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    commitments,
    commitments::HomomorphicCommitmentScheme,
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, self_product},
    proofs::Result,
};

// TODO: can I move consts to the function bodies?

pub trait RangeProof<
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims (the lower bound is fixed to zero.)
    const RANGE_CLAIM_LIMBS: usize,
>: PartialEq + Clone where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
{
    /// The commitment scheme used for the range proof
    type CommitmentScheme: HomomorphicCommitmentScheme<
    MessageSpaceGroupElement = self_product::GroupElement<
    NUM_RANGE_CLAIMS,
    power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
    >,
    >;

    /// The public parameters of the range proof.
    ///
    /// Includes the public parameters of the commitment scheme, and any range claims if the scheme permits such.
    ///
    /// SECURITY NOTE: Needs to be inserted to the  Fiat-Shamir Transcript of the proof protocol.
    type PublicParameters: AsRef<
        commitments::PublicParameters<Self::CommitmentScheme>
    > + Serialize
    + for<'r> Deserialize<'r>
    + Clone
    + PartialEq;

    /// Proves in zero-knowledge that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn prove(
        public_parameters: &Self::PublicParameters,
        witnesses: Vec<[power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
        commitment_randomness: &commitments::RandomnessSpaceGroupElement<Self::CommitmentScheme>,
        commitment: &commitments::CommitmentSpaceGroupElement<Self::CommitmentScheme>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self>;

    /// Verifies that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn verify(
        &self,
        public_parameters: &Self::PublicParameters,
        commitment: &commitments::CommitmentSpaceGroupElement<Self::CommitmentScheme>,
    ) -> Result<()>;
}

pub type CommitmentScheme<const NUM_RANGE_CLAIMS: usize, const RANGE_CLAIM_LIMBS: usize, Proof> =
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme;

pub type CommitmentSchemePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::PublicParameters<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeMessageSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::MessageSpaceGroupElement<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeMessageSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::MessageSpacePublicParameters<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeMessageSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::MessageSpaceValue<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeRandomnessSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::RandomnessSpaceGroupElement<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeRandomnessSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::RandomnessSpacePublicParameters<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeRandomnessSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::RandomnessSpaceValue<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeCommitmentSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::CommitmentSpaceGroupElement<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeCommitmentSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::CommitmentSpacePublicParameters<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;

pub type CommitmentSchemeCommitmentSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::CommitmentSpaceValue<
    <Proof as RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::CommitmentScheme,
>;
