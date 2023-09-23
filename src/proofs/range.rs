// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint, Wrapping};

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, self_product, GroupElement},
    proofs::Result,
};

pub trait RangeProof<
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims
    const RANGE_CLAIM_LIMBS: usize,
    // The upper bound for the scalar size of the commitment scheme's randomness group
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    // The upper bound for the scalar size of the commitment scheme's commitment group
    const COMMITMENT_SPACE_SCALAR_LIMBS: usize,
    // The commitment scheme's randomness group element
    RandomnessSpaceGroupElement,
    // The commitment scheme's commitment group element
    CommitmentSpaceGroupElement,
    // The commitment scheme used for the range proof
    CommitmentScheme,
>: PartialEq + Clone where
    RandomnessSpaceGroupElement: GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CommitmentSpaceGroupElement: GroupElement<COMMITMENT_SPACE_SCALAR_LIMBS>,
    CommitmentScheme: HomomorphicCommitmentScheme<
        RANGE_CLAIM_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        self_product::GroupElement<
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
        >,
        RandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
    >,
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
{
    // TODO: protocol context? needed or not?

    /// Proves in zero-knowledge that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn prove(
        witnesses_and_range_claims: Vec<[(power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>, Uint<RANGE_CLAIM_LIMBS>); NUM_RANGE_CLAIMS]>,
        commitment_randomness: &RandomnessSpaceGroupElement, // TODO: one for all?
        commitment: &CommitmentSpaceGroupElement, // TODO: one for all?
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self>;

    /// Verifies that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn verify(
        &self,
        range_claims: Vec<[Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
        commitment: &CommitmentSpaceGroupElement,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()>;
}
