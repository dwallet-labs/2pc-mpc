// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint, Wrapping};

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group::{additive_group_of_integers_modulu_n, self_product, GroupElement},
    proofs::Result,
};

pub trait RangeProof<
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims
    const RANGE_CLAIM_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const COMMITMENT_SPACE_SCALAR_LIMBS: usize,
    RandomnessSpaceGroupElement,
    CommitmentSpaceGroupElement,
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
            Wrapping<Uint<RANGE_CLAIM_LIMBS>>,
        >,
        RandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
    >,
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
{
    /// Proves that all `witnesses` committed in `commitment` are bounded by their corresponding
    /// range upper bound in `range_claims`.
    fn prove(
        witnesses: [Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS], // TODO: batching?
        range_claims: [Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS],
        randomness: &RandomnessSpaceGroupElement,
        commitment: &CommitmentSpaceGroupElement,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self>;
}

// TODO: actually, additive_group_modulu_n is not what I need here; I need group over
// Wrapped<Uint<>> and not over DynResidue. As my modulus is 2^n which is not odd so can't use
// DynResidue, also operations are much cheaper with Uint.
