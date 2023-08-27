// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::group::GroupElement;

/// A Schnorr Zero-Knowledge Proof Language
/// Can be generically used to generate a batched Schnorr zero-knowledge proof
pub trait Language<
    // The upper bound for the scalar size of the witness group
    const WITNESS_SCALAR_LIMBS: usize,
    // The upper bound for the scalar size of the associated public-value space group
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    // An element of the witness space $(\HH, +)$
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    // An element in the associated public-value space $(\GG, +)$
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
>
{
    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$
    type PublicParameters: Serialize + PartialEq;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// $\phi:\HH\to\GG$ a group homomorphism from $(\HH_\pp, +)$, the witness space, to $(\GG_\pp,
    /// \cdot)$, the statement space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
    ) -> PublicValueSpaceGroupElement;
}
