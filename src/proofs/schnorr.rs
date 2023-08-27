// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;

use serde::Serialize;

use crate::group::GroupElement;

/// A Schnorr Zero-Knowledge Proof Language
/// Can be generically used to generate a batched Schnorr zero-knowledge proof
/// As defined in Appendix B. Schnorr Protocols in the paper
pub trait Language<
    // The upper bound for the scalar size of the witness group
    const WITNESS_SCALAR_LIMBS: usize,
    // The upper bound for the scalar size of the associated public-value space group
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    // An element of the witness space $(\HH, +)$
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    // An element in the associated public-value space $(\GG, \cdot)$
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
>
{
    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$
    ///
    /// Must uniquely identify the witness and statement spaces,
    /// as well as including all public parameters of the language
    /// (e.g., the public parameters of the commitment scheme used for proving knowledge of
    /// decommitment - the bases $g$, $h$ in the case of Pedersen)
    ///
    /// By restricting `Borrow` here we assure that `PublicParameters` encodes both
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `PublicValueSpaceGroupElement::PublicParameters`, which restricts implementors to hold
    /// copies of these values inside the struct they use for `PublicParameters`.
    type PublicParameters: Serialize
        + PartialEq
        + Borrow<WitnessSpaceGroupElement::PublicParameters>
        + Borrow<PublicValueSpaceGroupElement::PublicParameters>;

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
