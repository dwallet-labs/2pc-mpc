// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

pub mod direct_product;

pub mod secp256k1;
pub mod self_product;

pub mod paillier;

pub mod additive_group_of_integers_modulu_n;
pub mod multiplicative_group_of_integers_modulu_n;

/// An error in group element instantiation [`GroupElement::new()`]
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error(
    "unsupported public parameters: the implementation doesn't support the public parameters, whether or not it identifies a valid group."
    )]
    UnsupportedPublicParametersError,

    #[error(
        "invalid public parameters: no valid group can be identified by the public parameters."
    )]
    InvalidPublicParametersError,

    #[error(
    "invalid group element: the value does not belong to the group identified by the public parameters."
    )]
    InvalidGroupElementError,
}

/// The Result of the `new()` operation of types implementing the `GroupElement` trait
pub type Result<T> = std::result::Result<T, Error>;

/// An element of an abelian group, in additive notation.
///
/// Group operations are only valid between elements within the group (otherwise the result is
/// undefined.)
///
/// All group operations are guaranteed to be constant time
pub trait GroupElement:
    PartialEq
    + Clone
    + Neg<Output = Self>
    + Add<Self, Output = Self>
    + for<'r> Add<&'r Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'r> Sub<&'r Self, Output = Self>
    + AddAssign<Self>
    + for<'r> AddAssign<&'r Self>
    + SubAssign<Self>
    + for<'r> SubAssign<&'r Self>
{
    /// The actual value of the group point used for encoding/decoding.
    ///
    /// For some groups (e.g. `group::secp256k1::Secp256k1GroupElement`) the group parameters and
    /// equations are statically hard-coded into the code, and then they would have `Self::Value
    /// = Self`.
    ///
    /// However, other groups (e.g. `group::paillier::PaillierCiphertextGroupElement`) rely on
    /// dynamic values to determine group operations in runtime (like the Paillier modulus
    /// $N^2$).
    ///
    /// In those cases, it is both ineffecient communication-wise to serialize these public values
    /// as they are known by the deserializing side, and even worse it is a security risk as
    /// malicious actors could try and craft groups in which they can break security assumptions
    /// in order to e.g. bypass zk-proof verification and have the verifier use those groups.
    ///
    /// In order to mitigate these risks and save on communication, we separate the value of the
    /// point from the group parameters.
    type Value: Serialize + for<'r> Deserialize<'r> + Clone + PartialEq + ConstantTimeEq;

    /// Returns the value of this group element
    fn value(&self) -> Self::Value;

    /// The public parameters of the group, used for group operations.
    ///
    /// These include both dynamic information for runtime calculations
    /// (that provides the required context for `Self::new()` alongside the `Self::Value` to
    /// instantiate a `GroupElement`), as well as static information hardcoded into the code
    /// (that, together with the dynamic information, uniquely identifies a group and will be used
    /// for Fiat-Shamir Transcripts).
    type PublicParameters: Serialize + for<'r> Deserialize<'r> + Clone + PartialEq;

    /// Returns the public parameters of this group element
    fn public_parameters(&self) -> Self::PublicParameters;

    /// Instantiate the group element from its value and the caller supplied parameters.
    ///
    /// *** NOTICE ***: `Self::new()` must check that the
    /// `value` belongs to the group identified by `params` and return an error otherwise!
    ///
    /// Even for static groups where `Self::Value = Self`, it must be assured the value is an
    /// element of the group either here or in deserialization.
    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// Returns the additive identity, also known as the "neutral element".
    fn neutral(&self) -> Self;

    /// Determines if this point is the identity in constant-time.
    fn is_neutral(&self) -> Choice {
        self.value().ct_eq(&self.neutral().value())
    }

    /// Constant-time Multiplication by (any bounded) natural number (scalar)
    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self;

    /// Double this point in constant-time.
    #[must_use]
    fn double(&self) -> Self;
}

pub type Value<G> = <G as GroupElement>::Value;

pub type PublicParameters<G> = <G as GroupElement>::PublicParameters;

/// An element of an abelian group of bounded (by `Uint<SCALAR_LIMBS>::MAX`) order, in additive
/// notation.
pub trait BoundedGroupElement<const SCALAR_LIMBS: usize>: GroupElement {}

/// Constant-time multiplication by the generator.
///
/// May use optimizations (e.g. precomputed tables) when available.
pub trait MulByGenerator<T> {
    /// Multiply by the generator of the cyclic group in constant-time.
    #[must_use]
    fn mul_by_generator(&self, scalar: T) -> Self;
}

/// An element of an abelian, cyclic group of bounded (by `Uint<SCALAR_LIMBS>::MAX`) order, in
/// additive notation.
pub trait CyclicGroupElement: GroupElement {
    fn generator(&self) -> Self;
}

/// An element of a known-order abelian group, in additive notation.
pub trait KnownOrderGroupElement<const SCALAR_LIMBS: usize>:
    BoundedGroupElement<SCALAR_LIMBS>
{
    type Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar = Self::Scalar>
        + Mul<Self, Output = Self>
        + for<'r> Mul<&'r Self, Output = Self>
        + Samplable
        + Copy;

    fn order(&self) -> Uint<SCALAR_LIMBS> {
        Self::order_from_public_parameters(&self.public_parameters())
    }

    fn order_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS>;
}

pub type Scalar<G, const SCALAR_LIMBS: usize> = <G as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar;

/// A marker trait for elements of a (known) prime-order group.
/// Any prime-order group is also cyclic.
/// In additive notation.
pub trait PrimeGroupElement<const SCALAR_LIMBS: usize>:
    KnownOrderGroupElement<SCALAR_LIMBS>
    + CyclicGroupElement
    + MulByGenerator<Self::Scalar>
    + for<'r> MulByGenerator<&'r Self::Scalar>
{
}

pub trait Samplable: GroupElement {
    /// Uniformly sample a random value.
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> Result<Self>;
}
