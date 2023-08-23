// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crypto_bigint::Uint;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

#[derive(thiserror::Error, Debug, PartialEq)]
#[error("Invalid Group Element: does not belong to the group")]
pub struct InvalidGroupElementError();

/// An element of an abelian group of bounded (by `Uint<SCALAR_LIMBS>::MAX`) order, in additive
/// notation.
///
/// Group operations are only valid between elements within the group (otherwise the result is
/// undefined.)
///
/// All group operations are guaranteed to be constant time
pub trait GroupElement<const SCALAR_LIMBS: usize>:
    PartialEq
    + ConstantTimeEq
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
    + Mul<Uint<SCALAR_LIMBS>, Output = Self>
    + for<'r> Mul<&'r Uint<SCALAR_LIMBS>, Output = Self>
    + MulAssign<Uint<SCALAR_LIMBS>>
    + for<'r> MulAssign<&'r Uint<SCALAR_LIMBS>>
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
    type Value: Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + PartialEq
        + ConstantTimeEq
        + AsRef<[u8]>;

    /// Returns the value of this group element
    fn value(&self) -> &Self::Value;

    /// The public parameters of the group, used for group operations.
    ///
    /// These include both dynamic information for runtime calculations
    /// (that provides the required context for `Self::new()` alongside the `Self::Value` to
    /// instantiate a `GroupElement`), as well as static information hardcoded into the code
    /// (that, together with the dynamic information, uniquely identifies a group and will be used
    /// for Fiat-Shamir Transcripts).
    type PublicParameters: Serialize + for<'r> Deserialize<'r> + Clone + PartialEq + AsRef<[u8]>;

    /// Returns the public parameters of this group element
    fn public_parameters(&self) -> &Self::PublicParameters;

    /// Instantiate the group element from its value and the caller supplied parameters.
    ///
    /// *** NOTICE ***: `Self::new()` must check that the
    /// `value` belongs to the group identified by `params` and return an error otherwise!
    ///
    /// Even for static groups where `Self::Value = Self`, it must be assured the value is an
    /// element of the group either here or in deserialization.
    fn new(
        value: Self::Value,
        params: Self::PublicParameters,
    ) -> Result<Self, InvalidGroupElementError>;

    /// Returns the additive identity, also known as the "neutral element".
    fn neutral(&self) -> Self;

    /// Determines if this point is the identity in constant-time.
    fn is_neutral(&self) -> Choice {
        self.ct_eq(&self.neutral())
    }

    /// Constant-time Multiplication by (any bounded) natural number (scalar)
    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self;

    /// Double this point in constant-time.
    #[must_use]
    fn double(&self) -> Self;
}

/// Constant-time multiplication by the generator.
///
/// May use optimizations (e.g. precomputed tables) when available.
pub trait MulByGenerator<T>
where
    Self: Mul<T, Output = Self>,
{
    /// Multiply by the generator of the cyclic group in constant-time.
    #[must_use]
    fn mul_by_generator(scalar: T) -> Self;
}

/// An element of an abelian, cyclic group of bounded (by `Uint<SCALAR_LIMBS>::MAX`) order, in
/// additive notation.
pub trait CyclicGroupElement<const SCALAR_LIMBS: usize>:
    GroupElement<SCALAR_LIMBS> + MulByGenerator<Uint<SCALAR_LIMBS>>
{
    fn generator() -> Self;
}

/// An element of a known-order abelian group, in additive notation.
pub trait KnownOrderGroupElement<
    const SCALAR_LIMBS: usize,
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar>,
>:
    GroupElement<SCALAR_LIMBS>
    + Mul<Scalar, Output = Self>
    + for<'r> Mul<&'r Scalar, Output = Self>
    + MulAssign<Scalar>
    + for<'r> MulAssign<&'r Scalar>
{
    fn order() -> Uint<SCALAR_LIMBS>;
}

/// A marker trait for elements of a (known) prime-order group.
/// Any prime-order group is also cyclic.
/// In additive notation.
pub trait PrimeGroupElement<
    const SCALAR_LIMBS: usize,
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar>,
>:
    KnownOrderGroupElement<SCALAR_LIMBS, Scalar>
    + CyclicGroupElement<SCALAR_LIMBS>
    + MulByGenerator<Scalar>
{
}
