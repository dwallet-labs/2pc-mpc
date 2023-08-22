// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::Uint;
use subtle::{Choice, ConstantTimeEq};

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
{
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
    GroupElement<SCALAR_LIMBS> + Mul<Scalar, Output = Self> + for<'r> Mul<&'r Scalar, Output = Self>
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
