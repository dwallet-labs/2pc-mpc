use std::hash::Hash;
// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_scalar_mul_bounded;
use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub mod direct_product;

pub mod secp256k1;
pub mod self_product;

pub mod paillier;

pub mod additive_group_of_integers_modulu_n;
pub mod multiplicative_group_of_integers_modulu_n;
pub mod ristretto;
pub mod scalar;

/// An error in group element instantiation [`GroupElement::new()`]
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("unsupported public parameters: the implementation doesn't support the public parameters, whether or not it identifies a valid group.")]
    UnsupportedPublicParameters,

    #[error(
        "invalid public parameters: no valid group can be identified by the public parameters."
    )]
    InvalidPublicParameters,

    #[error("invalid group element: the value does not belong to the group identified by the public parameters.")]
    InvalidGroupElement,
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
    Neg<Output = Self>
    + Add<Self, Output = Self>
    + for<'r> Add<&'r Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'r> Sub<&'r Self, Output = Self>
    + AddAssign<Self>
    + for<'r> AddAssign<&'r Self>
    + SubAssign<Self>
    + for<'r> SubAssign<&'r Self>
    + Into<Self::Value>
    + Into<Self::PublicParameters>
    + PartialEq
    + Eq
    + Clone
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
    /// In those cases, it is both ineffecient communication-wise to serialize these statements
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
        + ConditionallySelectable
        + Copy;

    /// Returns the value of this group element
    fn value(&self) -> Self::Value {
        self.clone().into()
    }

    /// The public parameters of the group, used for group operations.
    ///
    /// These include both dynamic information for runtime calculations
    /// (that provides the required context for `Self::new()` alongside the `Self::Value` to
    /// instantiate a `GroupElement`), as well as static information hardcoded into the code
    /// (that, together with the dynamic information, uniquely identifies a group and will be used
    /// for Fiat-Shamir Transcripts).
    type PublicParameters: Serialize + for<'r> Deserialize<'r> + Clone + PartialEq;

    /// Returns the public parameters of this group element
    fn public_parameters(&self) -> Self::PublicParameters {
        self.clone().into()
    }

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

    /// Constant-time Multiplication by (any bounded) natural number (scalar),     
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scalar_mul_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: usize,
    ) -> Self {
        // A bench implementation for groups whose underlying implementation does not expose a
        // bounded multiplication function, and operates in constant-time. Until such
        // functionality will be exposed, we shall only optimize for the special case of
        // `scalar_bits == 1`, which is both of particular interest for our proof system and easily
        // implemented via a single addition.

        // First take only the `scalar_bits` least significant bits
        let mask = (Uint::<LIMBS>::ONE << scalar_bits).wrapping_sub(&Uint::<LIMBS>::ONE);
        let scalar = scalar & mask;
        // TODO: maybe remove this or at least the if

        // TODO: test
        if scalar_bits == 1 {
            // // TODO: calls expensive `.value()` function
            // let value = Self::Value::conditional_select(
            //     &self.neutral().value(),
            //     &self.value(),
            //     scalar.ct_eq(&Uint::<LIMBS>::ONE),
            // );
            //
            // // Safe to unwrap as the value comes from a valid group element of the same public
            // // parameters.
            // Self::new(value, &self.public_parameters()).unwrap()

            if scalar == Uint::<LIMBS>::ONE {
                self.clone()
            } else {
                self.neutral()
            }
        } else {
            // Call the underlying scalar mul function, which now only use the `scalar_bits` least
            // significant bits, but will still take the same time to compute due to
            // constant-timeness.
            self.scalar_mul(&scalar)
        }
    }

    /// Double this point in constant-time.
    #[must_use]
    fn double(&self) -> Self;
}

pub type Value<G> = <G as GroupElement>::Value;

pub type PublicParameters<G> = <G as GroupElement>::PublicParameters;

/// An element of an abelian group of bounded (by `Uint<SCALAR_LIMBS>::MAX`) order, in additive
/// notation.
pub trait BoundedGroupElement<const SCALAR_LIMBS: usize>: GroupElement {
    // TODO: remove `scalar` from the name?
    /// Returns a (tight) lower-bound on the scalar group
    fn scalar_lower_bound(&self) -> Uint<SCALAR_LIMBS> {
        Self::scalar_lower_bound_from_public_parameters(&self.public_parameters())
    }

    /// Returns a (tight) lower-bound on the scalar group
    fn scalar_lower_bound_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS>;
}

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
    /// Returns the generator of the group
    fn generator(&self) -> Self;

    // TODO: generator value from public parameters

    /// Returns the value of generator of the group
    fn generator_from_public_parameters(public_parameters: &Self::PublicParameters) -> Self::Value;
}

pub trait KnownOrderScalar<const SCALAR_LIMBS: usize>:
    KnownOrderGroupElement<SCALAR_LIMBS, Scalar = Self>
    + Mul<Self, Output = Self>
    + for<'r> Mul<&'r Self, Output = Self>
    + Samplable
    + Copy
    + Into<Uint<SCALAR_LIMBS>>
{
}

/// An element of a known-order abelian group, in additive notation.
pub trait KnownOrderGroupElement<const SCALAR_LIMBS: usize>:
    BoundedGroupElement<SCALAR_LIMBS>
{
    type Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Mul<Self, Output = Self>
        + for<'r> Mul<&'r Self, Output = Self>;

    /// Returns the order of the group
    fn order(&self) -> Uint<SCALAR_LIMBS> {
        Self::order_from_public_parameters(&self.public_parameters())
    }

    /// Returns the order of the group
    fn order_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS>;
}

pub type Scalar<const SCALAR_LIMBS: usize, G> = <G as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar;
pub type ScalarPublicParameters<const SCALAR_LIMBS: usize, G> =
    PublicParameters<<G as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar>;
pub type ScalarValue<const SCALAR_LIMBS: usize, G> =
    Value<<G as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar>;

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

#[cfg(test)]
mod tests {
    use crypto_bigint::U64;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn multiplies_bounded_scalar() {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let scalar =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let point = scalar * generator;

        assert_eq!(
            scalar.scalar_mul_bounded(&U64::from(0u8), 1),
            scalar.neutral()
        );

        assert_eq!(
            point.scalar_mul_bounded(&U64::from(0u8), 1),
            point.neutral()
        );

        assert_eq!(
            scalar.scalar_mul_bounded(&U64::from(0u8), 1),
            scalar.scalar_mul(&U64::from(0u8)),
        );

        assert_eq!(
            point.scalar_mul_bounded(&U64::from(0u8), 1),
            point.scalar_mul(&U64::from(0u8)),
        );

        assert_eq!(scalar.scalar_mul_bounded(&U64::from(1u8), 1), scalar);

        assert_eq!(point.scalar_mul_bounded(&U64::from(1u8), 1), point);

        assert_eq!(
            scalar.scalar_mul_bounded(&U64::from(1u8), 1),
            scalar.scalar_mul(&U64::from(1u8)),
        );

        assert_eq!(
            point.scalar_mul_bounded(&U64::from(1u8), 1),
            point.scalar_mul(&U64::from(1u8)),
        );

        assert_eq!(
            scalar.scalar_mul_bounded(&U64::from(4u8), 1),
            scalar.neutral()
        );

        assert_eq!(
            point.scalar_mul_bounded(&U64::from(4u8), 1),
            point.neutral()
        );

        assert_eq!(
            scalar.scalar_mul_bounded(&U64::from(3u8), 1),
            scalar.scalar_mul_bounded(&U64::from(1u8), 1),
        );

        assert_eq!(
            point.scalar_mul_bounded(&U64::from(3u8), 1),
            point.scalar_mul_bounded(&U64::from(1u8), 1),
        );

        assert_eq!(
            scalar.scalar_mul_bounded(&U64::from(3u8), 2),
            scalar.scalar_mul(&U64::from(3u8)),
        );

        assert_eq!(
            point.scalar_mul_bounded(&U64::from(3u8), 2),
            point.scalar_mul(&U64::from(3u8)),
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;
    use crypto_bigint::{Random, U256};
    use rand_core::OsRng;

    use crate::group::{secp256k1, GroupElement as _, Samplable};

    pub(crate) fn benchmark_scalar_mul_bounded(c: &mut Criterion) {
        let mut g = c.benchmark_group("scalar_mul_bounded()");

        g.sample_size(10);

        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let scalar =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let point = scalar * generator;

        let exp = U256::random(&mut OsRng);

        for bitsize in [1, 128, 256] {
            g.bench_function(
                format!("secp256k1 scalar by {:?}-bit exponent", bitsize),
                |bench| bench.iter(|| scalar.scalar_mul_bounded(&exp, bitsize)),
            );

            g.bench_function(
                format!("secp256k1 point by {:?}-bit exponent", bitsize),
                |bench| bench.iter(|| point.scalar_mul_bounded(&exp, bitsize)),
            );
        }
    }
}
