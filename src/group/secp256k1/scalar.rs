// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, NonZero, Uint, U256};
use k256::elliptic_curve::{scalar::FromUintUnchecked, Field};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use super::GroupElement;
use crate::{
    group,
    group::{
        secp256k1::ORDER, BoundedGroupElement, CyclicGroupElement, KnownOrderGroupElement,
        KnownOrderScalar, MulByGenerator, PrimeGroupElement, Samplable,
    },
    traits::Reduce,
};

/// A Scalar of the prime field $\mathbb{Z}_p$ over which the secp256k1 prime group is
/// defined.
#[derive(PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Scalar(pub(super) k256::Scalar);

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Samplable for Scalar {
    fn sample(
        rng: &mut impl CryptoRngCore,
        _public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(Self(k256::Scalar::random(rng)))
    }
}

/// The public parameters of the secp256k1 scalar field.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    order: U256,
}

impl Default for PublicParameters {
    fn default() -> Self {
        PublicParameters {
            name: "The finite field of integers modulo prime q $\\mathbb{Z}_q$".to_string(),
            order: ORDER,
        }
    }
}

impl group::GroupElement for Scalar {
    type Value = Self;

    fn value(&self) -> Self::Value {
        *self
    }

    type PublicParameters = PublicParameters;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters::default()
    }

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        // Since `k256::Scalar` assures deserialized values are valid, this is always safe.
        Ok(value)
    }

    fn neutral(&self) -> Self {
        Self(k256::Scalar::ZERO)
    }

    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        self * Self::from(scalar)
    }

    fn double(&self) -> Self {
        Self(<k256::Scalar as Field>::double(&self.0))
    }
}

impl From<Scalar> for group::PublicParameters<Scalar> {
    fn from(_value: Scalar) -> Self {
        Self::default()
    }
}

impl BoundedGroupElement<{ U256::LIMBS }> for Scalar {}

impl<const LIMBS: usize> From<Uint<LIMBS>> for Scalar {
    fn from(value: Uint<LIMBS>) -> Self {
        Self(k256::Scalar::from_uint_unchecked(
            value.reduce(&NonZero::new(ORDER).unwrap()),
        ))
    }
}

impl<const LIMBS: usize> From<&Uint<LIMBS>> for Scalar {
    fn from(value: &Uint<LIMBS>) -> Self {
        Self::from(*value)
    }
}

impl From<Scalar> for U256 {
    fn from(value: Scalar) -> Self {
        value.0.into()
    }
}

impl From<&Scalar> for U256 {
    fn from(value: &Scalar) -> Self {
        value.0.into()
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Add<Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl<'r> Add<&'r Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Sub<Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl<'r> Sub<&'r Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl AddAssign<Self> for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<'r> AddAssign<&'r Self> for Scalar {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(&rhs.0)
    }
}

impl SubAssign<Self> for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<'r> SubAssign<&'r Self> for Scalar {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(&rhs.0)
    }
}

impl Mul<Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl<'r> Mul<&'r Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Mul<Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0.mul(rhs.0))
    }
}

impl<'r> Mul<&'r Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: &'r Scalar) -> Self::Output {
        Scalar(self.0.mul(&rhs.0))
    }
}

impl Mul<GroupElement> for Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl<'r> Mul<&'r GroupElement> for Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: &'r GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl<'r> Mul<GroupElement> for &'r Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl<'r> Mul<&'r GroupElement> for &'r Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: &'r GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl MulByGenerator<U256> for Scalar {
    fn mul_by_generator(&self, scalar: U256) -> Self {
        // In the additive scalar group, our generator is 1 and multiplying a group element by it
        // results in that same element. However, a `U256` might be bigger than the field
        // order, so we must first reduce it by the modulus to get a valid element.
        Self(k256::Scalar::from_uint_unchecked(
            scalar.reduce(&NonZero::new(ORDER).unwrap()),
        ))
    }
}

impl<'r> MulByGenerator<&'r U256> for Scalar {
    fn mul_by_generator(&self, scalar: &'r U256) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl CyclicGroupElement for Scalar {
    fn generator(&self) -> Self {
        Scalar(k256::Scalar::ONE)
    }
}

impl KnownOrderScalar<{ U256::LIMBS }> for Scalar {}

impl KnownOrderGroupElement<{ U256::LIMBS }> for Scalar {
    type Scalar = Self;
    fn order(&self) -> Uint<{ U256::LIMBS }> {
        ORDER
    }

    fn order_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Uint<{ U256::LIMBS }> {
        ORDER
    }
}

impl MulByGenerator<Scalar> for Scalar {
    fn mul_by_generator(&self, scalar: Scalar) -> Self {
        // In the additive scalar group, our generator is 1 and multiplying a group element by it
        // results in that same element.
        scalar
    }
}

impl<'r> MulByGenerator<&'r Scalar> for Scalar {
    fn mul_by_generator(&self, scalar: &'r Scalar) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl PrimeGroupElement<{ U256::LIMBS }> for Scalar {}
