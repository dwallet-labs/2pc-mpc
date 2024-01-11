// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, NonZero, Random, Uint, U256};
use k256::elliptic_curve::ff::Field;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{GroupElement, SCALAR_LIMBS};
use crate::{
    group,
    group::{
        BoundedGroupElement, CyclicGroupElement, GroupElement as _, HashToGroup, Invert,
        KnownOrderGroupElement, KnownOrderScalar, MulByGenerator, PrimeGroupElement, Samplable,
    },
    traits::Reduce,
};

/// A Scalar of the prime field $\mathbb{Z}_p$ over which the ristretto prime group is
/// defined.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Scalar(pub(crate) curve25519_dalek::scalar::Scalar);

// TODO: handle these errors, which arise because the underlying crate of ristretto uses different
// subtle crate
impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, _other: &Self) -> Choice {
        todo!()
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        todo!()
        // Self(curve25519_dalek::scalar::Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl Samplable for Scalar {
    fn sample(
        _public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> group::Result<Self> {
        Ok(Self(curve25519_dalek::scalar::Scalar::random(rng)))
    }
}

/// The public parameters of the ristretto scalar field.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    order: U256,
    generator: Scalar,
}

impl Default for PublicParameters {
    fn default() -> Self {
        PublicParameters {
            name: "The finite field of integers modulo prime q $\\mathbb{Z}_q$".to_string(),
            order: super::ORDER,
            generator: Scalar(curve25519_dalek::scalar::Scalar::one()),
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
        // Since `curve25519_dalek::scalar::Scalar` assures deserialized values are valid, this is
        // always safe.
        Ok(value)
    }

    fn neutral(&self) -> Self {
        Self(curve25519_dalek::scalar::Scalar::zero())
    }

    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        self * Self::from(scalar)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl From<Scalar> for PublicParameters {
    fn from(_value: Scalar) -> Self {
        Self::default()
    }
}

impl BoundedGroupElement<SCALAR_LIMBS> for Scalar {
    fn lower_bound(&self) -> Uint<SCALAR_LIMBS> {
        self.order()
    }

    fn lower_bound_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        Self::order_from_public_parameters(public_parameters)
    }
}

impl<const LIMBS: usize> From<Uint<LIMBS>> for Scalar {
    fn from(value: Uint<LIMBS>) -> Self {
        let value: U256 = if LIMBS > U256::LIMBS {
            value.reduce(&NonZero::new(super::ORDER).unwrap())
        } else {
            (&value).into()
        };

        Self(curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
            value.to_le_bytes(),
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
        (&value).into()
    }
}

impl From<&Scalar> for U256 {
    fn from(value: &Scalar) -> Self {
        U256::from_le_bytes(*value.0.as_bytes())
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
        scalar.into()
    }
}

impl<'r> MulByGenerator<&'r U256> for Scalar {
    fn mul_by_generator(&self, scalar: &'r U256) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl CyclicGroupElement for Scalar {
    fn generator(&self) -> Self {
        Scalar(curve25519_dalek::scalar::Scalar::one())
    }

    fn generator_value_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Scalar(curve25519_dalek::scalar::Scalar::one())
    }
}

impl Invert for Scalar {
    fn invert(&self) -> CtOption<Self> {
        CtOption::new(Self(self.0.invert()), !self.is_neutral())
    }
}

impl KnownOrderScalar<SCALAR_LIMBS> for Scalar {}

impl KnownOrderGroupElement<SCALAR_LIMBS> for Scalar {
    type Scalar = Self;
    fn order(&self) -> Uint<SCALAR_LIMBS> {
        super::ORDER
    }

    fn order_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        super::ORDER
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

impl PrimeGroupElement<SCALAR_LIMBS> for Scalar {}

impl HashToGroup for Scalar {
    fn hash_to_group(bytes: &[u8]) -> group::Result<Self> {
        // TODO: what hash function to use ?
        Ok(Self(curve25519_dalek::scalar::Scalar::hash_from_bytes::<
            Sha512,
        >(bytes)))
    }
}
