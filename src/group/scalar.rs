// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::{
    group,
    group::{
        BoundedGroupElement, GroupElement, Invert, KnownOrderGroupElement, KnownOrderScalar,
        Samplable,
    },
};

/// Newtype used to comply with Rust's local-type checks.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct Scalar<const SCALAR_LIMBS: usize, S>(pub S);

/// Newtype used to comply with Rust's local-type checks.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<PP>(PP);

/// Newtype used to comply with Rust's local-type checks.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Serialize, Deserialize)]
pub struct Value<V>(V);

impl<const SCALAR_LIMBS: usize, S: GroupElement> GroupElement for Scalar<SCALAR_LIMBS, S> {
    type Value = Value<group::Value<S>>;
    type PublicParameters = PublicParameters<group::PublicParameters<S>>;

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        Ok(Self(S::new(value.0, &public_parameters.0)?))
    }

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters(self.0.public_parameters())
    }

    fn neutral(&self) -> Self {
        Self(self.0.neutral())
    }

    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        Self(self.0.scalar_mul(scalar))
    }

    fn scalar_mul_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: usize,
    ) -> Self {
        Self(self.0.scalar_mul_bounded(scalar, scalar_bits))
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }
}

impl<V: ConstantTimeEq> ConstantTimeEq for Value<V> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<V: ConditionallySelectable> ConditionallySelectable for Value<V> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(V::conditional_select(&a.0, &b.0, choice))
    }
}

impl<const SCALAR_LIMBS: usize, V: From<Uint<SCALAR_LIMBS>>> From<Uint<SCALAR_LIMBS>> for Value<V> {
    fn from(value: Uint<SCALAR_LIMBS>) -> Self {
        Value(V::from(value))
    }
}

impl<const SCALAR_LIMBS: usize, V: Into<Uint<SCALAR_LIMBS>>> Into<Uint<SCALAR_LIMBS>> for Value<V> {
    fn into(self) -> Uint<SCALAR_LIMBS> {
        self.0.into()
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement> Neg for Scalar<SCALAR_LIMBS, S> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement> Add<Self> for Scalar<SCALAR_LIMBS, S> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl<'r, const SCALAR_LIMBS: usize, S: GroupElement> Add<&'r Self> for Scalar<SCALAR_LIMBS, S> {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement> Sub<Self> for Scalar<SCALAR_LIMBS, S> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl<'r, const SCALAR_LIMBS: usize, S: GroupElement> Sub<&'r Self> for Scalar<SCALAR_LIMBS, S> {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement> AddAssign<Self> for Scalar<SCALAR_LIMBS, S> {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<'r, const SCALAR_LIMBS: usize, S: GroupElement> AddAssign<&'r Self>
    for Scalar<SCALAR_LIMBS, S>
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(&rhs.0)
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement> SubAssign<Self> for Scalar<SCALAR_LIMBS, S> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<'r, const SCALAR_LIMBS: usize, S: GroupElement> SubAssign<&'r Self>
    for Scalar<SCALAR_LIMBS, S>
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'r, const SCALAR_LIMBS: usize, S: GroupElement> Mul<Scalar<SCALAR_LIMBS, S>>
    for &'r Scalar<SCALAR_LIMBS, S>
where
    &'r S: Mul<S, Output = S>,
{
    type Output = Scalar<SCALAR_LIMBS, S>;

    fn mul(self, rhs: Scalar<SCALAR_LIMBS, S>) -> Self::Output {
        Scalar::<SCALAR_LIMBS, S>(self.0.mul(rhs.0))
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement + Mul<S, Output = S>> Mul<Self>
    for Scalar<SCALAR_LIMBS, S>
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<'r, const SCALAR_LIMBS: usize, S: GroupElement + Mul<&'r S, Output = S>> Mul<&'r Self>
    for Scalar<SCALAR_LIMBS, S>
{
    type Output = Self;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        Self(self.0 * &rhs.0)
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement> From<Scalar<SCALAR_LIMBS, S>>
    for PublicParameters<S::PublicParameters>
{
    fn from(value: Scalar<SCALAR_LIMBS, S>) -> Self {
        PublicParameters(value.0.into())
    }
}

impl<const SCALAR_LIMBS: usize, S: GroupElement> From<Scalar<SCALAR_LIMBS, S>> for Value<S::Value> {
    fn from(value: Scalar<SCALAR_LIMBS, S>) -> Self {
        Value(value.0.into())
    }
}

impl<const SCALAR_LIMBS: usize, S: BoundedGroupElement<SCALAR_LIMBS>>
    BoundedGroupElement<SCALAR_LIMBS> for Scalar<SCALAR_LIMBS, S>
{
    fn lower_bound(&self) -> Uint<SCALAR_LIMBS> {
        self.0.lower_bound()
    }
    fn lower_bound_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        S::lower_bound_from_public_parameters(&public_parameters.0)
    }
}

impl<const SCALAR_LIMBS: usize, S: Into<Uint<SCALAR_LIMBS>>> From<Scalar<SCALAR_LIMBS, S>>
    for Uint<SCALAR_LIMBS>
{
    fn from(value: Scalar<SCALAR_LIMBS, S>) -> Self {
        value.0.into()
    }
}

impl<const SCALAR_LIMBS: usize, S: KnownOrderScalar<SCALAR_LIMBS>> Invert
    for Scalar<SCALAR_LIMBS, S>
where
    S: Default + ConditionallySelectable,
{
    fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }
}

impl<const SCALAR_LIMBS: usize, S: KnownOrderScalar<SCALAR_LIMBS>> KnownOrderScalar<SCALAR_LIMBS>
    for Scalar<SCALAR_LIMBS, S>
where
    S::Value: From<Uint<SCALAR_LIMBS>> + Into<Uint<SCALAR_LIMBS>>,
    S: Default + ConditionallySelectable,
{
}

impl<const SCALAR_LIMBS: usize, S: KnownOrderScalar<SCALAR_LIMBS>>
    KnownOrderGroupElement<SCALAR_LIMBS> for Scalar<SCALAR_LIMBS, S>
where
    S::Value: From<Uint<SCALAR_LIMBS>> + Into<Uint<SCALAR_LIMBS>>,
    S: Default + ConditionallySelectable,
{
    type Scalar = Self;

    fn order_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        S::order_from_public_parameters(&public_parameters.0)
    }
}

impl<const SCALAR_LIMBS: usize, S: Samplable> Samplable for Scalar<SCALAR_LIMBS, S> {
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> group::Result<Self> {
        Ok(Self(S::sample(&public_parameters.0, rng)?))
    }
}
