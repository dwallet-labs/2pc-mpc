// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, BitAnd, Mul, MulAssign, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    group,
    group::{GroupElement as _, Samplable},
};

/// An element of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<FirstGroupElement, SecondGroupElement>(
    FirstGroupElement,
    SecondGroupElement,
);

impl<
        FirstGroupElement: group::GroupElement + Samplable,
        SecondGroupElement: group::GroupElement + Samplable,
    > Samplable for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(Self(
            FirstGroupElement::sample(rng, &public_parameters.0)?,
            SecondGroupElement::sample(rng, &public_parameters.1)?,
        ))
    }
}

/// The public parameters of the Direct Product of the two Groups `FirstGroupElement` and
/// `SecondGroupElement`. The public parameters of the Direct Product of the two Groups
/// `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<
    FirstGroupElement: group::GroupElement,
    SecondGroupElement: group::GroupElement,
>(
    FirstGroupElement::PublicParameters,
    SecondGroupElement::PublicParameters,
);

/// The value of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct Value<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>(
    FirstGroupElement::Value,
    SecondGroupElement::Value,
);

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement> ConstantTimeEq
    for Value<FirstGroupElement, SecondGroupElement>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    group::GroupElement for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Value = Value<FirstGroupElement, SecondGroupElement>;

    fn value(&self) -> Self::Value {
        Value(self.0.value(), self.1.value())
    }

    type PublicParameters = PublicParameters<FirstGroupElement, SecondGroupElement>;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters(self.0.public_parameters(), self.1.public_parameters())
    }

    fn new(
        value: Self::Value,
        public_parameters: &Self::PublicParameters,
    ) -> crate::group::Result<Self> {
        Ok(Self(
            FirstGroupElement::new(value.0, &public_parameters.0)?,
            SecondGroupElement::new(value.1, &public_parameters.1)?,
        ))
    }

    fn neutral(&self) -> Self {
        Self(
            FirstGroupElement::neutral(&self.0),
            SecondGroupElement::neutral(&self.1),
        )
    }

    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        Self(self.0.scalar_mul(scalar), self.1.scalar_mul(scalar))
    }

    fn double(&self) -> Self {
        Self(self.0.double(), self.1.double())
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement> Neg
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg(), self.1.neg())
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement> Add<Self>
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(rhs.1))
    }
}

impl<'r, FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    Add<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(&rhs.1))
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement> Sub<Self>
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(rhs.1))
    }
}

impl<'r, FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    Sub<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(&rhs.1))
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    AddAssign<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(rhs.1);
    }
}

impl<'r, FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    AddAssign<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(&rhs.1);
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    SubAssign<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(rhs.1);
    }
}

impl<'r, FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    SubAssign<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(&rhs.1);
    }
}

impl<
        const LIMBS: usize,
        FirstGroupElement: group::GroupElement,
        SecondGroupElement: group::GroupElement,
    > Mul<Uint<LIMBS>> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: group::GroupElement,
        SecondGroupElement: group::GroupElement,
    > Mul<&'r Uint<LIMBS>> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: group::GroupElement,
        SecondGroupElement: group::GroupElement,
    > Mul<Uint<LIMBS>> for &'r GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = GroupElement<FirstGroupElement, SecondGroupElement>;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: group::GroupElement,
        SecondGroupElement: group::GroupElement,
    > Mul<&'r Uint<LIMBS>> for &'r GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = GroupElement<FirstGroupElement, SecondGroupElement>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
        const LIMBS: usize,
        FirstGroupElement: group::GroupElement,
        SecondGroupElement: group::GroupElement,
    > MulAssign<Uint<LIMBS>> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn mul_assign(&mut self, rhs: Uint<LIMBS>) {
        *self = self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: group::GroupElement,
        SecondGroupElement: group::GroupElement,
    > MulAssign<&'r Uint<LIMBS>> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn mul_assign(&mut self, rhs: &'r Uint<LIMBS>) {
        *self = self.scalar_mul(rhs)
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<GroupElement<FirstGroupElement, SecondGroupElement>>
    for (FirstGroupElement, SecondGroupElement)
{
    fn from(value: GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        (value.0, value.1)
    }
}

impl<'r, FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<&'r GroupElement<FirstGroupElement, SecondGroupElement>>
    for (&'r FirstGroupElement, &'r SecondGroupElement)
{
    fn from(value: &'r GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        (&value.0, &value.1)
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<(FirstGroupElement, SecondGroupElement)>
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn from(value: (FirstGroupElement, SecondGroupElement)) -> Self {
        Self(value.0, value.1)
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<PublicParameters<FirstGroupElement, SecondGroupElement>>
    for (
        FirstGroupElement::PublicParameters,
        SecondGroupElement::PublicParameters,
    )
{
    fn from(value: PublicParameters<FirstGroupElement, SecondGroupElement>) -> Self {
        (value.0, value.1)
    }
}

impl<'r, FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<&'r PublicParameters<FirstGroupElement, SecondGroupElement>>
    for (
        &'r FirstGroupElement::PublicParameters,
        &'r SecondGroupElement::PublicParameters,
    )
{
    fn from(value: &'r PublicParameters<FirstGroupElement, SecondGroupElement>) -> Self {
        (&value.0, &value.1)
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<(
        FirstGroupElement::PublicParameters,
        SecondGroupElement::PublicParameters,
    )> for PublicParameters<FirstGroupElement, SecondGroupElement>
{
    fn from(
        value: (
            FirstGroupElement::PublicParameters,
            SecondGroupElement::PublicParameters,
        ),
    ) -> Self {
        Self(value.0, value.1)
    }
}
