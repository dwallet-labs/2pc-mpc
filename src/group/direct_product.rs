// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, BitAnd, Mul, MulAssign, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    group,
    group::{GroupElement as GroupElementTrait, Samplable},
};

/// An element of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FirstGroupElement,
    SecondGroupElement,
>(FirstGroupElement, SecondGroupElement);

pub type ThreeWayGroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
    const THIRD_SCALAR_LIMBS: usize,
    FirstGroupElement,
    SecondGroupElement,
    ThirdGroupElement,
> = GroupElement<
    SCALAR_LIMBS,
    FIRST_BY_SECOND_SCALAR_LIMBS,
    THIRD_SCALAR_LIMBS,
    GroupElement<
        FIRST_BY_SECOND_SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >,
    ThirdGroupElement,
>;

pub type FourWayGroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
    const THIRD_SCALAR_LIMBS: usize,
    const FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS: usize,
    const FOURTH_SCALAR_LIMBS: usize,
    FirstGroupElement,
    SecondGroupElement,
    ThirdGroupElement,
    FourthGroupElement,
> = GroupElement<
    SCALAR_LIMBS,
    FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
    FOURTH_SCALAR_LIMBS,
    GroupElement<
        FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
        FIRST_BY_SECOND_SCALAR_LIMBS,
        THIRD_SCALAR_LIMBS,
        GroupElement<
            FIRST_BY_SECOND_SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
        ThirdGroupElement,
    >,
    FourthGroupElement,
>;

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS> + Samplable<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS> + Samplable<SECOND_SCALAR_LIMBS>,
    > Samplable<SCALAR_LIMBS>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
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
/// `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
>(
    FirstGroupElement::PublicParameters,
    SecondGroupElement::PublicParameters,
);

/// The value of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct Value<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
>(FirstGroupElement::Value, SecondGroupElement::Value);

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > ConstantTimeEq
    for Value<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > GroupElementTrait<SCALAR_LIMBS>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Value = Value<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >;

    fn value(&self) -> Self::Value {
        Value(self.0.value(), self.1.value())
    }

    type PublicParameters = PublicParameters<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >;

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

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Neg
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg(), self.1.neg())
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Add<Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(rhs.1))
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Add<&'r Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(&rhs.1))
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Sub<Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(rhs.1))
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Sub<&'r Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(&rhs.1))
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > AddAssign<Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(rhs.1);
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > AddAssign<&'r Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(&rhs.1);
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > SubAssign<Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(rhs.1);
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > SubAssign<&'r Self>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(&rhs.1);
    }
}

impl<
        const LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<Uint<LIMBS>>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = Self;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<&'r Uint<LIMBS>>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = Self;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<Uint<LIMBS>>
    for &'r GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<&'r Uint<LIMBS>>
    for &'r GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    type Output = GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
        const LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > MulAssign<Uint<LIMBS>>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn mul_assign(&mut self, rhs: Uint<LIMBS>) {
        *self = self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > MulAssign<&'r Uint<LIMBS>>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn mul_assign(&mut self, rhs: &'r Uint<LIMBS>) {
        *self = self.scalar_mul(rhs)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
    >
    From<
        GroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    > for (FirstGroupElement, SecondGroupElement)
{
    fn from(
        value: GroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
    >
    From<
        &'r GroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    > for (&'r FirstGroupElement, &'r SecondGroupElement)
{
    fn from(
        value: &'r GroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
    > From<(FirstGroupElement, SecondGroupElement)>
    for GroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
{
    fn from(value: (FirstGroupElement, SecondGroupElement)) -> Self {
        Self(value.0, value.1)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    >
    From<
        PublicParameters<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    >
    for (
        FirstGroupElement::PublicParameters,
        SecondGroupElement::PublicParameters,
    )
{
    fn from(
        value: PublicParameters<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    >
    From<
        &'r PublicParameters<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    >
    for (
        &'r FirstGroupElement::PublicParameters,
        &'r SecondGroupElement::PublicParameters,
    )
{
    fn from(
        value: &'r PublicParameters<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
        >,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    >
    From<(
        FirstGroupElement::PublicParameters,
        SecondGroupElement::PublicParameters,
    )>
    for PublicParameters<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
    >
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

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
        const THIRD_SCALAR_LIMBS: usize,
        FirstGroupElement: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        SecondGroupElement: GroupElementTrait<SECOND_SCALAR_LIMBS>,
        ThirdGroupElement: GroupElementTrait<THIRD_SCALAR_LIMBS>,
    > From<(FirstGroupElement, SecondGroupElement, ThirdGroupElement)>
    for ThreeWayGroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FIRST_BY_SECOND_SCALAR_LIMBS,
        THIRD_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
    >
{
    fn from(value: (FirstGroupElement, SecondGroupElement, ThirdGroupElement)) -> Self {
        let (first_element, second_element, third_element) = value;

        GroupElement(GroupElement(first_element, second_element), third_element)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
        const THIRD_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
    >
    From<
        ThreeWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
        >,
    > for (FirstGroupElement, SecondGroupElement, ThirdGroupElement)
{
    fn from(
        value: ThreeWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
        >,
    ) -> Self {
        let (first_by_second_element, third_element) = value.into();
        let (first_element, second_element) = first_by_second_element.into();

        (first_element, second_element, third_element)
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
        const THIRD_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
    >
    From<
        &'r ThreeWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
        >,
    >
    for (
        &'r FirstGroupElement,
        &'r SecondGroupElement,
        &'r ThirdGroupElement,
    )
{
    fn from(
        value: &'r ThreeWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
        >,
    ) -> Self {
        let (first_by_second_element, third_element) = value.into();
        let (first_element, second_element) = first_by_second_element.into();

        (first_element, second_element, third_element)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
        const THIRD_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS: usize,
        const FOURTH_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    >
    From<(
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    )>
    for FourWayGroupElement<
        SCALAR_LIMBS,
        FIRST_SCALAR_LIMBS,
        SECOND_SCALAR_LIMBS,
        FIRST_BY_SECOND_SCALAR_LIMBS,
        THIRD_SCALAR_LIMBS,
        FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
        FOURTH_SCALAR_LIMBS,
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    >
{
    fn from(
        value: (
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        ),
    ) -> Self {
        let (first_element, second_element, third_element, fourth_element) = value;

        GroupElement(
            GroupElement(GroupElement(first_element, second_element), third_element),
            fourth_element,
        )
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
        const THIRD_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS: usize,
        const FOURTH_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    >
    From<
        FourWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
            FOURTH_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    >
    for (
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    )
{
    fn from(
        value: FourWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
            FOURTH_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    ) -> Self {
        let (first_by_second_by_third_element, fourth_element) = value.into();
        let (first_element, second_element, third_element) =
            first_by_second_by_third_element.into();

        (first_element, second_element, third_element, fourth_element)
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
        const THIRD_SCALAR_LIMBS: usize,
        const FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS: usize,
        const FOURTH_SCALAR_LIMBS: usize,
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    >
    From<
        &'r FourWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
            FOURTH_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    >
    for (
        &'r FirstGroupElement,
        &'r SecondGroupElement,
        &'r ThirdGroupElement,
        &'r FourthGroupElement,
    )
{
    fn from(
        value: &'r FourWayGroupElement<
            SCALAR_LIMBS,
            FIRST_SCALAR_LIMBS,
            SECOND_SCALAR_LIMBS,
            FIRST_BY_SECOND_SCALAR_LIMBS,
            THIRD_SCALAR_LIMBS,
            FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
            FOURTH_SCALAR_LIMBS,
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    ) -> Self {
        let (first_by_second_by_third_element, fourth_element) = value.into();
        let (first_element, second_element, third_element) =
            first_by_second_by_third_element.into();

        (first_element, second_element, third_element, fourth_element)
    }
}
