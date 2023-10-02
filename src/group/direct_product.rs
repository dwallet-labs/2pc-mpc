// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, BitAnd, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    group,
    group::{GroupElement as _, Samplable},
};

/// An element of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct GroupElement<FirstGroupElement, SecondGroupElement>(
    FirstGroupElement,
    SecondGroupElement,
);

pub type ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement> =
    GroupElement<GroupElement<FirstGroupElement, SecondGroupElement>, ThirdGroupElement>;

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
/// `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>(
    pub FirstGroupPublicParameters,
    pub SecondGroupPublicParameters,
);

pub type ThreeWayPublicParameters<
    FirstGroupPublicParameters,
    SecondGroupPublicParameters,
    ThirdGroupPublicParameters,
> = PublicParameters<
    PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>,
    ThirdGroupPublicParameters,
>;

/// The value of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Copy)]
pub struct Value<FirstGroupElementValue, SecondGroupElementValue>(
    FirstGroupElementValue,
    SecondGroupElementValue,
);

impl<FirstGroupElementValue: ConstantTimeEq, SecondGroupElementValue: ConstantTimeEq> ConstantTimeEq
    for Value<FirstGroupElementValue, SecondGroupElementValue>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    group::GroupElement for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Value = Value<group::Value<FirstGroupElement>, group::Value<SecondGroupElement>>;

    type PublicParameters =
        PublicParameters<FirstGroupElement::PublicParameters, SecondGroupElement::PublicParameters>;

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
impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<GroupElement<FirstGroupElement, SecondGroupElement>>
    for group::Value<GroupElement<FirstGroupElement, SecondGroupElement>>
{
    fn from(value: GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        Self(value.0.into(), value.1.into())
    }
}

impl<FirstGroupElement: group::GroupElement, SecondGroupElement: group::GroupElement>
    From<GroupElement<FirstGroupElement, SecondGroupElement>>
    for group::PublicParameters<GroupElement<FirstGroupElement, SecondGroupElement>>
{
    fn from(value: GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        Self(value.0.into(), value.1.into())
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

impl<FirstGroupElement, SecondGroupElement>
    From<GroupElement<FirstGroupElement, SecondGroupElement>>
    for (FirstGroupElement, SecondGroupElement)
{
    fn from(value: GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        (value.0, value.1)
    }
}

impl<'r, FirstGroupElement, SecondGroupElement>
    From<&'r GroupElement<FirstGroupElement, SecondGroupElement>>
    for (&'r FirstGroupElement, &'r SecondGroupElement)
{
    fn from(value: &'r GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        (&value.0, &value.1)
    }
}

impl<FirstGroupElement, SecondGroupElement> From<(FirstGroupElement, SecondGroupElement)>
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn from(value: (FirstGroupElement, SecondGroupElement)) -> Self {
        Self(value.0, value.1)
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters>
    From<PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>>
    for (FirstGroupPublicParameters, SecondGroupPublicParameters)
{
    fn from(
        value: PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<'r, FirstGroupPublicParameters, SecondGroupPublicParameters>
    From<&'r PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>>
    for (
        &'r FirstGroupPublicParameters,
        &'r SecondGroupPublicParameters,
    )
{
    fn from(
        value: &'r PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters>
    From<(FirstGroupPublicParameters, SecondGroupPublicParameters)>
    for PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>
{
    fn from(value: (FirstGroupPublicParameters, SecondGroupPublicParameters)) -> Self {
        Self(value.0, value.1)
    }
}

impl<FirstGroupElement, SecondGroupElement, ThirdGroupElement>
    From<(FirstGroupElement, SecondGroupElement, ThirdGroupElement)>
    for ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>
{
    fn from(value: (FirstGroupElement, SecondGroupElement, ThirdGroupElement)) -> Self {
        let (first_element, second_element, third_element) = value;

        GroupElement(GroupElement(first_element, second_element), third_element)
    }
}

impl<FirstGroupElement, SecondGroupElement, ThirdGroupElement>
    From<ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>>
    for (FirstGroupElement, SecondGroupElement, ThirdGroupElement)
{
    fn from(
        value: ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>,
    ) -> Self {
        let (first_by_second_element, third_element) = value.into();
        let (first_element, second_element) = first_by_second_element.into();

        (first_element, second_element, third_element)
    }
}

impl<'r, FirstGroupElement, SecondGroupElement, ThirdGroupElement>
    From<&'r ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>>
    for (
        &'r FirstGroupElement,
        &'r SecondGroupElement,
        &'r ThirdGroupElement,
    )
{
    fn from(
        value: &'r ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>,
    ) -> Self {
        let (first_by_second_element, third_element) = value.into();
        let (first_element, second_element) = first_by_second_element.into();

        (first_element, second_element, third_element)
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters, ThirdGroupPublicParameters>
    From<(
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
    )>
    for ThreeWayPublicParameters<
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
    >
{
    fn from(
        value: (
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        ),
    ) -> Self {
        let (first_public_parameters, second_public_parameters, third_public_parameters) = value;

        PublicParameters(
            PublicParameters(first_public_parameters, second_public_parameters),
            third_public_parameters,
        )
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters, ThirdGroupPublicParameters>
    From<
        ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    >
    for (
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
    )
{
    fn from(
        value: ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    ) -> Self {
        let (first_by_second_public_parameters, third_public_parameters) = value.into();
        let (first_public_parameters, second_public_parameters) =
            first_by_second_public_parameters.into();

        (
            first_public_parameters,
            second_public_parameters,
            third_public_parameters,
        )
    }
}

impl<'r, FirstGroupPublicParameters, SecondGroupPublicParameters, ThirdGroupPublicParameters>
    From<
        &'r ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    >
    for (
        &'r FirstGroupPublicParameters,
        &'r SecondGroupPublicParameters,
        &'r ThirdGroupPublicParameters,
    )
{
    fn from(
        value: &'r ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    ) -> Self {
        let (first_by_second_public_parameters, third_public_parameters) = value.into();
        let (first_public_parameters, second_public_parameters) =
            first_by_second_public_parameters.into();

        (
            first_public_parameters,
            second_public_parameters,
            third_public_parameters,
        )
    }
}
