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

/// An element of the Direct Product of the two Groups `FIRST_GROUP_ELEMENT` and `SECOND_GROUP_ELEMENT`.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT,
    SECOND_GROUP_ELEMENT,
>(FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT);

pub type ThreeWayGroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
    const THIRD_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT,
    SECOND_GROUP_ELEMENT,
    THIRD_GROUP_ELEMENT,
> = GroupElement<
    SCALAR_LIMBS,
    FIRST_BY_SECOND_SCALAR_LIMBS,
    THIRD_SCALAR_LIMBS,
    GroupElement<FIRST_BY_SECOND_SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>,
    THIRD_GROUP_ELEMENT,
>;

pub type FourWayGroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
    const THIRD_SCALAR_LIMBS: usize,
    const FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS: usize,
    const FOURTH_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT,
    SECOND_GROUP_ELEMENT,
    THIRD_GROUP_ELEMENT,
    FOURTH_GROUP_ELEMENT,
> = GroupElement<
    SCALAR_LIMBS,
    FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
    FOURTH_SCALAR_LIMBS,
    GroupElement<
        FIRST_BY_SECOND_BY_THIRD_SCALAR_LIMBS,
        FIRST_BY_SECOND_SCALAR_LIMBS,
        THIRD_SCALAR_LIMBS,
        GroupElement<FIRST_BY_SECOND_SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>,
        THIRD_GROUP_ELEMENT,
    >,
    FOURTH_GROUP_ELEMENT,
>;

impl<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS> + Samplable<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS> + Samplable<SECOND_SCALAR_LIMBS>,
> Samplable<SCALAR_LIMBS>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(Self(
            FIRST_GROUP_ELEMENT::sample(rng, &public_parameters.0)?,
            SECOND_GROUP_ELEMENT::sample(rng, &public_parameters.1)?,
        ))
    }
}

/// The public parameters of the Direct Product of the two Groups `FIRST_GROUP_ELEMENT` and `SECOND_GROUP_ELEMENT`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
>(FIRST_GROUP_ELEMENT::PublicParameters, SECOND_GROUP_ELEMENT::PublicParameters);

/// The value of the Direct Product of the two Groups `FIRST_GROUP_ELEMENT` and `SECOND_GROUP_ELEMENT`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct Value<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
>(FIRST_GROUP_ELEMENT::Value, SECOND_GROUP_ELEMENT::Value);

impl<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> ConstantTimeEq for Value<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> GroupElementTrait<SCALAR_LIMBS>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    type Value = Value<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>;

    fn value(&self) -> Self::Value {
        Value(self.0.value(), self.1.value())
    }

    type PublicParameters =
    PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters(self.0.public_parameters(), self.1.public_parameters())
    }

    fn new(
        value: Self::Value,
        public_parameters: &Self::PublicParameters,
    ) -> crate::group::Result<Self> {
        Ok(Self(
            FIRST_GROUP_ELEMENT::new(value.0, &public_parameters.0)?,
            SECOND_GROUP_ELEMENT::new(value.1, &public_parameters.1)?,
        ))
    }

    fn neutral(&self) -> Self {
        Self(FIRST_GROUP_ELEMENT::neutral(&self.0), SECOND_GROUP_ELEMENT::neutral(&self.1))
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Neg for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Add<Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Add<&'r Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Sub<Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Sub<&'r Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> AddAssign<Self>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> AddAssign<&'r Self>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> SubAssign<Self>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> SubAssign<&'r Self>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Mul<Uint<LIMBS>>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Mul<&'r Uint<LIMBS>>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Mul<Uint<LIMBS>>
for &'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    type Output = GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>;

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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> Mul<&'r Uint<LIMBS>>
for &'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    type Output = GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
    const LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> MulAssign<Uint<LIMBS>>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
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
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> MulAssign<&'r Uint<LIMBS>>
for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    fn mul_assign(&mut self, rhs: &'r Uint<LIMBS>) {
        *self = self.scalar_mul(rhs)
    }
}

impl<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> From<GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>> for (FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT)
{
    fn from(
        value: GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<
    'r,
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> From<&'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>>
for (&'r FIRST_GROUP_ELEMENT, &'r SECOND_GROUP_ELEMENT)
{
    fn from(
        value: &'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> From<(FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT)> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    fn from(value: (FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT)) -> Self {
        Self(value.0, value.1)
    }
}

impl<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> From<PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>>
for (FIRST_GROUP_ELEMENT::PublicParameters, SECOND_GROUP_ELEMENT::PublicParameters)
{
    fn from(
        value: PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<
    'r,
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> From<&'r PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>>
for (&'r FIRST_GROUP_ELEMENT::PublicParameters, &'r SECOND_GROUP_ELEMENT::PublicParameters)
{
    fn from(
        value: &'r PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
> From<(FIRST_GROUP_ELEMENT::PublicParameters, SECOND_GROUP_ELEMENT::PublicParameters)>
for PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT>
{
    fn from(value: (FIRST_GROUP_ELEMENT::PublicParameters, SECOND_GROUP_ELEMENT::PublicParameters)) -> Self {
        Self(value.0, value.1)
    }
}

impl<const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    const FIRST_BY_SECOND_SCALAR_LIMBS: usize,
    const THIRD_SCALAR_LIMBS: usize,
    FIRST_GROUP_ELEMENT: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    SECOND_GROUP_ELEMENT: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    THIRD_GROUP_ELEMENT: GroupElementTrait<THIRD_SCALAR_LIMBS>,
> From<(FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT)> for ThreeWayGroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, FIRST_BY_SECOND_SCALAR_LIMBS, THIRD_SCALAR_LIMBS, FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT> {
    fn from(value: (FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT)) -> Self {
        todo!()
    }
}


//
// impl<FIRST_GROUP_ELEMENT: GroupElement, SECOND_GROUP_ELEMENT: GroupElement, THIRD_GROUP_ELEMENT: GroupElement> From<(FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT)>
//     for ThreeWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT>
// {
//     fn from(value: (FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT)) -> Self {
//         ProductGroupElement(ProductGroupElement(value.0, value.1), value.2)
//     }
// }
//

// impl<FIRST_GROUP_ELEMENT: GroupElement, SECOND_GROUP_ELEMENT: GroupElement, THIRD_GROUP_ELEMENT: GroupElement> From<ThreeWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT>>
//     for (FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT)
// {
//     fn from(value: ThreeWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT>) -> Self {
//         (value.0 .0, value.0 .1, value.1)
//     }
// }
//
// impl<'r, FIRST_GROUP_ELEMENT: GroupElement, SECOND_GROUP_ELEMENT: GroupElement, THIRD_GROUP_ELEMENT: GroupElement> From<&'r ThreeWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT>>
//     for (&'r FIRST_GROUP_ELEMENT, &'r SECOND_GROUP_ELEMENT, &'r THIRD_GROUP_ELEMENT)
// {
//     fn from(value: &'r ThreeWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT>) -> Self {
//         (&value.0 .0, &value.0 .1, &value.1)
//     }
// }
//
// impl<FIRST_GROUP_ELEMENT: GroupElement, SECOND_GROUP_ELEMENT: GroupElement, THIRD_GROUP_ELEMENT: GroupElement, FOURTH_GROUP_ELEMENT: GroupElement> From<(FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT)>
//     for FourWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT>
// {
//     fn from(value: (FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT)) -> Self {
//         ProductGroupElement(
//             ProductGroupElement(value.0, value.1),
//             ProductGroupElement(value.2, value.3),
//         )
//     }
// }
//
// impl<FIRST_GROUP_ELEMENT: GroupElement, SECOND_GROUP_ELEMENT: GroupElement, THIRD_GROUP_ELEMENT: GroupElement, FOURTH_GROUP_ELEMENT: GroupElement>
//     From<FourWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT>> for (FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT)
// {
//     fn from(value: FourWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT>) -> Self {
//         (value.0 .0, value.0 .1, value.1 .0, value.1 .1)
//     }
// }
//
// impl<'r, FIRST_GROUP_ELEMENT: GroupElement, SECOND_GROUP_ELEMENT: GroupElement, THIRD_GROUP_ELEMENT: GroupElement, FOURTH_GROUP_ELEMENT: GroupElement>
//     From<&'r FourWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT>> for (&'r FIRST_GROUP_ELEMENT, &'r SECOND_GROUP_ELEMENT, &'r THIRD_GROUP_ELEMENT, &'r FOURTH_GROUP_ELEMENT)
// {
//     fn from(value: &'r FourWayGroupElement<FIRST_GROUP_ELEMENT, SECOND_GROUP_ELEMENT, THIRD_GROUP_ELEMENT, FOURTH_GROUP_ELEMENT>) -> Self {
//         (&value.0 .0, &value.0 .1, &value.1 .0, &value.1 .1)
//     }
// }
