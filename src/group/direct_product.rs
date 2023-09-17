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

/// An element of the Direct Product of the two Groups `G` and `H`.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    G,
    H,
>(G, H);

pub type ThreeWayGroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    const G_SECOND_SCALAR_LIMBS: usize,
    const THIRD_SCALAR_LIMBS: usize,
    G,
    H,
    I,
> = GroupElement<
    SCALAR_LIMBS,
    G_SECOND_SCALAR_LIMBS,
    THIRD_SCALAR_LIMBS,
    GroupElement<G_SECOND_SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>,
    I,
>;

pub type FourWayGroupElement<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    const G_SECOND_SCALAR_LIMBS: usize,
    const THIRD_SCALAR_LIMBS: usize,
    const G_H_THIRD_SCALAR_LIMBS: usize,
    const FOURTH_SCALAR_LIMBS: usize,
    G,
    H,
    I,
    J,
> = GroupElement<
    SCALAR_LIMBS,
    G_H_THIRD_SCALAR_LIMBS,
    FOURTH_SCALAR_LIMBS,
    GroupElement<
        G_H_THIRD_SCALAR_LIMBS,
        G_SECOND_SCALAR_LIMBS,
        THIRD_SCALAR_LIMBS,
        GroupElement<G_SECOND_SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>,
        I,
    >,
    J,
>;

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS> + Samplable<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS> + Samplable<SECOND_SCALAR_LIMBS>,
    > Samplable<SCALAR_LIMBS>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(Self(
            G::sample(rng, &public_parameters.0)?,
            H::sample(rng, &public_parameters.1)?,
        ))
    }
}

/// The public parameters of the Direct Product of the two Groups `G` and `H`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
>(G::PublicParameters, H::PublicParameters);

/// The value of the Direct Product of the two Groups `G` and `H`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct Value<
    const SCALAR_LIMBS: usize,
    const FIRST_SCALAR_LIMBS: usize,
    const SECOND_SCALAR_LIMBS: usize,
    G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
    H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
>(G::Value, H::Value);

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > ConstantTimeEq for Value<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > GroupElementTrait<SCALAR_LIMBS>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    type Value = Value<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>;

    fn value(&self) -> Self::Value {
        Value(self.0.value(), self.1.value())
    }

    type PublicParameters =
        PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters(self.0.public_parameters(), self.1.public_parameters())
    }

    fn new(
        value: Self::Value,
        public_parameters: &Self::PublicParameters,
    ) -> crate::group::Result<Self> {
        Ok(Self(
            G::new(value.0, &public_parameters.0)?,
            H::new(value.1, &public_parameters.1)?,
        ))
    }

    fn neutral(&self) -> Self {
        Self(G::neutral(&self.0), H::neutral(&self.1))
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Neg for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Add<Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Add<&'r Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Sub<Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Sub<&'r Self> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > AddAssign<Self>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > AddAssign<&'r Self>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > SubAssign<Self>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > SubAssign<&'r Self>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<Uint<LIMBS>>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<&'r Uint<LIMBS>>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<Uint<LIMBS>>
    for &'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    type Output = GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>;

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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > Mul<&'r Uint<LIMBS>>
    for &'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    type Output = GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
        const LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > MulAssign<Uint<LIMBS>>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
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
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > MulAssign<&'r Uint<LIMBS>>
    for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    fn mul_assign(&mut self, rhs: &'r Uint<LIMBS>) {
        *self = self.scalar_mul(rhs)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > From<GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>> for (G, H)
{
    fn from(
        value: GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > From<&'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>>
    for (&'r G, &'r H)
{
    fn from(
        value: &'r GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > From<(G, H)> for GroupElement<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    fn from(value: (G, H)) -> Self {
        Self(value.0, value.1)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > From<PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>>
    for (G::PublicParameters, H::PublicParameters)
{
    fn from(
        value: PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<
        'r,
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > From<&'r PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>>
    for (&'r G::PublicParameters, &'r H::PublicParameters)
{
    fn from(
        value: &'r PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FIRST_SCALAR_LIMBS: usize,
        const SECOND_SCALAR_LIMBS: usize,
        G: GroupElementTrait<FIRST_SCALAR_LIMBS>,
        H: GroupElementTrait<SECOND_SCALAR_LIMBS>,
    > From<(G::PublicParameters, H::PublicParameters)>
    for PublicParameters<SCALAR_LIMBS, FIRST_SCALAR_LIMBS, SECOND_SCALAR_LIMBS, G, H>
{
    fn from(value: (G::PublicParameters, H::PublicParameters)) -> Self {
        Self(value.0, value.1)
    }
}
