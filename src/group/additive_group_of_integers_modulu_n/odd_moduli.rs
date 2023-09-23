// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

// This should be called Z module?

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::CryptoRngCore,
    Encoding, NonZero, Random, Uint,
};
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{
        CyclicGroupElement, GroupElement as _, KnownOrderGroupElement, MulByGenerator, Samplable,
    },
    traits::Reduce,
};

/// An element of the additive group of integers for an odd modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<const LIMBS: usize>(DynResidue<LIMBS>);

impl<const LIMBS: usize> Samplable<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        <GroupElement<LIMBS> as group::GroupElement<LIMBS>>::new(
            Uint::<LIMBS>::random(rng),
            public_parameters,
        )
    }
}

/// The public parameters of the additive group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub modulus: NonZero<Uint<LIMBS>>,
}

impl<const LIMBS: usize> PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub fn new(modulus: NonZero<Uint<LIMBS>>) -> Self {
        Self { modulus }
    }
}

impl<const LIMBS: usize> group::GroupElement<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Uint<LIMBS>;

    fn value(&self) -> Self::Value {
        self.0.retrieve()
    }

    type PublicParameters = PublicParameters<LIMBS>;

    fn public_parameters(&self) -> Self::PublicParameters {
        // Montgomery form only works for odd modulus, and this is assured in `DynResidue`
        // instantiation; therefore, the modulus of an instance can never be zero and it is safe to
        // `unwrap()`.
        PublicParameters {
            modulus: NonZero::new(*self.0.params().modulus()).unwrap(),
        }
    }

    fn new(
        value: Self::Value,
        public_parameters: &Self::PublicParameters,
    ) -> crate::group::Result<Self> {
        Ok(Self(DynResidue::<LIMBS>::new(
            &value,
            DynResidueParams::<LIMBS>::new(&public_parameters.modulus),
        )))
    }

    fn neutral(&self) -> Self {
        Self(DynResidue::<LIMBS>::zero(*self.0.params()))
    }

    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        let scalar = DynResidue::new(
            &scalar.reduce(&self.public_parameters().modulus),
            *self.0.params(),
        );

        Self(self.0 * scalar)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl<const LIMBS: usize> Neg for GroupElement<LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl<const LIMBS: usize> Add<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl<'r, const LIMBS: usize> Add<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl<const LIMBS: usize> Sub<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl<'r, const LIMBS: usize> Sub<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl<const LIMBS: usize> AddAssign<Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<'r, const LIMBS: usize> AddAssign<&'r Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<const LIMBS: usize> SubAssign<Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<'r, const LIMBS: usize> SubAssign<&'r Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<const LIMBS: usize> MulByGenerator<Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Uint<LIMBS>) -> Self {
        self.mul_by_generator(&scalar)
    }
}

impl<const LIMBS: usize> MulByGenerator<&Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: &Uint<LIMBS>) -> Self {
        // In the additive group, the generator is 1 and multiplication by it is simply returning
        // the same number modulu the order (which is taken care of in `DynResidue`.
        Self(DynResidue::new(scalar, *self.0.params()))
    }
}

impl<const LIMBS: usize> CyclicGroupElement<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn generator(&self) -> Self {
        Self(DynResidue::<LIMBS>::one(*self.0.params()))
    }
}

impl<const LIMBS: usize> Mul<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl<'r, const LIMBS: usize> Mul<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl<const LIMBS: usize> MulAssign<Self> for GroupElement<LIMBS> {
    fn mul_assign(&mut self, rhs: Self) {
        self.0.mul_assign(rhs.0)
    }
}

impl<'r, const LIMBS: usize> MulAssign<&'r Self> for GroupElement<LIMBS> {
    fn mul_assign(&mut self, rhs: &'r Self) {
        self.0.mul_assign(rhs.0)
    }
}

impl<'r, const LIMBS: usize> Mul<Self> for &'r GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Self) -> Self::Output {
        GroupElement(self.0.mul(rhs.0))
    }
}

impl<'r, const LIMBS: usize> Mul<&'r Self> for &'r GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        GroupElement(self.0.mul(rhs.0))
    }
}

impl<const LIMBS: usize> Mul<Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<'r, const LIMBS: usize> Mul<&'r Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<'r, const LIMBS: usize> Mul<Uint<LIMBS>> for &'r GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<'r, const LIMBS: usize> Mul<&'r Uint<LIMBS>> for &'r GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<const LIMBS: usize> MulAssign<Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_assign(&mut self, rhs: Uint<LIMBS>) {
        *self = self.scalar_mul(&rhs)
    }
}

impl<'r, const LIMBS: usize> MulAssign<&'r Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_assign(&mut self, rhs: &'r Uint<LIMBS>) {
        *self = self.scalar_mul(rhs)
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<const LIMBS: usize> KnownOrderGroupElement<LIMBS, Self> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn order_from_public_parameters(public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
        *public_parameters.modulus
    }
}
