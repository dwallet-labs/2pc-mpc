// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use std::ops::Mul;

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::CryptoRngCore,
    Encoding, Integer, Random, Uint,
};
use group::GroupElement as GroupElementTrait;
use serde::{Deserialize, Serialize};

use crate::{group, group::Samplable};

/// An element of the multiplicative group of integers modulo `n` $\mathbb{Z}_n^*$
/// [Multiplicative group of integers modulo n](https://en.wikipedia.org/wiki/Multiplicative_group_of_integers_modulo_n)
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct GroupElement<const LIMBS: usize>(DynResidue<LIMBS>);

impl<const LIMBS: usize> Samplable<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        // Classic rejection-sampling technique.
        loop {
            match Self::new(Uint::<LIMBS>::random(rng), public_parameters) {
                Err(group::Error::UnsupportedPublicParametersError) => {
                    return Err(group::Error::UnsupportedPublicParametersError);
                }
                Err(group::Error::InvalidPublicParametersError) => {
                    return Err(group::Error::InvalidPublicParametersError);
                }
                Err(group::Error::InvalidGroupElementError) => {
                    continue;
                }
                Ok(sampled_element) => {
                    return Ok(sampled_element);
                }
            }
        }
    }
}

/// The public parameters of the multiplicative group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub modulus: Uint<LIMBS>,
}

impl<const LIMBS: usize> PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub const fn new(modulus: Uint<LIMBS>) -> Self {
        Self { modulus }
    }
}

impl<const LIMBS: usize> GroupElementTrait<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Uint<LIMBS>;

    fn value(&self) -> Self::Value {
        self.0.retrieve()
    }

    type PublicParameters = PublicParameters<LIMBS>;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters {
            modulus: *self.0.params().modulus(),
        }
    }

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        // A valid modulus must be odd,
        // and bigger than 3: `0` and `1` are invalid, `2` is even
        if public_parameters.modulus.is_odd().unwrap_u8() == 0
            || public_parameters.modulus < Uint::<LIMBS>::from(3u8)
        {
            return Err(group::Error::UnsupportedPublicParametersError);
        }

        let element = DynResidue::<LIMBS>::new(
            &value,
            DynResidueParams::<LIMBS>::new(&public_parameters.modulus),
        );

        // `element` is valid if and only if it has an inverse
        match element.invert().1.into() {
            true => Ok(Self(element)),
            false => Err(group::Error::InvalidGroupElementError),
        }
    }

    fn neutral(&self) -> Self {
        GroupElement(DynResidue::<LIMBS>::one(*self.0.params()))
    }

    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        // This is inefficient, but in a hidden-order group, we can't do better than this as we
        // can't take the scalar modulus the order.
        Self(self.0.pow(scalar))
    }

    fn double(&self) -> Self {
        Self(self.0.square())
    }
}

impl<const LIMBS: usize> Neg for GroupElement<LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // In a group, every element has its inverse;
        // because `self` is an element within the group,
        // `invert()` is guaranteed to succeed and we
        // skip the check.
        Self(self.0.invert().0)
    }
}

impl<const LIMBS: usize> Neg for &GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn neg(self) -> Self::Output {
        GroupElement::<LIMBS>(self.0.invert().0)
    }
}

impl<const LIMBS: usize> Add<Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        // We are trying to adapt a multiplicative group to
        // the `GroupElement` trait which is in an additive notation -
        // so the abstract group operation "add" is mapped to the group operation (x \mod N) of the
        // multiplicative group of integers modulo N.
        Self(self.0 * rhs.0)
    }
}

impl<'r, const LIMBS: usize> Add<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<const LIMBS: usize> Sub<Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        // Substitution is actually division in the multiplicative group,
        // which is defined as multiplication by the inverse of `rhs` - which we get from `neg()`
        Self(self.0 * rhs.neg().0)
    }
}

impl<'r, const LIMBS: usize> Sub<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0 * rhs.neg().0)
    }
}

impl<const LIMBS: usize> AddAssign<Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl<'r, const LIMBS: usize> AddAssign<&'r Self> for GroupElement<LIMBS> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add_assign(&mut self, rhs: &'r Self) {
        *self = *self + rhs
    }
}

impl<const LIMBS: usize> SubAssign<Self> for GroupElement<LIMBS> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs
    }
}

impl<'r, const LIMBS: usize> SubAssign<&'r Self> for GroupElement<LIMBS> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub_assign(&mut self, rhs: &'r Self) {
        *self = *self - rhs
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<Uint<RHS_LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<&Uint<RHS_LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<Uint<RHS_LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<&Uint<RHS_LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
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
