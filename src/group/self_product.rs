// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{
    array,
    ops::{Add, AddAssign, BitAnd, Mul, Neg, Sub, SubAssign},
};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    group,
    group::{BoundedGroupElement, GroupElement as _, Samplable},
    helpers::flat_map_results,
};

/// An element of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct GroupElement<const N: usize, G>([G; N]);

impl<const N: usize, G: group::GroupElement> Samplable for GroupElement<N, G>
where
    G: Samplable,
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        let public_parameters = &public_parameters.public_parameters;

        if N < 2 {
            // there is no use of using this struct for a "product group" of less than two groups.
            return Err(group::Error::InvalidPublicParametersError);
        }

        Ok(Self(flat_map_results(array::from_fn(|_| {
            G::sample(rng, public_parameters)
        }))?))
    }
}

/// The public parameters of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const N: usize, PP> {
    pub public_parameters: PP,
    pub size: usize,
}

/// The value of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct Value<const N: usize, G: group::GroupElement>(
    #[serde(with = "crate::helpers::const_generic_array_serialization")] [G::Value; N],
);

impl<const N: usize, G: group::GroupElement> ConstantTimeEq for Value<N, G> {
    fn ct_eq(&self, other: &Self) -> Choice {
        // The arrays are of the same size so its safe to `zip` them.
        // Following that, we get an array of the pairs, and we assure they are all equal to each
        // other using `ct_eq` between the pairs and `bitand` between the results
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(Choice::from(1u8), |choice, (x, y)| {
                choice.bitand(x.ct_eq(y))
            })
    }
}

impl<const N: usize, G: group::GroupElement> group::GroupElement for GroupElement<N, G> {
    type Value = Value<N, G>;

    type PublicParameters = PublicParameters<N, G::PublicParameters>;

    fn public_parameters(&self) -> Self::PublicParameters {
        // in [`Self::new()`] we used the same public parameters for all elements, so we just pick
        // the first calling `unwrap()` is safe here because we assure to get at least two
        // values, i.e. this struct cannot be instantiated for `N == 0`.
        Self::PublicParameters {
            public_parameters: self.0.first().unwrap().public_parameters(),
            size: N,
        }
    }

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        let public_parameters = &public_parameters.public_parameters;

        if N < 2 {
            // there is no use of using this struct for a "product group" of less than two groups.
            return Err(group::Error::InvalidPublicParametersError);
        }

        Ok(Self(flat_map_results(
            value.0.map(|value| G::new(value, public_parameters)),
        )?))
    }

    fn neutral(&self) -> Self {
        Self(self.0.clone().map(|element| element.neutral()))
    }

    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        Self(self.0.clone().map(|element| element.scalar_mul(scalar)))
    }

    fn double(&self) -> Self {
        Self(self.0.clone().map(|element| element.double()))
    }
}

impl<const N: usize, G: group::GroupElement> From<GroupElement<N, G>>
    for group::Value<GroupElement<N, G>>
{
    fn from(value: GroupElement<N, G>) -> Self {
        Self(value.0.map(|element| element.into()))
    }
}

impl<const N: usize, G: group::GroupElement> From<GroupElement<N, G>>
    for group::PublicParameters<GroupElement<N, G>>
{
    fn from(value: GroupElement<N, G>) -> Self {
        value.public_parameters()
    }
}

impl<const N: usize, G: group::GroupElement> Neg for GroupElement<N, G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.clone().map(|element| element.neg()))
    }
}

impl<const N: usize, G: group::GroupElement> Add<Self> for GroupElement<N, G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl<'r, const N: usize, G: group::GroupElement> Add<&'r Self> for GroupElement<N, G> {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        let mut result: [G; N] = self.0.clone();

        for (i, element) in result.iter_mut().enumerate() {
            *element += &rhs.0[i];
        }

        Self(result)
    }
}

impl<const N: usize, G: group::GroupElement> Sub<Self> for GroupElement<N, G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl<'r, const N: usize, G: group::GroupElement> Sub<&'r Self> for GroupElement<N, G> {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        let mut result: [G; N] = self.0.clone();

        for (i, element) in result.iter_mut().enumerate() {
            *element -= &rhs.0[i];
        }

        Self(result)
    }
}

impl<const N: usize, G: group::GroupElement> AddAssign<Self> for GroupElement<N, G> {
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs
    }
}

impl<'r, const N: usize, G: group::GroupElement> AddAssign<&'r Self> for GroupElement<N, G> {
    fn add_assign(&mut self, rhs: &'r Self) {
        for i in 0..N {
            self.0[i] += &rhs.0[i];
        }
    }
}

impl<const N: usize, G: group::GroupElement> SubAssign<Self> for GroupElement<N, G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs
    }
}

impl<'r, const N: usize, G: group::GroupElement> SubAssign<&'r Self> for GroupElement<N, G> {
    fn sub_assign(&mut self, rhs: &'r Self) {
        for i in 0..N {
            self.0[i] -= &rhs.0[i];
        }
    }
}

impl<const LIMBS: usize, const N: usize, G: group::GroupElement> Mul<Uint<LIMBS>>
    for GroupElement<N, G>
{
    type Output = Self;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<'r, const LIMBS: usize, const N: usize, G: group::GroupElement> Mul<&'r Uint<LIMBS>>
    for GroupElement<N, G>
{
    type Output = Self;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<'r, const LIMBS: usize, const N: usize, G: group::GroupElement> Mul<Uint<LIMBS>>
    for &'r GroupElement<N, G>
{
    type Output = GroupElement<N, G>;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<'r, const LIMBS: usize, const N: usize, G: group::GroupElement> Mul<&'r Uint<LIMBS>>
    for &'r GroupElement<N, G>
{
    type Output = GroupElement<N, G>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<const N: usize, G: group::GroupElement> From<GroupElement<N, G>> for [G; N] {
    fn from(value: GroupElement<N, G>) -> Self {
        value.0
    }
}

impl<'r, const N: usize, G: group::GroupElement> From<&'r GroupElement<N, G>> for &'r [G; N] {
    fn from(value: &'r GroupElement<N, G>) -> Self {
        &value.0
    }
}

impl<const N: usize, G: group::GroupElement> From<[G; N]> for GroupElement<N, G> {
    fn from(value: [G; N]) -> Self {
        GroupElement::<N, G>(value)
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: BoundedGroupElement<SCALAR_LIMBS>>
    BoundedGroupElement<SCALAR_LIMBS> for GroupElement<N, G>
{
}
