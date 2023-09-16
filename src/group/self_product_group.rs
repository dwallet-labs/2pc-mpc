// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{
    array,
    ops::{Add, AddAssign, BitAnd, Mul, MulAssign, Neg, Sub, SubAssign},
};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    group, group::GroupElement as GroupElementTrait, helpers::const_generic_array_serialization,
    traits::Samplable,
};

/// An element of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<const N: usize, const SCALAR_LIMBS: usize, G>([G; N]);

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> Samplable
    for GroupElement<N, SCALAR_LIMBS, G>
where
    G: Samplable,
{
    fn sample(rng: &mut impl CryptoRngCore) -> Self {
        Self(array::from_fn(|_| G::sample(rng)))
    }
}

/// The public parameters of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicParameters<
    const N: usize,
    const SCALAR_LIMBS: usize,
    G: GroupElementTrait<SCALAR_LIMBS>,
> {
    pub(crate) public_parameters: G::PublicParameters,
    size: usize,
}

/// The value of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct Value<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>(
    #[serde(with = "const_generic_array_serialization")] [G::Value; N],
);

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> ConstantTimeEq
    for Value<N, SCALAR_LIMBS, G>
{
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

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>
    GroupElementTrait<SCALAR_LIMBS> for GroupElement<N, SCALAR_LIMBS, G>
{
    type Value = Value<N, SCALAR_LIMBS, G>;

    fn value(&self) -> Self::Value {
        Value(self.0.clone().map(|element| element.value()))
    }

    type PublicParameters = PublicParameters<N, SCALAR_LIMBS, G>;

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

        // Any one of these values could be invalid and thus return an error upon instantiation
        // First, get all the `Result<>`s from `new()`
        let results = value.0.map(|value| G::new(value, public_parameters));

        // Then return the first error you encounter, or create a valid group element and return it
        if let Some(Err(err)) = results.iter().find(|res| res.is_err()) {
            return Err(err.clone());
        }
        Ok(Self(results.map(|res| res.unwrap())))
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

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> Neg
    for GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.clone().map(|element| element.neg()))
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> Add<Self>
    for GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl<'r, const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>
    Add<&'r Self> for GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        let mut result: [G; N] = self.0.clone();

        for (i, element) in result.iter_mut().enumerate() {
            *element += &rhs.0[i];
        }

        Self(result)
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> Sub<Self>
    for GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl<'r, const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>
    Sub<&'r Self> for GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        let mut result: [G; N] = self.0.clone();

        for (i, element) in result.iter_mut().enumerate() {
            *element -= &rhs.0[i];
        }

        Self(result)
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> AddAssign<Self>
    for GroupElement<N, SCALAR_LIMBS, G>
{
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs
    }
}

impl<'r, const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>
    AddAssign<&'r Self> for GroupElement<N, SCALAR_LIMBS, G>
{
    fn add_assign(&mut self, rhs: &'r Self) {
        for i in 0..N {
            self.0[i] += &rhs.0[i];
        }
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> SubAssign<Self>
    for GroupElement<N, SCALAR_LIMBS, G>
{
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs
    }
}

impl<'r, const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>
    SubAssign<&'r Self> for GroupElement<N, SCALAR_LIMBS, G>
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        for i in 0..N {
            self.0[i] -= &rhs.0[i];
        }
    }
}

impl<
        const LIMBS: usize,
        const N: usize,
        const SCALAR_LIMBS: usize,
        G: GroupElementTrait<SCALAR_LIMBS>,
    > Mul<Uint<LIMBS>> for GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = Self;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const N: usize,
        const SCALAR_LIMBS: usize,
        G: GroupElementTrait<SCALAR_LIMBS>,
    > Mul<&'r Uint<LIMBS>> for GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = Self;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const N: usize,
        const SCALAR_LIMBS: usize,
        G: GroupElementTrait<SCALAR_LIMBS>,
    > Mul<Uint<LIMBS>> for &'r GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = GroupElement<N, SCALAR_LIMBS, G>;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const N: usize,
        const SCALAR_LIMBS: usize,
        G: GroupElementTrait<SCALAR_LIMBS>,
    > Mul<&'r Uint<LIMBS>> for &'r GroupElement<N, SCALAR_LIMBS, G>
{
    type Output = GroupElement<N, SCALAR_LIMBS, G>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

impl<
        const LIMBS: usize,
        const N: usize,
        const SCALAR_LIMBS: usize,
        G: GroupElementTrait<SCALAR_LIMBS>,
    > MulAssign<Uint<LIMBS>> for GroupElement<N, SCALAR_LIMBS, G>
{
    fn mul_assign(&mut self, rhs: Uint<LIMBS>) {
        *self = self.scalar_mul(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        const N: usize,
        const SCALAR_LIMBS: usize,
        G: GroupElementTrait<SCALAR_LIMBS>,
    > MulAssign<&'r Uint<LIMBS>> for GroupElement<N, SCALAR_LIMBS, G>
{
    fn mul_assign(&mut self, rhs: &'r Uint<LIMBS>) {
        *self = self.scalar_mul(rhs)
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>
    From<GroupElement<N, SCALAR_LIMBS, G>> for [G; N]
{
    fn from(value: GroupElement<N, SCALAR_LIMBS, G>) -> Self {
        value.0
    }
}

impl<'r, const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>>
    From<&'r GroupElement<N, SCALAR_LIMBS, G>> for &'r [G; N]
{
    fn from(value: &'r GroupElement<N, SCALAR_LIMBS, G>) -> Self {
        &value.0
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: GroupElementTrait<SCALAR_LIMBS>> From<[G; N]>
    for GroupElement<N, SCALAR_LIMBS, G>
{
    fn from(value: [G; N]) -> Self {
        GroupElement::<N, SCALAR_LIMBS, G>(value)
    }
}
