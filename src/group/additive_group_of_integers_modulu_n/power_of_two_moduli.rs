use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Random, Uint, Wrapping, Zero};
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{
        sample_uint_within, BoundedGroupElement, CyclicGroupElement, GroupElement as _,
        MulByGenerator, Samplable, SamplableWithin,
    },
};

/// An element of the additive group of integers for a power-of-two modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, PartialOrd, Eq, Clone, Debug, Copy)]
pub struct GroupElement<const LIMBS: usize>(Wrapping<Uint<LIMBS>>);

impl<const LIMBS: usize> Samplable for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> group::Result<Self> {
        Self::new(Uint::<LIMBS>::random(rng), public_parameters)
    }
}

impl<const LIMBS: usize> SamplableWithin for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample_within(
        subrange: (&Self, &Self),
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> group::Result<Self> {
        let (lower_bound, upper_bound) = subrange;
        let lower_bound = Uint::<LIMBS>::from(lower_bound);
        let upper_bound = Uint::<LIMBS>::from(upper_bound);

        Self::new(
            sample_uint_within(lower_bound, upper_bound, rng)?,
            public_parameters,
        )
    }

    fn lower_bound(public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        Ok(Uint::<LIMBS>::ZERO.into())
    }

    fn upper_bound(public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        Ok(Uint::<LIMBS>::MAX.into())
    }
}

impl<const LIMBS: usize> group::GroupElement for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Uint<LIMBS>;
    type PublicParameters = ();
    fn public_parameters(&self) -> Self::PublicParameters {
        ()
    }
    fn new(
        value: Self::Value,
        _public_parameters: &Self::PublicParameters,
    ) -> crate::group::Result<Self> {
        Ok(Self(Wrapping(value)))
    }
    fn neutral(&self) -> Self {
        Self(Wrapping::<Uint<LIMBS>>::ZERO)
    }
    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        Self(Wrapping(self.0 .0.wrapping_mul(scalar)))
    }
    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for group::PublicParameters<GroupElement<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.public_parameters()
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
        // the same number modulu the order.
        scalar.into()
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

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.0 .0
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.0 .0
    }
}

impl<const LIMBS: usize> From<Uint<LIMBS>> for GroupElement<LIMBS> {
    fn from(value: Uint<LIMBS>) -> Self {
        Self(Wrapping((&value).into()))
    }
}

impl<'r, const LIMBS: usize> From<&'r Uint<LIMBS>> for GroupElement<LIMBS> {
    fn from(value: &'r Uint<LIMBS>) -> Self {
        Self(Wrapping(value.into()))
    }
}

impl<const LIMBS: usize> BoundedGroupElement<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn scalar_lower_bound_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Uint<LIMBS> {
        Uint::<LIMBS>::MAX
    }
}

impl<const LIMBS: usize> CyclicGroupElement for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn generator(&self) -> Self {
        Self(Wrapping(Uint::<LIMBS>::ONE))
    }

    fn generator_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Uint::<LIMBS>::ONE
    }
}
