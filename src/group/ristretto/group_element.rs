// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

use crypto_bigint::{Uint, U256};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto, ristretto::RistrettoPoint, traits::Identity,
};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    group,
    group::{
        ristretto::{scalar::Scalar, CURVE_EQUATION_A, CURVE_EQUATION_B, MODULUS, ORDER},
        BoundedGroupElement, CyclicGroupElement, KnownOrderGroupElement, MulByGenerator,
        PrimeGroupElement,
    },
};

/// An element of the ristretto prime group.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct GroupElement(pub(super) ristretto::RistrettoPoint);

/// The public parameters of the ristretto group.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    curve_type: String,
    pub order: U256,
    pub modulus: U256,
    pub generator: GroupElement,
    pub curve_equation_a: U256,
    pub curve_equation_b: U256,
}

impl Default for PublicParameters {
    fn default() -> Self {
        Self {
            name: "Ristretto".to_string(),
            curve_type: "Montgomery".to_string(),
            order: ORDER,
            modulus: MODULUS,
            generator: GroupElement(RISTRETTO_BASEPOINT_POINT),
            curve_equation_a: CURVE_EQUATION_A,
            curve_equation_b: CURVE_EQUATION_B,
        }
    }
}

impl ConstantTimeEq for GroupElement {
    fn ct_eq(&self, _other: &Self) -> Choice {
        todo!()
    }
}

impl group::GroupElement for GroupElement {
    type Value = Self;

    fn value(&self) -> Self::Value {
        *self
    }

    type PublicParameters = PublicParameters;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters::default()
    }

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        // `RistrettoPoint` assures deserialized values are on curve,
        // and `Self` can only be instantiated through deserialization, so
        // this is always safe.
        Ok(value)
    }

    fn neutral(&self) -> Self {
        Self(RistrettoPoint::identity())
    }

    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        Scalar::from(scalar) * self
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl From<GroupElement> for group::PublicParameters<GroupElement> {
    fn from(_value: GroupElement) -> Self {
        Self::default()
    }
}

impl Neg for GroupElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Add<Self> for GroupElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl<'r> Add<&'r Self> for GroupElement {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl Sub<Self> for GroupElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl<'r> Sub<&'r Self> for GroupElement {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl AddAssign<Self> for GroupElement {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<'r> AddAssign<&'r Self> for GroupElement {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(rhs.0)
    }
}

impl SubAssign<Self> for GroupElement {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<'r> SubAssign<&'r Self> for GroupElement {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl MulByGenerator<U256> for GroupElement {
    fn mul_by_generator(&self, scalar: U256) -> Self {
        self.mul_by_generator(Scalar::from(scalar))
    }
}

impl<'r> MulByGenerator<&'r U256> for GroupElement {
    fn mul_by_generator(&self, scalar: &'r U256) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl CyclicGroupElement for GroupElement {
    fn generator(&self) -> Self {
        Self(RISTRETTO_BASEPOINT_POINT)
    }
}

impl BoundedGroupElement<{ U256::LIMBS }> for GroupElement {}

impl KnownOrderGroupElement<{ U256::LIMBS }> for GroupElement {
    type Scalar = Scalar;

    fn order(&self) -> Uint<{ U256::LIMBS }> {
        ORDER
    }

    fn order_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Uint<{ U256::LIMBS }> {
        ORDER
    }
}

impl MulByGenerator<Scalar> for GroupElement {
    fn mul_by_generator(&self, scalar: Scalar) -> Self {
        scalar * self
    }
}

impl<'r> MulByGenerator<&'r Scalar> for GroupElement {
    fn mul_by_generator(&self, scalar: &'r Scalar) -> Self {
        scalar * self
    }
}

impl PrimeGroupElement<{ U256::LIMBS }> for GroupElement {}
