// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

use crypto_bigint::{Uint, U256};
use k256::{
    elliptic_curve,
    elliptic_curve::{group::prime::PrimeCurveAffine, Group},
    AffinePoint, ProjectivePoint,
};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    group,
    group::{
        secp256k1::{scalar::Scalar, CURVE_EQUATION_A, CURVE_EQUATION_B, MODULUS, ORDER},
        BoundedGroupElement, CyclicGroupElement, KnownOrderGroupElement, MulByGenerator, PrimeGroupElement,
    },
};

/// An element of the secp256k1 prime group.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct GroupElement(pub(super) ProjectivePoint);

/// The public parameters of the secp256k1 group.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    pub order: U256,
    pub modulus: U256,
    pub generator: Value,
    pub curve_equation_a: U256,
    pub curve_equation_b: U256,
}

impl Default for PublicParameters {
    fn default() -> Self {
        Self {
            name: "Secp256k1".to_string(),
            order: ORDER,
            modulus: MODULUS,
            generator: Value(AffinePoint::GENERATOR),
            curve_equation_a: CURVE_EQUATION_A,
            curve_equation_b: CURVE_EQUATION_B,
        }
    }
}

/// The value of the secp256k1 group used for serialization.
///
/// This is a `newtype` around `AffinePoint` used to control instantiation;
/// the only way to instantiate this type from outside this module is through deserialization,
/// which in turn will invoke `AffinePoint`'s deserialization which assures the point is on curve.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Serialize, Deserialize)]
pub struct Value(AffinePoint);

impl ConstantTimeEq for Value {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl group::GroupElement for GroupElement {
    type Value = Value;

    fn value(&self) -> Self::Value {
        // As this group element is valid, it's safe to instantiate a `Value`
        // from the valid affine representation.
        Value(self.0.to_affine())
    }

    type PublicParameters = PublicParameters;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters::default()
    }

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization, so
        // this is always safe.
        Ok(Self(value.0.to_curve()))
    }

    fn neutral(&self) -> Self {
        Self(ProjectivePoint::IDENTITY)
    }

    fn scalar_mul<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        Scalar::from(scalar) * self
    }

    fn double(&self) -> Self {
        Self(<ProjectivePoint as Group>::double(&self.0))
    }
}

impl From<GroupElement> for group::Value<GroupElement> {
    fn from(value: GroupElement) -> Self {
        // As this group element is valid, it's safe to instantiate a `Value`
        // from the valid affine representation.
        Self(value.0.to_affine())
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
        Self(ProjectivePoint::GENERATOR)
    }
}

impl BoundedGroupElement<{ U256::LIMBS }> for GroupElement {}

impl KnownOrderGroupElement<{ U256::LIMBS }> for GroupElement {
    type Scalar = Scalar;

    fn order(&self) -> Uint<{ U256::LIMBS }> {
        ORDER
    }

    fn order_from_public_parameters(_public_parameters: &Self::PublicParameters) -> Uint<{ U256::LIMBS }> {
        ORDER
    }
}

impl MulByGenerator<Scalar> for GroupElement {
    fn mul_by_generator(&self, scalar: Scalar) -> Self {
        GroupElement(<ProjectivePoint as elliptic_curve::ops::MulByGenerator>::mul_by_generator(
            &scalar.0,
        ))
    }
}

impl<'r> MulByGenerator<&'r Scalar> for GroupElement {
    fn mul_by_generator(&self, scalar: &'r Scalar) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl PrimeGroupElement<{ U256::LIMBS }> for GroupElement {}
