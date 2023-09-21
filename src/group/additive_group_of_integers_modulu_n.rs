// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

// This should be called Z module?

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::CryptoRngCore,
    Encoding, NonZero, Random, Uint, Wrapping,
};
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{
        CyclicGroupElement, GroupElement as _, KnownOrderGroupElement, MulByGenerator, Samplable,
    },
    traits::Reduce,
};

// Crypto-bigint has two structures we can work with for modular arithmetics;
// 1. DynResidue - uses Montgomery and works for odd moduli only
// 2. Wrapping<Uint<>> - works for moduli which is a multiple of the LIMB size 2^64, and is much
//    more efficient.
//
// For groups like the Paillier plaintext space, 1 is more appropriate.
// For groups that should behave like the integers group $Z$ but bounded by some upper bound, 2. is
// more appropriate.

/// An element of the additive group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$
pub type GroupElement<const LIMBS: usize> = DynResidue<LIMBS>;

impl<const LIMBS: usize> Samplable<LIMBS> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        <DynResidue<LIMBS> as group::GroupElement<LIMBS>>::new(
            Uint::<LIMBS>::random(rng),
            public_parameters,
        )
    }
}

impl<const LIMBS: usize> Samplable<LIMBS> for Wrapping<Uint<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        _public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(Wrapping(Uint::<LIMBS>::random(rng)))
    }
}

/// The public parameters of the additive group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    modulus: NonZero<Uint<LIMBS>>,
}

impl<const LIMBS: usize> PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub fn new(modulus: NonZero<Uint<LIMBS>>) -> Self {
        Self { modulus }
    }
}

impl<const LIMBS: usize> group::GroupElement<LIMBS> for Wrapping<Uint<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Uint<LIMBS>;

    fn value(&self) -> Self::Value {
        self.0
    }

    type PublicParameters = ();

    fn public_parameters(&self) -> Self::PublicParameters {}

    fn new(
        value: Self::Value,
        _public_parameters: &Self::PublicParameters,
    ) -> crate::group::Result<Self> {
        Ok(Wrapping(value))
    }

    fn neutral(&self) -> Self {
        Wrapping(Uint::<LIMBS>::ZERO)
    }

    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        Wrapping(self.0.wrapping_mul(scalar))
    }

    fn double(&self) -> Self {
        self + self
    }
}

impl<const LIMBS: usize> group::GroupElement<LIMBS> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Uint<LIMBS>;

    fn value(&self) -> Self::Value {
        self.retrieve()
    }

    type PublicParameters = PublicParameters<LIMBS>;

    fn public_parameters(&self) -> Self::PublicParameters {
        // Montgomery form only works for odd modulus, and this is assured in `DynResidue`
        // instantiation; therefore, the modulus of an instance can never be zero and it is safe to
        // `unwrap()`.
        PublicParameters {
            modulus: NonZero::new(*self.params().modulus()).unwrap(),
        }
    }

    fn new(
        value: Self::Value,
        public_parameters: &Self::PublicParameters,
    ) -> crate::group::Result<Self> {
        Ok(DynResidue::<LIMBS>::new(
            &value,
            DynResidueParams::<LIMBS>::new(&public_parameters.modulus),
        ))
    }

    fn neutral(&self) -> Self {
        DynResidue::<LIMBS>::zero(*self.params())
    }

    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        let scalar = DynResidue::new(
            &scalar.reduce(&self.public_parameters().modulus),
            *self.params(),
        );

        self * scalar
    }

    fn double(&self) -> Self {
        self + self
    }
}

impl<const LIMBS: usize> MulByGenerator<Uint<LIMBS>> for Wrapping<Uint<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Uint<LIMBS>) -> Self {
        self.mul_by_generator(&scalar)
    }
}

impl<const LIMBS: usize> MulByGenerator<&Uint<LIMBS>> for Wrapping<Uint<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: &Uint<LIMBS>) -> Self {
        Wrapping(scalar.into())
    }
}

impl<const LIMBS: usize> CyclicGroupElement<LIMBS> for Wrapping<Uint<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    fn generator(&self) -> Self {
        Wrapping(Uint::<LIMBS>::ONE)
    }
}

impl<const LIMBS: usize> MulByGenerator<Uint<LIMBS>> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Uint<LIMBS>) -> Self {
        self.mul_by_generator(&scalar)
    }
}

impl<const LIMBS: usize> MulByGenerator<&Uint<LIMBS>> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: &Uint<LIMBS>) -> Self {
        // In the additive group, the generator is 1 and multiplication by it is simply returning
        // the same number modulu the order (which is taken care of in `DynResidue`.
        DynResidue::new(scalar, *self.params())
    }
}

impl<const LIMBS: usize> CyclicGroupElement<LIMBS> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn generator(&self) -> Self {
        DynResidue::<LIMBS>::one(*self.params())
    }
}
