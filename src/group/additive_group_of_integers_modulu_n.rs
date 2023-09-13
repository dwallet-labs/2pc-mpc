// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

// This should be called Z module?

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Encoding, NonZero, Uint,
};
use serde::{Deserialize, Serialize};

use crate::{
    group::{CyclicGroupElement, GroupElement, KnownOrderGroupElement, MulByGenerator},
    traits::Reduce,
};

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

impl<const LIMBS: usize> GroupElement<LIMBS> for DynResidue<LIMBS>
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
        // todo: this is always safe for any non-zero modulu right?
        Ok(DynResidue::<LIMBS>::new(
            &value,
            DynResidueParams::<LIMBS>::new(&public_parameters.modulus),
        ))
    }

    fn neutral(&self) -> Self {
        DynResidue::<LIMBS>::zero(*self.params())
    }

    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        // I can't do this elegantly right? montgomery only works for the same limbs?

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

impl<const LIMBS: usize> KnownOrderGroupElement<LIMBS, Self> for DynResidue<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn order(&self) -> Uint<LIMBS> {
        // todo: this is right?
        *self.public_parameters().modulus
    }
}
