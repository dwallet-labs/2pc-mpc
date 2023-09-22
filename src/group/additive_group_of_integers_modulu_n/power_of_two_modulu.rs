use crypto_bigint::{rand_core::CryptoRngCore, Encoding, NonZero, Random, Uint, Wrapping, Zero};
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{CyclicGroupElement, KnownOrderGroupElement, MulByGenerator, Samplable},
    traits::Reduce,
};

impl<const LIMBS: usize> Samplable<LIMBS> for Wrapping<Uint<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        rng: &mut impl CryptoRngCore,
        _public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(Self::random(rng))
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
        Self::ZERO
    }

    fn scalar_mul<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        Wrapping(self.0.wrapping_mul(scalar))
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
