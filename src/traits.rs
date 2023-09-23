// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{NonZero, Uint};

pub(crate) trait Reduce<const MODULUS_LIMBS: usize> {
    /// Reduces `self` by `modulus`.

    fn reduce(&self, modulus: &NonZero<Uint<MODULUS_LIMBS>>) -> Uint<MODULUS_LIMBS>;
}

impl<const LIMBS: usize, const MODULUS_LIMBS: usize> Reduce<MODULUS_LIMBS> for Uint<LIMBS> {
    fn reduce(&self, modulus: &NonZero<Uint<MODULUS_LIMBS>>) -> Uint<MODULUS_LIMBS> {
        // If the `modulus` is of a type bigger than `self`, it's safe to take it.
        // Otherwise, we must first `resize()` - enlarge - the modulus to be able to take it.
        // Note that resizing is not always safe, as if the modulus is bigger than `self`, it could
        // result in loss of information, so we must perform this check.
        if LIMBS <= MODULUS_LIMBS {
            let value: Uint<MODULUS_LIMBS> = self.resize();

            return value % modulus;
        }

        let modulus: NonZero<Uint<LIMBS>> = NonZero::new(modulus.resize()).unwrap();
        let reduced_value = self % modulus;

        // Now it is safe to resize the result as it has already gone modulation and thus is already
        // of that size.
        reduced_value.resize()
    }
}
