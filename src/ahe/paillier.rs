// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, CheckedAdd, Uint};
use tiresias::{DecryptionKey, EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::{
    ahe::AdditivelyHomomorphicEncryption,
    group::{
        multiplicative_group_of_integers_modulu_n::PublicParameters,
        paillier::{CiphertextGroupElement, RandomnessGroupElement},
        GroupElement,
    },
};

#[derive(PartialEq, Clone)]
pub struct Paillier {}

impl
    AdditivelyHomomorphicEncryption<
        { LargeBiPrimeSizedNumber::LIMBS },
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for Paillier
{
    type EncryptionKey = EncryptionKey;
    type DecryptionKey = DecryptionKey;

    fn encrypt_with_randomness(
        encryption_key: &EncryptionKey,
        plaintext: LargeBiPrimeSizedNumber,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // TODO: we could optimize this process if we work with the group elements in tiresias
        // directly, avoiding needless montomgery reductions. This is probably insignificant though.

        // `new()` is bound to succeed as Paillier encryption is an homomoprhism - as long as the
        // message (which is taken modulu `N` in `encryption_key.encrypt_with_randomness`) and
        // randmoness (which is of type `GroupElement` which assures validity) are valid group
        // elements, so it's safe to `unwrap()` here
        CiphertextGroupElement::new(
            encryption_key.encrypt_with_randomness(&plaintext, &randomness.into()),
            &PublicParameters::new(encryption_key.n2),
        )
        .unwrap()
    }

    fn encrypt(
        encryption_key: &EncryptionKey,
        plaintext: LargeBiPrimeSizedNumber,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        // See comment in `encrypt_with_randomness`
        CiphertextGroupElement::new(
            encryption_key.encrypt(&plaintext, rng),
            &PublicParameters::new(encryption_key.n2),
        )
        .unwrap()
    }

    fn decrypt(
        decryption_key: &DecryptionKey,
        ciphertext: &CiphertextGroupElement,
    ) -> LargeBiPrimeSizedNumber {
        decryption_key.decrypt(&ciphertext.into())
    }

    fn evaluate_linear_transformation_with_randomness<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
    >(
        encryption_key: &EncryptionKey,
        range_upper_bound: Uint<COEFFICIENT_LIMBS>,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        mask: LargeBiPrimeSizedNumber,
        randomness: &RandomnessGroupElement,
    ) -> super::Result<CiphertextGroupElement> {
        // TODO: range checks: e.g. check that COEFFICIENT_LIMBS < LargeBiPrimeSizedNumber::LIMBS

        let bla = mask.checked_mul(&range_upper_bound);
        Ok(Self::encrypt_with_randomness(
            free_variable.wrapped_add(&mask.wrapped_mul(&range_upper_bound)),
            randomness,
        ))
        // todo
    }

    fn evaluate_linear_transformation<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
    >(
        encryption_key: &EncryptionKey,
        range_upper_bound: Uint<COEFFICIENT_LIMBS>,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> super::Result<CiphertextGroupElement> {
        // TODO: how can I sample the mask? I would need something like a concat mixed of the
        // Uint<FUNCTION_DEGREE/LIMBS> or a bound, and ConcatMixed of that with the statistical
        // parameter and COEFFICIENT_LIMBS

        // TODO: also, this is not that generic at all; COEFFICIENT_LIMBS must be small enough to
        // fit and also not modulate and such; perhaps we should just implement this for U256?

        // let modulation_mask = ;
        todo!()
    }
}
