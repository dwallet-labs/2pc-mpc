// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use group::paillier::{CiphertextGroupElement, MessageGroupElement, RandomnessGroupElement};
use tiresias::{DecryptionKey, EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use super::{Error, Result};
use crate::{group, AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey};

impl
    AdditivelyHomomorphicEncryptionKey<
        { LargeBiPrimeSizedNumber::LIMBS },
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for EncryptionKey
{
    fn encrypt_with_randomness(
        &self,
        plaintext: MessageGroupElement,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // self.encrypt_with_randomness(randomness.into())
        todo!()
    }

    fn encrypt(
        &self,
        plaintext: MessageGroupElement,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        todo!()
    }

    fn evaluate_linear_transformation_with_randomness<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
        const MASK_LIMBS: usize,
    >(
        &self,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        mask: Option<Uint<MASK_LIMBS>>,
        randomness: Option<RandomnessGroupElement>,
    ) -> Result<CiphertextGroupElement> {
        todo!()
    }

    fn evaluate_linear_transformation<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
        const MASK_LIMBS: usize,
    >(
        &self,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> Result<CiphertextGroupElement> {
        todo!()
    }
}

impl
    AdditivelyHomomorphicEncryptionKey<
        { LargeBiPrimeSizedNumber::LIMBS },
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for DecryptionKey
{
    fn encrypt_with_randomness(
        &self,
        plaintext: MessageGroupElement,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        AdditivelyHomomorphicEncryptionKey::encrypt_with_randomness(
            &self.encryption_key,
            plaintext,
            randomness,
        )
    }

    fn encrypt(
        &self,
        plaintext: MessageGroupElement,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        AdditivelyHomomorphicEncryptionKey::encrypt(&self.encryption_key, plaintext, rng)
    }

    fn evaluate_linear_transformation_with_randomness<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
        const MASK_LIMBS: usize,
    >(
        &self,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        mask: Option<Uint<MASK_LIMBS>>,
        randomness: Option<RandomnessGroupElement>,
    ) -> Result<CiphertextGroupElement> {
        AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation_with_randomness(
            &self.encryption_key,
            free_variable,
            coefficients,
            ciphertexts,
            mask,
            randomness,
        )
    }

    fn evaluate_linear_transformation<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
        const MASK_LIMBS: usize,
    >(
        &self,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> Result<CiphertextGroupElement> {
        AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation::<
            FUNCTION_DEGREE,
            COEFFICIENT_LIMBS,
            MASK_LIMBS,
        >(
            &self.encryption_key,
            free_variable,
            coefficients,
            ciphertexts,
            rng,
        )
    }
}

impl
    AdditivelyHomomorphicDecryptionKey<
        { LargeBiPrimeSizedNumber::LIMBS },
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for DecryptionKey
{
    fn decrypt(&self, ciphertext: &CiphertextGroupElement) -> MessageGroupElement {
        todo!()
    }
}
