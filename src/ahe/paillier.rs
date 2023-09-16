// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::CryptoRngCore,
    ConcatMixed, NonZero, Random, Uint, U128, U64,
};
use group::{
    multiplicative_group_of_integers_modulu_n,
    paillier::{CiphertextGroupElement, RandomnessGroupElement},
};
use tiresias::{DecryptionKey, EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::{
    group,
    group::{GroupElement, KnownOrderGroupElement},
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    StatisticalSecuritySizedNumber,
};

/// Emulate an additively homomorphic encryption with `PlaintextSpaceGroupElement` as the plaintext
/// group using the Paillier encryption scheme.
///
/// NOTICE: ensures circuit-privacy as long as MASK_LIMBS < LargeBiPrimeSizedNumber::LIMBS
impl<
        const MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        PlaintextSpaceGroupElement,
    >
    AdditivelyHomomorphicEncryptionKey<
        MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        PlaintextSpaceGroupElement,
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for EncryptionKey
where
    PlaintextSpaceGroupElement: KnownOrderGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        Value = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >,
    // In order to ensure circuit-privacy we assure that the mask is a number of the size of the
    // plaintext concated with the statistical security parameter contacted with a U64 (which is a
    // bound on the log of FUNCTION_DEGREE)
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<
        <StatisticalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput,
        MixedOutput = Uint<MASK_LIMBS>,
    >,
{
    fn encrypt_with_randomness(
        &self,
        plaintext: &PlaintextSpaceGroupElement,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // safe to `unwrap()` here, as encryption always returns a valid element in the
        // ciphertext group

        CiphertextGroupElement::new(
            self.encrypt_with_randomness(&(&plaintext.value()).into(), &randomness.into()),
            &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n2),
        )
        .unwrap()
    }

    fn encrypt(
        &self,
        plaintext: &PlaintextSpaceGroupElement,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        CiphertextGroupElement::new(
            self.encrypt(&(&plaintext.value()).into(), rng),
            &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n2),
        )
        .unwrap()
    }

    fn evaluate_linear_transformation_with_randomness<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: &PlaintextSpaceGroupElement,
        coefficients: &[PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: &[CiphertextGroupElement; FUNCTION_DEGREE],
        mask: &Uint<MASK_LIMBS>,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // Compute:
        //
        // $\ct = \Enc(pk,a_0 + \omega q; \eta) \bigoplus_{i=1}^\ell \left(  a_i \odot \ct_i
        // \right)$
        //
        // Which is the affine evaluation masked by an encryption of a masked
        // multiplication of the order $q$ using fresh randomness.
        //
        // This method ensures circuit privacy.

        // TODO: assure bound computations are correct.
        let plaintext_order = LargeBiPrimeSizedNumber::from(&free_variable.order());
        let free_variable = LargeBiPrimeSizedNumber::from(&free_variable.value());

        // \Enc(pk,a_0 + \omega q; \eta): An encryption of the free variable with fresh randomness
        // and a masked multiplication of the order $q$ (the free variable is added here instead of
        // in the affine evaluation below)
        let masking_encryption_of_free_variable = CiphertextGroupElement::new(
            self.encrypt_with_randomness(
                &free_variable.wrapping_add(
                    &LargeBiPrimeSizedNumber::from(mask).wrapping_mul(&plaintext_order),
                ),
                &randomness.into(),
            ),
            &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n2),
        )
        .unwrap();

        coefficients.iter().zip(ciphertexts.iter()).fold(
            masking_encryption_of_free_variable,
            |curr, (coefficient, ciphertext)| curr + ciphertext.scalar_mul(&coefficient.value()),
        )
    }

    fn evaluate_linear_transformation<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: &PlaintextSpaceGroupElement,
        coefficients: &[PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: &[CiphertextGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        let mask = Uint::<MASK_LIMBS>::random(rng);

        // In Paillier, it is actually statistically insignificant to randomly generate an invalid
        // element of the randomness group. We perform the check anyways to be 100% safe, since it
        // is a cheap check that will succeed on the first iteration with overwhalming odds.
        let randomness = loop {
            if let Ok(randomness) = RandomnessGroupElement::new(
                LargeBiPrimeSizedNumber::random(rng),
                &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n),
            ) {
                break randomness;
            }
        };

        self.evaluate_linear_transformation_with_randomness(
            free_variable,
            coefficients,
            ciphertexts,
            &mask,
            &randomness,
        )
    }
}

impl<
        const MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        PlaintextSpaceGroupElement,
    >
    AdditivelyHomomorphicEncryptionKey<
        MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        PlaintextSpaceGroupElement,
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for DecryptionKey
where
    PlaintextSpaceGroupElement: KnownOrderGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        Value = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >,
    // In order to ensure circuit-privacy we assure that the mask is a number of the size of the
    // plaintext concated with the statistical security parameter contacted with a U64 (which is a
    // bound on the log of FUNCTION_DEGREE)
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<
        <StatisticalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput,
        MixedOutput = Uint<MASK_LIMBS>,
    >,
{
    fn encrypt_with_randomness(
        &self,
        plaintext: &PlaintextSpaceGroupElement,
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
        plaintext: &PlaintextSpaceGroupElement,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        AdditivelyHomomorphicEncryptionKey::encrypt(&self.encryption_key, plaintext, rng)
    }

    fn evaluate_linear_transformation_with_randomness<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: &PlaintextSpaceGroupElement,
        coefficients: &[PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: &[CiphertextGroupElement; FUNCTION_DEGREE],
        mask: &Uint<MASK_LIMBS>,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation_with_randomness(
            &self.encryption_key,
            free_variable,
            coefficients,
            ciphertexts,
            mask,
            randomness,
        )
    }

    fn evaluate_linear_transformation<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: &PlaintextSpaceGroupElement,
        coefficients: &[PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: &[CiphertextGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation(
            &self.encryption_key,
            free_variable,
            coefficients,
            ciphertexts,
            rng,
        )
    }
}

impl<
        const MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        PlaintextSpaceGroupElement,
    >
    AdditivelyHomomorphicDecryptionKey<
        MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        PlaintextSpaceGroupElement,
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for DecryptionKey
where
    PlaintextSpaceGroupElement: KnownOrderGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        Value = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >,
    // In order to ensure circuit-privacy we assure that the mask is a number of the size of the
    // plaintext concated with the statistical security parameter contacted with a U64 (which is a
    // bound on the log of FUNCTION_DEGREE)
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<
        <StatisticalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput,
        MixedOutput = Uint<MASK_LIMBS>,
    >,
{
    fn decrypt(
        &self,
        ciphertext: &CiphertextGroupElement,
        plaintext_group_public_parameters: &PlaintextSpaceGroupElement::PublicParameters,
    ) -> PlaintextSpaceGroupElement {
        PlaintextSpaceGroupElement::new(
            self.decrypt(&ciphertext.into()),
            plaintext_group_public_parameters,
        )
        .unwrap()
    }
}
