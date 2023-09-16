// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{ConcatMixed, Uint, U64};
use group::{
    multiplicative_group_of_integers_modulu_n,
    paillier::{CiphertextGroupElement, RandomnessGroupElement},
};
use serde::{Deserialize, Serialize};
use tiresias::{DecryptionKey, EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::{
    group,
    group::{GroupElement, KnownOrderGroupElement},
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    StatisticalSecuritySizedNumber,
};

/// The Public Parameters of the Paillier Additively Homomorphic Encryption Scheme
#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    PlaintextSpaceGroupElement,
> {
    paillier_modulus: LargeBiPrimeSizedNumber,
    // TODO: better name? the modulus is N^2 but N is
    // good enough here.
    #[serde(skip_serializing)]
    _plaintext_group_element_choice: PhantomData<PlaintextSpaceGroupElement>,
}

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
    type PublicParameters =
        PublicParameters<MASK_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>;

    fn public_parameters(&self) -> Self::PublicParameters {
        Self::PublicParameters {
            paillier_modulus: self.n,
            _plaintext_group_element_choice: PhantomData,
        }
    }

    fn new(public_parameters: &Self::PublicParameters) -> Self {
        EncryptionKey::new(public_parameters.paillier_modulus)
    }

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
        EncryptionKey,
    > for DecryptionKey
where
    PlaintextSpaceGroupElement: KnownOrderGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        Value = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >,
    PlaintextSpaceGroupElement: From<LargeBiPrimeSizedNumber>,
    // In order to ensure circuit-privacy we assure that the mask is a number of the size of the
    // plaintext concated with the statistical security parameter contacted with a U64 (which is a
    // bound on the log of FUNCTION_DEGREE)
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<
        <StatisticalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput,
        MixedOutput = Uint<MASK_LIMBS>,
    >,
{
    fn decrypt(&self, ciphertext: &CiphertextGroupElement) -> PlaintextSpaceGroupElement {
        self.decrypt(&ciphertext.into()).into()
    }
}
