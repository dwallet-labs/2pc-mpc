// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::process::Output;

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::CryptoRngCore,
    ConcatMixed, NonZero, Uint, U128, U64,
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
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: From<PlaintextSpaceGroupElement>,
    // to ensure circuit-privacy:
    // First, assure that the statistical security (currently configured to U64, code would break
    // and require changes if it will change) contacted with a U64 which is a bound on the log of
    // FUNCTION_DEGREE
    StatisticalSecuritySizedNumber: ConcatMixed<U64, MixedOutput = U128>,
    // Second, assure that MASK_LIMBS is PLAINTEXT_SPACE_SCALAR_LIMBS +
    // StatisticalSecuritySizedNumber + U64 = PLAINTEXT_SPACE_SCALAR_LIMBS + U128
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<U128, MixedOutput = Uint<MASK_LIMBS>>,
{
    fn encrypt_with_randomness(
        &self,
        plaintext: PlaintextSpaceGroupElement,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // safe to `unwrap()` here, as encryption always returns a valid element in the
        // ciphertext group

        CiphertextGroupElement::new(
            self.encrypt_with_randomness(
                &(&Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(plaintext)).into(),
                &randomness.into(),
            ),
            &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n2),
        )
        .unwrap()
    }

    fn encrypt(
        &self,
        plaintext: PlaintextSpaceGroupElement,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        CiphertextGroupElement::new(
            self.encrypt(
                &(&Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(plaintext)).into(),
                rng,
            ),
            &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n2),
        )
        .unwrap()
    }

    fn evaluate_linear_transformation_with_randomness<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: PlaintextSpaceGroupElement,
        coefficients: [PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        mask: Uint<MASK_LIMBS>,
        randomness: RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        let masking_encryption_of_free_variable =
            AdditivelyHomomorphicEncryptionKey::encrypt_with_randomness(
                self,
                free_variable,
                &randomness,
            );

        todo!()
    }

    fn evaluate_linear_transformation<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: PlaintextSpaceGroupElement,
        coefficients: [PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextGroupElement {
        todo!()
    }
}

// impl
//     AdditivelyHomomorphicEncryptionKey<
//         { LargeBiPrimeSizedNumber::LIMBS },
//         { LargeBiPrimeSizedNumber::LIMBS },
//         { PaillierModulusSizedNumber::LIMBS },
//         RandomnessGroupElement,
//         CiphertextGroupElement,
//     > for EncryptionKey
// {
//     fn encrypt_with_randomness(
//         &self,
//         plaintext: MessageGroupElement,
//         randomness: &RandomnessGroupElement,
//     ) -> CiphertextGroupElement { // TODO: this can be optimized by returning DynResidue from
//       tiresias function
//
//         // safe to `unwrap()` here, as encryption always returns a valid element in the
//         // ciphertext group
//         CiphertextGroupElement::new(
//             self.encrypt_with_randomness(&plaintext.retrieve(), &randomness.into()),
//             &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n2),
//         )
//         .unwrap()
//     }
//
//     fn encrypt(
//         &self,
//         plaintext: MessageGroupElement,
//         rng: &mut impl CryptoRngCore,
//     ) -> CiphertextGroupElement { // safe to `unwrap()` here, as encryption always returns a
//       valid element in the // ciphertext group CiphertextGroupElement::new(
//       self.encrypt(&plaintext.retrieve(), rng),
//       &multiplicative_group_of_integers_modulu_n::PublicParameters::new(self.n2), ) .unwrap()
//     }
//
//     fn evaluate_linear_transformation_with_randomness<
//         const FUNCTION_DEGREE: usize,
//         const MASK_LIMBS: usize,
//     >(
//         &self,
//         free_variable: PlaintextSpaceGroupElement,
//         coefficients: [PlaintextSpaceGroupElement; FUNCTION_DEGREE],
//         ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
//         mask: Uint<MASK_LIMBS>,
//         randomness: RandomnessGroupElement,
//     ) -> Result<CiphertextGroupElement> { // The check (Dolev): MASK_LIMBS = LOG_FUNCTION_DEGREE
//       + LOG_ORDER (rounded up) + // STATISTICAL_SECURITY_PARAMETER then this needs to be sampled
//       uniformly
//
//         // also check that MASK_LIMBS < LargeBiPrimeSizedNumber::LIMBS
//         // maybe check that in new, or statically
//
//         // do wrapped mul, add but with U2048.
//
//         // if MASK_LIMBS >= LargeBiPrimeSizedNumber::LIMBS {
//         //     return Err(Error::);
//         // }
//         //
//         // todo!()
//     }
//
//     fn evaluate_linear_transformation<const FUNCTION_DEGREE: usize, const MASK_LIMBS: usize>(
//         &self,
//         free_variable: PlaintextSpaceGroupElement,
//         coefficients: [Uint<PLAINTEXT_LIMBS>; FUNCTION_DEGREE],
//         ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
//         rng: &mut impl CryptoRngCore,
//     ) -> Result<CiphertextGroupElement> { todo!()
//     }
// }
//
// impl
//     AdditivelyHomomorphicEncryptionKey<
//         { LargeBiPrimeSizedNumber::LIMBS },
//         { LargeBiPrimeSizedNumber::LIMBS },
//         { PaillierModulusSizedNumber::LIMBS },
//         RandomnessGroupElement,
//         CiphertextGroupElement,
//     > for DecryptionKey
// {
//     fn encrypt_with_randomness(
//         &self,
//         plaintext: MessageGroupElement,
//         randomness: &RandomnessGroupElement,
//     ) -> CiphertextGroupElement { AdditivelyHomomorphicEncryptionKey::encrypt_with_randomness(
//       &self.encryption_key, plaintext, randomness, )
//     }
//
//     fn encrypt(
//         &self,
//         plaintext: MessageGroupElement,
//         rng: &mut impl CryptoRngCore,
//     ) -> CiphertextGroupElement {
//       AdditivelyHomomorphicEncryptionKey::encrypt(&self.encryption_key, plaintext, rng)
//     }
//
//     fn evaluate_linear_transformation_with_randomness<
//         const FUNCTION_DEGREE: usize,
//         const COEFFICIENT_LIMBS: usize,
//         const MASK_LIMBS: usize,
//     >(
//         &self,
//         free_variable: Uint<COEFFICIENT_LIMBS>,
//         coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
//         ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
//         mask: Uint<MASK_LIMBS>,
//         randomness: RandomnessGroupElement,
//     ) -> Result<CiphertextGroupElement> {
//       AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation_with_randomness(
//       &self.encryption_key, free_variable, coefficients, ciphertexts, mask, randomness, )
//     }
//
//     fn evaluate_linear_transformation<
//         const FUNCTION_DEGREE: usize,
//         const COEFFICIENT_LIMBS: usize,
//         const MASK_LIMBS: usize,
//     >(
//         &self,
//         free_variable: Uint<COEFFICIENT_LIMBS>,
//         coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
//         ciphertexts: [CiphertextGroupElement; FUNCTION_DEGREE],
//         rng: &mut impl CryptoRngCore,
//     ) -> Result<CiphertextGroupElement> {
//       AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation::< FUNCTION_DEGREE,
//       COEFFICIENT_LIMBS, MASK_LIMBS, >( &self.encryption_key, free_variable, coefficients,
//       ciphertexts, rng, )
//     }
// }
//
// impl
//     AdditivelyHomomorphicDecryptionKey<
//         { LargeBiPrimeSizedNumber::LIMBS },
//         { LargeBiPrimeSizedNumber::LIMBS },
//         { PaillierModulusSizedNumber::LIMBS },
//         RandomnessGroupElement,
//         CiphertextGroupElement,
//     > for DecryptionKey
// {
//     fn decrypt(&self, ciphertext: &CiphertextGroupElement) -> MessageGroupElement {
//         // TODO: with all this functions, do I know they are correct?
//         // Yes, the ciphertext group element is indeed valid, but who says its connected to the
// `n`         // of `self`? or that the decryption key is valid?
//         DynResidue::new(
//             &self.decrypt(&ciphertext.into()),
//             DynResidueParams::new(&self.encryption_key.n),
//         )
//     }
// }
