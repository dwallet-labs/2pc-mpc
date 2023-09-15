// // Author: dWallet Labs, LTD.
// // SPDX-License-Identifier: Apache-2.0
//
// use crypto_bigint::{
//     modular::runtime_mod::{DynResidue, DynResidueParams},
//     rand_core::CryptoRngCore,
//     NonZero, Uint,
// };
// use group::{
//     additive_group_of_integers_modulu_n, multiplicative_group_of_integers_modulu_n,
//     paillier::{CiphertextGroupElement, MessageGroupElement, RandomnessGroupElement},
// };
// use tiresias::{DecryptionKey, EncryptionKey, LargeBiPrimeSizedNumber,
// PaillierModulusSizedNumber};
//
// use super::{Error, Result};
// use crate::{
//     group, group::GroupElement, AdditivelyHomomorphicDecryptionKey,
//     AdditivelyHomomorphicEncryptionKey,
// };
//
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
//         free_variable: Uint<PLAINTEXT_LIMBS>,
//         coefficients: [Uint<PLAINTEXT_LIMBS>; FUNCTION_DEGREE],
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
//         free_variable: Uint<PLAINTEXT_LIMBS>,
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
