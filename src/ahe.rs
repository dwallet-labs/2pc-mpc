// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use tiresias::{DecryptionKey, EncryptionKey};

use crate::group::GroupElement;

mod paillier;

/// An error in additively homomorphic encryption evaluation
/// [`AdditivelyHomomorphicEncryption::evaluate_linear_transformation()`]
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error(
    "out of range: the range upper bound over the coefficients is too large to satisfy circuit privacy"
    )]
    OutOfRangeError,
    // TODO: do I want to seperate cases where the number of coefficients is too large?
}

/// The result of an additively homomorphic encryption evaluation
/// [`AdditivelyHomomorphicEncryption::evaluate_linear_transformation()`]
pub type Result<T> = std::result::Result<T, Error>;

pub trait AdditivelyHomomorphicEncryption<
    const PLAINTEXT_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    RandomnessSpaceGroupElement: GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
>
{
    type EncryptionKey;
    type DecryptionKey;

    fn encrypt_with_randomness(
        encryption_key: &EncryptionKey,
        plaintext: Uint<PLAINTEXT_LIMBS>,
        randomness: &RandomnessSpaceGroupElement,
    ) -> CiphertextSpaceGroupElement;

    fn encrypt(
        encryption_key: &EncryptionKey,
        plaintext: Uint<PLAINTEXT_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextSpaceGroupElement;

    // TODO: can this fail? should we return Result?
    fn decrypt(
        decryption_key: &DecryptionKey,
        ciphertext: &CiphertextSpaceGroupElement,
    ) -> Uint<PLAINTEXT_LIMBS>;

    // TODO: rename affine_evaluation()?
    // TODO: coefficient size?

    fn evaluate_linear_transformation_with_randomness<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
    >(
        encryption_key: &EncryptionKey,
        range_upper_bound: Uint<COEFFICIENT_LIMBS>,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        mask: Uint<PLAINTEXT_LIMBS>,
        randomness: &RandomnessSpaceGroupElement,
    ) -> Result<CiphertextSpaceGroupElement>;

    fn evaluate_linear_transformation<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
    >(
        encryption_key: &EncryptionKey,
        range_upper_bound: Uint<COEFFICIENT_LIMBS>,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> Result<CiphertextSpaceGroupElement>;
}
