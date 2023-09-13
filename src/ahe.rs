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

/// An Additively Homomorphic Encryption scheme
pub trait AdditivelyHomomorphicEncryption<
    const PLAINTEXT_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    // TODO: MessageSpaceGroupElement with Z_n+ which is known-order. Then use this for eval.
    RandomnessSpaceGroupElement: GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
>
{
    type EncryptionKey;
    type DecryptionKey;

    /// $\Enc(pk, \pt; \eta_{\sf enc}) \to \ct$: Encrypt `plaintext` to `encryption_key` using
    /// `randomness`.
    ///
    /// A deterministic algorithm that on input a public key $pk$, a plaintext $\pt \in \calP_{pk}$
    /// and randomness $\eta_{\sf enc} \in \calR_{pk}$, outputs a ciphertext $\ct \in \calC_{pk}$.
    /// We define $\Enc(pk, \pt)$ as a probabilistic algorithm that first uniformly samples
    /// $\eta_{\sf enc} \in \calR_{pk}$ and then outputs $\ct=\Enc(pk, \pt; \eta_{\sf
    /// enc})\in\calC_{pk}$.
    fn encrypt_with_randomness(
        encryption_key: &EncryptionKey,
        plaintext: Uint<PLAINTEXT_LIMBS>,
        randomness: &RandomnessSpaceGroupElement,
    ) -> CiphertextSpaceGroupElement;

    // TODO: encrypt & decrypt as functions of types.

    /// Encrypt `plaintext` to `encryption_key`.
    ///
    /// This is the probabilistic encryption algorithm which samples randomness
    /// from `rng`.    
    fn encrypt(
        encryption_key: &EncryptionKey,
        plaintext: Uint<PLAINTEXT_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextSpaceGroupElement;

    /// $\Dec(sk, \ct) \to \pt$: Decrypt `ciphertext` using `decryption_key`.
    /// A deterministic algorithm that on input a secret key $sk$ and a ciphertext $\ct \in
    /// \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
    fn decrypt(
        decryption_key: &DecryptionKey,
        ciphertext: &CiphertextSpaceGroupElement,
    ) -> Uint<PLAINTEXT_LIMBS>;

    // TODO: option types

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// affine function defined by `free_variable` and `coefficients` on `ciphertexts`; to ensure
    /// circuit-privacy, some implementations may require `mask` and `randmomness` to be `Some`.
    ///
    /// Whenever we omit the randomness in $\Eval(pk,
    /// f, \ct_1,\ldots,\ct_t)$, we refer to the process of sampling a randomness $\eta_{\sf
    /// eval}\gets\{0,1\}^{\poly(\kappa)}$ and running $\Eval(pk, f, \ct_1,\ldots,\ct_t; \eta_{\sf
    /// eval})$. Given a public key $pk$, an affine function $f(x_1,\ldots,x_\ell)=
    /// a_0+\sum_{i=1}^{\ell}{a_i x_i}$ (with $a_i\in\ZZ$ and $\ell,\|a_i\|_2\in\poly(\kappa)$ for
    /// all $0\le i\le \ell$) and $\ell$ ciphertexts $\ct_1,\ldots,\ct_t \in \calC$, $\Eval$ outputs
    /// a ciphertext $\ct$.
    fn evaluate_linear_transformation_with_randomness<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
        const MASK_LIMBS: usize,
    >(
        encryption_key: &EncryptionKey,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        mask: Uint<MASK_LIMBS>,
        randomness: &RandomnessSpaceGroupElement,
    ) -> Result<CiphertextSpaceGroupElement>;

    fn evaluate_linear_transformation<
        const FUNCTION_DEGREE: usize,
        const COEFFICIENT_LIMBS: usize,
    >(
        encryption_key: &EncryptionKey,
        free_variable: Uint<COEFFICIENT_LIMBS>,
        coefficients: [Uint<COEFFICIENT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> Result<CiphertextSpaceGroupElement>;
}
