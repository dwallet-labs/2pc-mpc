// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Uint};

use crate::group::{additive_group_of_integers_modulu_n, GroupElement};

mod paillier;

/// An error in additively homomorphic encryption evaluation
/// [`AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation()`]
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("wrong mask size: the mask size is not of the right size, which might compromise circuit privacy")]
    WrongMaskSizeError,
    #[error("oversize mask: the mask is too large to satisfy circuit privacy")]
    OversizeMaskError,
}

/// The result of an additively homomorphic encryption evaluation
/// [`AdditivelyHomomorphicEncryptionKey::evaluate_linear_transformation()`]
pub type Result<T> = std::result::Result<T, Error>;

type MessageSpaceGroupElement<const LIMBS: usize> =
    additive_group_of_integers_modulu_n::GroupElement<LIMBS>;

/// An Encryption Key of an Additively Homomorphic Encryption scheme
pub trait AdditivelyHomomorphicEncryptionKey<
    const PLAINTEXT_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    RandomnessSpaceGroupElement: GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
>
{
    /// $\Enc(pk, \pt; \eta_{\sf enc}) \to \ct$: Encrypt `plaintext` to `self` using
    /// `randomness`.
    ///
    /// A deterministic algorithm that on input a public key $pk$, a plaintext $\pt \in \calP_{pk}$
    /// and randomness $\eta_{\sf enc} \in \calR_{pk}$, outputs a ciphertext $\ct \in \calC_{pk}$.
    /// We define $\Enc(pk, \pt)$ as a probabilistic algorithm that first uniformly samples
    /// $\eta_{\sf enc} \in \calR_{pk}$ and then outputs $\ct=\Enc(pk, \pt; \eta_{\sf
    /// enc})\in\calC_{pk}$.
    fn encrypt_with_randomness(
        &self,
        plaintext: MessageSpaceGroupElement<PLAINTEXT_LIMBS>,
        randomness: &RandomnessSpaceGroupElement,
    ) -> CiphertextSpaceGroupElement;

    /// Encrypt `plaintext` to `self`.
    ///
    /// This is the probabilistic encryption algorithm which samples randomness
    /// from `rng`.    
    fn encrypt(
        &self,
        plaintext: MessageSpaceGroupElement<PLAINTEXT_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> CiphertextSpaceGroupElement;

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// affine function defined by `free_variable` and `coefficients` on `ciphertexts`; to
    /// ensure circuit-privacy, the `mask` and `randmomness` to parameters should be passed (and
    /// could be ignored by some implementors if unneeded.)
    ///
    /// Given a public key $pk$, an affine function $f(x_1,\ldots,x_\ell)=
    /// a_0+\sum_{i=1}^{\ell}{a_i x_i}$ (with $a_i\in\ZZ$ and $\ell,\|a_i\|_2\in\poly(\kappa)$ for
    /// all $0\le i\le \ell$) and $\ell$ ciphertexts $\ct_1,\ldots,\ct_t \in \calC$, $\Eval$
    /// outputs a ciphertext $\ct$.
    fn evaluate_linear_transformation_with_randomness<
        const FUNCTION_DEGREE: usize,
        const MASK_LIMBS: usize,
    >(
        &self,
        free_variable: Uint<PLAINTEXT_LIMBS>,
        coefficients: [Uint<PLAINTEXT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        mask: Uint<MASK_LIMBS>,
        randomness: RandomnessSpaceGroupElement,
    ) -> Result<CiphertextSpaceGroupElement>;

    fn evaluate_linear_transformation<const FUNCTION_DEGREE: usize, const MASK_LIMBS: usize>(
        &self,
        free_variable: Uint<PLAINTEXT_LIMBS>,
        coefficients: [Uint<PLAINTEXT_LIMBS>; FUNCTION_DEGREE],
        ciphertexts: [CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        rng: &mut impl CryptoRngCore,
    ) -> Result<CiphertextSpaceGroupElement>;
}

pub trait AdditivelyHomomorphicDecryptionKey<
    const PLAINTEXT_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    RandomnessSpaceGroupElement: GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
>:
    AdditivelyHomomorphicEncryptionKey<
    PLAINTEXT_LIMBS,
    RANDOMNESS_SPACE_SCALAR_LIMBS,
    CIPHERTEXT_SPACE_SCALAR_LIMBS,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
>
{
    /// $\Dec(sk, \ct) \to \pt$: Decrypt `ciphertext` using `decryption_key`.
    /// A deterministic algorithm that on input a secret key $sk$ and a ciphertext $\ct \in
    /// \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
    fn decrypt(
        &self,
        ciphertext: &CiphertextSpaceGroupElement,
    ) -> MessageSpaceGroupElement<PLAINTEXT_LIMBS>;
}
