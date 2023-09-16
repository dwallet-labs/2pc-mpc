// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
mod paillier;

use crypto_bigint::{rand_core::CryptoRngCore, Random, Uint};
use serde::{Deserialize, Serialize};

use crate::group::{GroupElement, KnownOrderGroupElement, Samplable};

/// An Encryption Key of an Additively Homomorphic Encryption scheme
pub trait AdditivelyHomomorphicEncryptionKey<
    const MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    PlaintextSpaceGroupElement,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
> where
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    RandomnessSpaceGroupElement:
        GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS> + Samplable<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
{
    /// The public parameters of the encryption scheme.
    ///
    /// Used for encryption-specific parameters (e.g., the modulus $N$ in case of Paillier.)
    ///
    /// Group public parameters are encoded separately in
    /// `PlaintextSpaceGroupElement::PublicParameters`,
    /// `RandomnessSpaceGroupElement::PublicParameters`
    /// `CiphertextSpaceGroupElement::PublicParameters`.
    ///
    /// Used in [`Self::encrypt()`] to define the encryption algorithm.
    /// As such, it uniquely identifies the encryption-scheme (alongside the type `Self`) and will
    /// be used for Fiat-Shamir Transcripts).
    type PublicParameters: Serialize + for<'r> Deserialize<'r> + Clone + PartialEq;

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
        plaintext: &PlaintextSpaceGroupElement,
        randomness: &RandomnessSpaceGroupElement,
    ) -> CiphertextSpaceGroupElement;

    /// Encrypt `plaintext` to `self`.
    ///
    /// This is the probabilistic encryption algorithm which samples randomness
    /// from `rng`.    
    fn encrypt(
        &self,
        plaintext: &PlaintextSpaceGroupElement,
        randomness_group_public_parameters: &RandomnessSpaceGroupElement::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> (RandomnessSpaceGroupElement, CiphertextSpaceGroupElement) {
        let randomness =
            RandomnessSpaceGroupElement::sample(rng, randomness_group_public_parameters);

        let ciphertext = self.encrypt_with_randomness(plaintext, &randomness);

        (randomness, ciphertext)
    }

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// affine function defined by `free_variable` and `coefficients` on `ciphertexts`; to
    /// ensure circuit-privacy, the `mask` and `randmomness` to parameters should be passed (and
    /// could be ignored by some implementors if unneeded.)
    ///
    /// Given a public key $pk$, an affine function $f(x_1,\ldots,x_\ell)=
    /// a_0+\sum_{i=1}^{\ell}{a_i x_i}$ (with $a_i\in\ZZ$ and $\ell,\|a_i\|_2\in\poly(\kappa)$ for
    /// all $0\le i\le \ell$) and $\ell$ ciphertexts $\ct_1,\ldots,\ct_t \in \calC$, $\Eval$
    /// outputs a ciphertext $\ct$.
    fn evaluate_linear_transformation_with_randomness<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: &PlaintextSpaceGroupElement,
        coefficients: &[PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: &[CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        mask: &Uint<MASK_LIMBS>,
        randomness: &RandomnessSpaceGroupElement,
    ) -> CiphertextSpaceGroupElement;

    fn evaluate_linear_transformation<const FUNCTION_DEGREE: usize>(
        &self,
        free_variable: &PlaintextSpaceGroupElement,
        coefficients: &[PlaintextSpaceGroupElement; FUNCTION_DEGREE],
        ciphertexts: &[CiphertextSpaceGroupElement; FUNCTION_DEGREE],
        randomness_group_public_parameters: &RandomnessSpaceGroupElement::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> (
        Uint<MASK_LIMBS>,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
    ) {
        let mask = Uint::<MASK_LIMBS>::random(rng);

        let randomness =
            RandomnessSpaceGroupElement::sample(rng, randomness_group_public_parameters);

        let evaluated_ciphertext = self.evaluate_linear_transformation_with_randomness(
            free_variable,
            coefficients,
            ciphertexts,
            &mask,
            &randomness,
        );

        (mask, randomness, evaluated_ciphertext)
    }
}

/// A Decryption Key of an Additively Homomorphic Encryption scheme
pub trait AdditivelyHomomorphicDecryptionKey<
    const MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    PlaintextSpaceGroupElement,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
>:
    AdditivelyHomomorphicEncryptionKey<
    MASK_LIMBS,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    RANDOMNESS_SPACE_SCALAR_LIMBS,
    CIPHERTEXT_SPACE_SCALAR_LIMBS,
    PlaintextSpaceGroupElement,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
> where
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    RandomnessSpaceGroupElement:
        GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS> + Samplable<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
{
    /// $\Dec(sk, \ct) \to \pt$: Decrypt `ciphertext` using `decryption_key`.
    /// A deterministic algorithm that on input a secret key $sk$ and a ciphertext $\ct \in
    /// \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
    fn decrypt(&self, ciphertext: &CiphertextSpaceGroupElement) -> PlaintextSpaceGroupElement;
}
