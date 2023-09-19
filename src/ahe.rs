// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod paillier;

use crypto_bigint::{rand_core::CryptoRngCore, Random, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{GroupElement, KnownOrderGroupElement, Samplable},
};

/// An error in encryption key instantiation [`AdditivelyHomomorphicEncryptionKey::new()`]
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error(
    "unsafe public parameters: circuit-privacy cannot be ensured by this scheme using these public parameters."
    )]
    UnsafePublicParameters,
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("zero dimension: cannot evalute a zero-dimension linear combination")]
    ZeroDimension,
}

/// The Result of the `new()` operation of types implementing the
/// `AdditivelyHomomorphicEncryptionKey` trait
pub type Result<T> = std::result::Result<T, Error>;

/// An Encryption Key of an Additively Homomorphic Encryption scheme.
pub trait AdditivelyHomomorphicEncryptionKey<
    const MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    PlaintextSpaceGroupElement,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
>: PartialEq + Sized where
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    PlaintextSpaceGroupElement: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: for<'a> From<&'a PlaintextSpaceGroupElement>,
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

    /// Returns the public parameters of this encryption scheme.
    fn public_parameters(&self) -> Self::PublicParameters;

    /// Instantiate the encryption scheme from the public parameters of the encryption scheme,
    /// plaintext, randomness and ciphertext groups.
    fn new(
        encryption_scheme_public_parameters: &Self::PublicParameters,
        plaintext_group_public_parameters: &PlaintextSpaceGroupElement::PublicParameters,
        randomness_group_public_parameters: &RandomnessSpaceGroupElement::PublicParameters,
        ciphertext_group_public_parameters: &CiphertextSpaceGroupElement::PublicParameters,
    ) -> Result<Self>;

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
    ) -> Result<(RandomnessSpaceGroupElement, CiphertextSpaceGroupElement)> {
        let randomness =
            RandomnessSpaceGroupElement::sample(rng, randomness_group_public_parameters)?;

        let ciphertext = self.encrypt_with_randomness(plaintext, &randomness);

        Ok((randomness, ciphertext))
    }

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// linear combination defined by `coefficients` and `ciphertexts`.
    ///
    /// To ensure circuit-privacy, one must assure that `ciphertexts` are encryptions of plaintext
    /// group elements (and thus their message is bounded by the plaintext group order) either by
    /// generating them via ['Self::encrypt()'] or verifying appropriate zero-knowledge proofs from
    /// encryptors.
    ///
    /// To ensure circuit-privacy, the `mask` and `randmomness` to parameters may be used by
    /// implementers.
    fn evaluate_linear_combination_with_randomness<const DIMENSION: usize>(
        &self,
        coefficients: &[PlaintextSpaceGroupElement; DIMENSION],
        ciphertexts: &[CiphertextSpaceGroupElement; DIMENSION],
        mask: &Uint<MASK_LIMBS>,
        randomness: &RandomnessSpaceGroupElement,
    ) -> Result<CiphertextSpaceGroupElement>;

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// linear combination defined by `coefficients` and `ciphertexts`.
    ///
    /// This is the probabilistic linear combination algorithm which samples `mask` and `randomness`
    /// from `rng` and calls [`Self::linear_combination_with_randomness()`].
    ///
    /// To ensure circuit-privacy, one must assure that `ciphertexts` are encryptions of plaintext
    /// group elements (and thus their message is bounded by the plaintext group order) either by
    /// generating them via ['Self::encrypt()'] or verifying appropriate zero-knowledge proofs from
    /// encryptors.
    fn evaluate_linear_combination<const DIMENSION: usize>(
        &self,
        coefficients: &[PlaintextSpaceGroupElement; DIMENSION],
        ciphertexts: &[CiphertextSpaceGroupElement; DIMENSION],
        randomness_group_public_parameters: &RandomnessSpaceGroupElement::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(
        Uint<MASK_LIMBS>,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
    )> {
        if DIMENSION == 0 {
            return Err(Error::ZeroDimension);
        }

        let mask = Uint::<MASK_LIMBS>::random(rng);

        let randomness =
            RandomnessSpaceGroupElement::sample(rng, randomness_group_public_parameters)?;

        let evaluated_ciphertext = self.evaluate_linear_combination_with_randomness(
            coefficients,
            ciphertexts,
            &mask,
            &randomness,
        );

        Ok((mask, randomness, evaluated_ciphertext?))
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
> where
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    PlaintextSpaceGroupElement: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: for<'a> From<&'a PlaintextSpaceGroupElement>,
    RandomnessSpaceGroupElement:
        GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS> + Samplable<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
{
    /// $\Dec(sk, \ct) \to \pt$: Decrypt `ciphertext` using `decryption_key`.
    /// A deterministic algorithm that on input a secret key $sk$ and a ciphertext $\ct \in
    /// \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
    fn decrypt(&self, ciphertext: &CiphertextSpaceGroupElement) -> PlaintextSpaceGroupElement;
}

#[cfg(test)]
#[allow(clippy::erasing_op)]
#[allow(clippy::identity_op)]
mod tests {
    use crypto_bigint::{Uint, U64};
    use rand_core::OsRng;

    use crate::{
        group::{GroupElement, KnownOrderGroupElement, Samplable},
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    };

    pub(crate) fn encrypt_decrypts<
        const MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
        const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        EncryptionKey,
        DecryptionKey,
    >(
        encryption_key: EncryptionKey,
        decryption_key: DecryptionKey,
        randomness_group_public_parameters: RandomnessSpaceGroupElement::PublicParameters,
    ) where
        PlaintextSpaceGroupElement:
            KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
        PlaintextSpaceGroupElement: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>> + std::fmt::Debug,
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: for<'a> From<&'a PlaintextSpaceGroupElement>,
        RandomnessSpaceGroupElement:
            GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS> + Samplable<RANDOMNESS_SPACE_SCALAR_LIMBS>,
        CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            PlaintextSpaceGroupElement,
            RandomnessSpaceGroupElement,
            CiphertextSpaceGroupElement,
        >,
        DecryptionKey: AdditivelyHomomorphicDecryptionKey<
            MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            PlaintextSpaceGroupElement,
            RandomnessSpaceGroupElement,
            CiphertextSpaceGroupElement,
        >,
    {
        let plaintext: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(42u64)).into();
        let plaintext: PlaintextSpaceGroupElement = plaintext.into();

        let (_, ciphertext) = encryption_key
            .encrypt(&plaintext, &randomness_group_public_parameters, &mut OsRng)
            .unwrap();

        assert_eq!(
            plaintext,
            decryption_key.decrypt(&ciphertext),
            "decrypted ciphertext should match the plaintext"
        );
    }

    pub(crate) fn evaluates<
        const MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
        const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        EncryptionKey,
        DecryptionKey,
    >(
        encryption_key: EncryptionKey,
        decryption_key: DecryptionKey,
        randomness_group_public_parameters: RandomnessSpaceGroupElement::PublicParameters,
    ) where
        PlaintextSpaceGroupElement:
            KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
        PlaintextSpaceGroupElement: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>> + std::fmt::Debug,
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: for<'a> From<&'a PlaintextSpaceGroupElement>,
        RandomnessSpaceGroupElement:
            GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS> + Samplable<RANDOMNESS_SPACE_SCALAR_LIMBS>,
        CiphertextSpaceGroupElement: GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS> + std::fmt::Debug,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            PlaintextSpaceGroupElement,
            RandomnessSpaceGroupElement,
            CiphertextSpaceGroupElement,
        >,
        DecryptionKey: AdditivelyHomomorphicDecryptionKey<
            MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            PlaintextSpaceGroupElement,
            RandomnessSpaceGroupElement,
            CiphertextSpaceGroupElement,
        >,
    {
        let zero: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(0u64)).into();
        let zero: PlaintextSpaceGroupElement = zero.into();
        let one: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(1u64)).into();
        let one: PlaintextSpaceGroupElement = one.into();
        let two: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(2u64)).into();
        let two: PlaintextSpaceGroupElement = two.into();
        let five: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(5u64)).into();
        let five: PlaintextSpaceGroupElement = five.into();
        let seven: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(7u64)).into();
        let seven: PlaintextSpaceGroupElement = seven.into();
        let seventy_three: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(73u64)).into();
        let seventy_three: PlaintextSpaceGroupElement = seventy_three.into();

        let (_, encrypted_two) = encryption_key
            .encrypt(&two, &randomness_group_public_parameters, &mut OsRng)
            .unwrap();

        let (_, encrypted_five) = encryption_key
            .encrypt(&five, &randomness_group_public_parameters, &mut OsRng)
            .unwrap();

        let (_, encrypted_seven) = encryption_key
            .encrypt(&seven, &randomness_group_public_parameters, &mut OsRng)
            .unwrap();

        let evaluted_ciphertext = encrypted_five.scalar_mul(&U64::from(1u64))
            + encrypted_seven.scalar_mul(&U64::from(0u64))
            + encrypted_two.scalar_mul(&U64::from(73u64));

        let expected_evaluation_result: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            (&U64::from(1u64 * 5 + 0 * 7 + 73 * 2)).into();
        let expected_evaluation_result: PlaintextSpaceGroupElement =
            expected_evaluation_result.into();

        assert_eq!(
            expected_evaluation_result,
            decryption_key.decrypt(&evaluted_ciphertext)
        );

        let (_, _, privately_evaluted_ciphertext) = encryption_key
            .evaluate_linear_combination(
                &[one, zero, seventy_three],
                &[encrypted_five, encrypted_seven, encrypted_two],
                &randomness_group_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        assert_ne!(evaluted_ciphertext, privately_evaluted_ciphertext, "privately evaluating the linear combination should result in a different ciphertext due to added randomness");

        assert_eq!(
            decryption_key.decrypt(&evaluted_ciphertext),
            decryption_key.decrypt(&privately_evaluted_ciphertext),
            "decryptions of privately evaluated linear combinations should match straightforward ones"
        );
    }
}
