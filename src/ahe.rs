// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod paillier;

use std::fmt::Debug;

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
pub trait AdditivelyHomomorphicEncryptionKey<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize>:
PartialEq + Clone + Debug
{
    type PlaintextSpaceGroupElement: GroupElement<Value=Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>
    + KnownOrderGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar=Self::PlaintextSpaceGroupElement,
    >;
    type RandomnessSpaceGroupElement: GroupElement + Samplable;
    type CiphertextSpaceGroupElement: GroupElement;

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

    /// Instantiate the encryption key from the public parameters of the encryption scheme,
    /// plaintext, randomness and ciphertext groups.
    fn new(
        encryption_scheme_public_parameters: &Self::PublicParameters,
        plaintext_group_public_parameters: &group::PublicParameters<
            Self::PlaintextSpaceGroupElement,
        >,
        randomness_group_public_parameters: &group::PublicParameters<
            Self::RandomnessSpaceGroupElement,
        >,
        ciphertext_group_public_parameters: &group::PublicParameters<
            Self::CiphertextSpaceGroupElement,
        >,
    ) -> Result<Self>;

    /// $\Enc(pk, \pt; \eta_{\sf enc}) \to \ct$: Encrypt `plaintext` to `self` using
    /// `randomness`.
    ///
    /// A deterministic algorithm that on input a public key $pk$, a plaintext $\pt \in \calP_{pk}$
    /// and randomness $\eta_{\sf enc} \in \calR_{pk}$, outputs a ciphertext $\ct \in \calC_{pk}$.
    fn encrypt_with_randomness(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Self::CiphertextSpaceGroupElement;

    /// $\Enc(pk, \pt)$: a probabilistic algorithm that first uniformly samples `randomness`
    /// $\eta_{\sf enc} \in \calR_{pk}$ from `rng` and then calls [`Self::
    /// encrypt_with_randomness()`] to encrypt `plaintext` to `self` using the sampled randomness.
    fn encrypt(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        randomness_group_public_parameters: &group::PublicParameters<
            Self::RandomnessSpaceGroupElement,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(
        Self::RandomnessSpaceGroupElement,
        Self::CiphertextSpaceGroupElement,
    )> {
        let randomness =
            Self::RandomnessSpaceGroupElement::sample(rng, randomness_group_public_parameters)?;

        let ciphertext = self.encrypt_with_randomness(plaintext, &randomness);

        Ok((randomness, ciphertext))
    }

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// linear combination defined by `coefficients` and `ciphertexts`.
    ///
    /// This method *does not assure circuit privacy*.
    fn evaluate_linear_combination<const DIMENSION: usize>(
        coefficients: &[Self::PlaintextSpaceGroupElement; DIMENSION],
        ciphertexts: &[Self::CiphertextSpaceGroupElement; DIMENSION],
    ) -> Result<Self::CiphertextSpaceGroupElement> {
        if DIMENSION == 0 {
            return Err(Error::ZeroDimension);
        }

        Ok(coefficients.iter().zip(ciphertexts.iter()).fold(
            ciphertexts[0].neutral(),
            |curr, (coefficient, ciphertext)| {
                curr + ciphertext.scalar_mul(&coefficient.value().into())
            },
        ))
    }

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// linear combination defined by `coefficients` and `ciphertexts`.
    ///
    /// In order to perform an affine evaluation, the free variable should be paired with an
    /// encryption of one.
    ///
    /// This method ensures circuit privacy by masking the linear combination with a random (`mask`)
    /// multiplication of the `modulus` $q$ using fresh `randomness`:
    ///
    /// $\ct = \Enc(pk, \omega q; \eta) \bigoplus_{i=1}^\ell \left(  a_i \odot \ct_i \right)$
    ///
    /// In more detail, these steps are taken to genrically assure circuit privacy:
    /// 1. Rerandomization. This should be done by adding an encryption of zero with fresh
    ///    randomness to the outputted ciphertext.
    ///
    /// 2. Masking. Our evaluation should be masked by a random multiplication of the homomorphic
    ///    evaluation group order $q$.
    ///
    ///    While the decryption modulo $q$ will remain correct,
    ///    assuming that the mask was "big enough", it will be statistically indistinguishable from
    ///    random.    
    ///
    ///    "Big enough" here means bigger by the statistical security parameter than the size of the
    ///    evaluation.
    ///
    ///    Assuming a bound $B$ on both the coefficients and the (encrypted) messages, the
    ///    evaluation is bounded by the number of coefficients $l$ by $B^2$.
    ///
    ///    In order to mask that, we need to add a mask that is bigger by the statistical security
    ///    parameter. Since we multiply our mask by $q$, we need our mask to be of size $(l*B^2 / q)
    ///    + s$.
    ///
    ///   Note that (unless we trust the encryptor) it is important to assure these bounds on
    ///   the ciphertexts by verifying appropriate zero-knowledge proofs.
    ///
    ///    TODO: I wanted to say the coefficients are bounded to $q$ because we create them, but in
    ///    fact when we prove in zero-knowledge that they are, we're going to have a gap here
    ///    too right? and so the verifier should check we didn't go through modulation using
    ///    that bound and not q.)
    /// 3. No modulations. The size of our evaluation $l*B^2$ should be smaller than the order of
    ///    the encryption plaintext group $N$ in order to assure it does not go through modulation
    ///    in the plaintext space.
    ///
    /// In the case that the plaintext order is the same as the evaluation `modulus`, steps 2, 3 are
    /// skipped.
    fn evaluate_circuit_private_linear_combination_with_randomness<
        const DIMENSION: usize,
        const MODULUS_LIMBS: usize,
        const MASK_LIMBS: usize,
    >(
        &self,
        coefficients: &[Self::PlaintextSpaceGroupElement; DIMENSION],
        ciphertexts: &[Self::CiphertextSpaceGroupElement; DIMENSION],
        modulus: &Uint<MODULUS_LIMBS>,
        mask: &Uint<MASK_LIMBS>,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Result<Self::CiphertextSpaceGroupElement> {
        if DIMENSION == 0 {
            return Err(Error::ZeroDimension);
        }

        let plaintext_order: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = coefficients[0].order();

        if PLAINTEXT_SPACE_SCALAR_LIMBS != MODULUS_LIMBS || plaintext_order != modulus.into() {
            // TODO: do checks here, BOUND_LIMBS?
        }

        let linear_combination = Self::evaluate_linear_combination(coefficients, ciphertexts)?;

        // Rerandomization is performed in any case, and a masked multiplication of the modulus is
        // added only if the order of the plaintext space differs from `modulus`.
        let plaintext =
            if PLAINTEXT_SPACE_SCALAR_LIMBS == MODULUS_LIMBS && plaintext_order == modulus.into() {
                coefficients[0].neutral()
            } else {
                Self::PlaintextSpaceGroupElement::new(
                    (Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(mask).wrapping_mul(modulus)).into(),
                    &coefficients[0].public_parameters(),
                )?
            };

        let encryption_with_fresh_randomness = self.encrypt_with_randomness(&plaintext, randomness);

        Ok(linear_combination + encryption_with_fresh_randomness)
    }

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Efficient homomorphic evaluation of the
    /// linear combination defined by `coefficients` and `ciphertexts`.
    ///
    /// This is the probabilistic linear combination algorithm which samples `mask` and `randomness`
    /// from `rng` and calls [`Self::linear_combination_with_randomness()`].
    fn evaluate_circuit_private_linear_combination<
        const DIMENSION: usize,
        const MODULUS_LIMBS: usize,
        const MASK_LIMBS: usize,
    >(
        &self,
        coefficients: &[Self::PlaintextSpaceGroupElement; DIMENSION],
        ciphertexts: &[Self::CiphertextSpaceGroupElement; DIMENSION],
        modulus: &Uint<MODULUS_LIMBS>,
        randomness_group_public_parameters: &group::PublicParameters<
            Self::RandomnessSpaceGroupElement,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(
        Uint<MASK_LIMBS>,
        Self::RandomnessSpaceGroupElement,
        Self::CiphertextSpaceGroupElement,
    )> {
        let mask = Uint::<MASK_LIMBS>::random(rng);

        let randomness =
            Self::RandomnessSpaceGroupElement::sample(rng, randomness_group_public_parameters)?;

        let evaluated_ciphertext = self
            .evaluate_circuit_private_linear_combination_with_randomness(
                coefficients,
                ciphertexts,
                modulus,
                &mask,
                &randomness,
            )?;

        Ok((mask, randomness, evaluated_ciphertext))
    }
}

/// A Decryption Key of an Additively Homomorphic Encryption scheme
pub trait AdditivelyHomomorphicDecryptionKey<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>: Into<EncryptionKey> + Clone + PartialEq
{
    type SecretKey;

    /// Instantiate the decryption key from the public parameters of the encryption scheme,
    /// plaintext, randomness, ciphertext groups and the secret key.
    fn new(
        encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
        plaintext_group_public_parameters: &group::PublicParameters<
            EncryptionKey::PlaintextSpaceGroupElement,
        >,
        randomness_group_public_parameters: &group::PublicParameters<
            EncryptionKey::RandomnessSpaceGroupElement,
        >,
        ciphertext_group_public_parameters: &group::PublicParameters<
            EncryptionKey::CiphertextSpaceGroupElement,
        >,
        secret_key: Self::SecretKey,
    ) -> Result<Self>;

    /// $\Dec(sk, \ct) \to \pt$: Decrypt `ciphertext` using `decryption_key`.
    /// A deterministic algorithm that on input a secret key $sk$ and a ciphertext $\ct \in
    /// \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
    fn decrypt(
        &self,
        ciphertext: &EncryptionKey::CiphertextSpaceGroupElement,
    ) -> EncryptionKey::PlaintextSpaceGroupElement;
}

pub type PlaintextSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = <
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::PlaintextSpaceGroupElement;
pub type PlaintextSpacePublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = group::PublicParameters<<
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::PlaintextSpaceGroupElement>;
pub type PlaintextSpaceValue<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = group::Value<<
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::PlaintextSpaceGroupElement>;

pub type RandomnessSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = <
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::RandomnessSpaceGroupElement;
pub type RandomnessSpacePublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = group::PublicParameters<<
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::RandomnessSpaceGroupElement>;
pub type RandomnessSpaceValue<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = group::Value<<
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::RandomnessSpaceGroupElement>;
pub type CiphertextSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = <
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::CiphertextSpaceGroupElement;
pub type CiphertextSpacePublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = group::PublicParameters<<
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::CiphertextSpaceGroupElement>;
pub type CiphertextSpaceValue<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> = group::Value<<
E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
>::CiphertextSpaceGroupElement>;
pub type PublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PublicParameters;


#[cfg(test)]
#[allow(clippy::erasing_op)]
#[allow(clippy::identity_op)]
mod tests {
    use crypto_bigint::{Uint, U64};
    use rand_core::OsRng;

    use super::*;
    use crate::{
        group::{GroupElement, KnownOrderGroupElement, Value},
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    };

    pub(crate) fn encrypt_decrypts<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKey,
    >(
        decryption_key: DecryptionKey,
        plaintext_group_public_parameters: group::PublicParameters<
            EncryptionKey::PlaintextSpaceGroupElement,
        >,
        randomness_group_public_parameters: group::PublicParameters<
            EncryptionKey::RandomnessSpaceGroupElement,
        >,
    ) where
        DecryptionKey:
        AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        EncryptionKey::PlaintextSpaceGroupElement: Debug,
    {
        let encryption_key: EncryptionKey = decryption_key.clone().into();
        let plaintext: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(42u64)).into();
        let plaintext: EncryptionKey::PlaintextSpaceGroupElement =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                plaintext.into(),
                &plaintext_group_public_parameters,
            )
                .unwrap();

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
        const EVALUATION_GROUP_SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EvaluationGroupElement: KnownOrderGroupElement<EVALUATION_GROUP_SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKey,
    >(
        decryption_key: DecryptionKey,
        evaluation_group_public_parameters: group::PublicParameters<EvaluationGroupElement>,
        plaintext_group_public_parameters: group::PublicParameters<
            EncryptionKey::PlaintextSpaceGroupElement,
        >,
        randomness_group_public_parameters: group::PublicParameters<
            EncryptionKey::RandomnessSpaceGroupElement,
        >,
    ) where
        DecryptionKey:
        AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        EncryptionKey::PlaintextSpaceGroupElement: Debug,
        EncryptionKey::CiphertextSpaceGroupElement: Debug,
        EvaluationGroupElement: From<Value<EncryptionKey::PlaintextSpaceGroupElement>> + Debug,
    {
        let encryption_key: EncryptionKey = decryption_key.clone().into();

        let zero: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(0u64)).into();
        let zero = EncryptionKey::PlaintextSpaceGroupElement::new(
            zero.into(),
            &plaintext_group_public_parameters,
        )
            .unwrap();

        let one: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(1u64)).into();
        let one = EncryptionKey::PlaintextSpaceGroupElement::new(
            one.into(),
            &plaintext_group_public_parameters,
        )
            .unwrap();
        let two: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(2u64)).into();
        let two = EncryptionKey::PlaintextSpaceGroupElement::new(
            two.into(),
            &plaintext_group_public_parameters,
        )
            .unwrap();
        let five: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(5u64)).into();
        let five = EncryptionKey::PlaintextSpaceGroupElement::new(
            five.into(),
            &plaintext_group_public_parameters,
        )
            .unwrap();
        let seven: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(7u64)).into();
        let seven = EncryptionKey::PlaintextSpaceGroupElement::new(
            seven.into(),
            &plaintext_group_public_parameters,
        )
            .unwrap();
        let seventy_three: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(73u64)).into();
        let seventy_three = EncryptionKey::PlaintextSpaceGroupElement::new(
            seventy_three.into(),
            &plaintext_group_public_parameters,
        )
            .unwrap();

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
        let expected_evaluation_result = EncryptionKey::PlaintextSpaceGroupElement::new(
            expected_evaluation_result.into(),
            &plaintext_group_public_parameters,
        )
            .unwrap();

        assert_eq!(
            expected_evaluation_result,
            decryption_key.decrypt(&evaluted_ciphertext)
        );

        let (_, _, privately_evaluted_ciphertext): (
            Uint<MASK_LIMBS>,
            EncryptionKey::RandomnessSpaceGroupElement,
            EncryptionKey::CiphertextSpaceGroupElement,
        ) = encryption_key
            .evaluate_circuit_private_linear_combination(
                &[one, zero, seventy_three],
                &[encrypted_five, encrypted_seven, encrypted_two],
                &EvaluationGroupElement::order_from_public_parameters(
                    &evaluation_group_public_parameters,
                ),
                &randomness_group_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        assert_ne!(evaluted_ciphertext, privately_evaluted_ciphertext, "privately evaluating the linear combination should result in a different ciphertext due to added randomness");

        assert_ne!(
            decryption_key.decrypt(&evaluted_ciphertext),
            decryption_key.decrypt(&privately_evaluted_ciphertext),
            "decryptions of privately evaluated linear combinations should be statistically indistinguishable from straightforward ones"
        );

        assert_eq!(
            EvaluationGroupElement::from(
                decryption_key.decrypt(&evaluted_ciphertext).value().into()
            ),
            EvaluationGroupElement::from(
                decryption_key.decrypt(&privately_evaluted_ciphertext).value().into()
            ),
            "decryptions of privately evaluated linear combinations should match straightforward ones modulu the evaluation group order"
        );
    }
}
