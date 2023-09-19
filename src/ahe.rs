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
    use crypto_bigint::{Uint, U256, U384, U64};
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::{self, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

    use crate::{
        ahe::paillier,
        group::{
            multiplicative_group_of_integers_modulu_n, secp256k1, GroupElement,
            KnownOrderGroupElement, Samplable,
        },
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    };

    const N: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    const N2: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("5960383b5378ad0607f0f270ce7fb6dcaba6506f9fc56deeffaf605c9128db8ccf063e2e8221a8bdf82c027741a0303b08eb71fa6225a03df18f24c473dc6d4d3d30eb9c52a233bbfe967d04011b95e8de5bc482c3c217bcfdeb4df6f57af6ba9c6d66c69fb03a70a41fe1e87975c85343ef7d572ca06a0139706b23ed2b73ad72cb1b7e2e41840115651897c8757b3da9af3a60eebb6396ffd193738b4f04aa6ece638cef1bf4e9c45cf57f8debeda8598cbef732484752f5380737ba75ee00bf1b146817b9ab336d0ce5540395377347c653d1c9d272127ff12b9a0721b8ef13ecd8a8379f1b9a358de2af2c4cd97564dbd5328c2fc13d56ee30c8a101d333f5406afb1f4417b49d7a629d5076726877df11f05c998ae365e374a0141f0b99802214532c97c1ebf9faf6e277a8f29dbd8f3eab72266e60a77784249694819e42877a5e826745c97f84a5f37002b74d83fc064cf094be0e706a6710d47d253c4532e6aa4a679a75fa1d860b39085dab03186c67248e6c92223682f58bd41b67143e299329ce3a8045f3a0124c3d0ef9f0f49374d89b37d9c3321feb2ab4117df4f68246724ce41cd765326457968d848afcc0735531e5de7fea88cf2eb35ac68710c6e79d5ad25df6c0393c0267f56e8eac90a52637abe3e606769e70b20560eaf70e0d531b11dca299104fa933f887d85fb5f72386c196e40f559baee356b9");
    const PAILLIER_SECRET_KEY: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");

    const PAILLIER_SCHEME_PUBLIC_PARAMETERS: paillier::PublicParameters<
        { U384::LIMBS },
        { U256::LIMBS },
        secp256k1::Scalar,
    > = paillier::PublicParameters::DEFAULT;
    const PAILLIER_RANDOMNESS_PUBLIC_PARAMETERS:
        multiplicative_group_of_integers_modulu_n::PublicParameters<
            { LargeBiPrimeSizedNumber::LIMBS },
        > = multiplicative_group_of_integers_modulu_n::PublicParameters::new(N);
    const PAILLIER_CIPHERTEXT_PUBLIC_PARAMETERS:
        multiplicative_group_of_integers_modulu_n::PublicParameters<
            { PaillierModulusSizedNumber::LIMBS },
        > = multiplicative_group_of_integers_modulu_n::PublicParameters::new(N2);

    fn paillier_encryption_key(
    ) -> paillier::EncryptionKey<{ U384::LIMBS }, { U256::LIMBS }, secp256k1::Scalar> {
        paillier::EncryptionKey::new(
            &PAILLIER_SCHEME_PUBLIC_PARAMETERS,
            &secp256k1::scalar::PublicParameters::default(),
            &PAILLIER_RANDOMNESS_PUBLIC_PARAMETERS,
            &PAILLIER_CIPHERTEXT_PUBLIC_PARAMETERS,
        )
        .unwrap()
    }

    fn paillier_decryption_key(
    ) -> paillier::DecryptionKey<{ U384::LIMBS }, { U256::LIMBS }, secp256k1::Scalar> {
        paillier::DecryptionKey::from(tiresias::DecryptionKey::new(
            tiresias::EncryptionKey::new(N),
            PAILLIER_SECRET_KEY,
        ))
    }

    #[rstest]
    #[case(
        paillier_encryption_key(),
        paillier_decryption_key(),
        PAILLIER_RANDOMNESS_PUBLIC_PARAMETERS
    )]
    fn encrypt_decrypts<
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
        #[case] encryption_key: EncryptionKey,
        #[case] decryption_key: DecryptionKey,
        #[case] randomness_group_public_parameters: RandomnessSpaceGroupElement::PublicParameters,
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

    #[rstest]
    #[case(
        paillier_encryption_key(),
        paillier_decryption_key(),
        PAILLIER_RANDOMNESS_PUBLIC_PARAMETERS
    )]
    fn evaluates<
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
        #[case] encryption_key: EncryptionKey,
        #[case] decryption_key: DecryptionKey,
        #[case] randomness_group_public_parameters: RandomnessSpaceGroupElement::PublicParameters,
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
            "decryptions of privately evaluted linear combinations should match straightforward ones"
        );
    }
}
