// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{ConcatMixed, Uint, U64};
use group::{
    multiplicative_group_of_integers_modulu_n,
    paillier::{CiphertextGroupElement, PlaintextGroupElement, RandomnessGroupElement},
};
use serde::{Deserialize, Serialize};
use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::{
    group,
    group::{
        additive_group_of_integers_modulu_n::odd_moduli, GroupElement, KnownOrderGroupElement,
    },
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    StatisticalSecuritySizedNumber,
};

/// An Encryption Key of the Paillier Additively Homomorphic Encryption Scheme.
#[derive(PartialEq, Clone)]
pub struct EncryptionKey(tiresias::EncryptionKey);

/// An Decryption Key of the Paillier Additively Homomorphic Encryption Scheme.
#[derive(PartialEq)]
pub struct DecryptionKey(tiresias::DecryptionKey);

type RandomnessPublicParameters =
    multiplicative_group_of_integers_modulu_n::PublicParameters<{ LargeBiPrimeSizedNumber::LIMBS }>;
type CiphertextPublicParameters = multiplicative_group_of_integers_modulu_n::PublicParameters<
    { PaillierModulusSizedNumber::LIMBS },
>;

pub const PLAINTEXT_SPACE_SCALAR_LIMBS: usize = LargeBiPrimeSizedNumber::LIMBS;
pub const RANDOMNESS_SPACE_SCALAR_LIMBS: usize = LargeBiPrimeSizedNumber::LIMBS;
pub const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize = PaillierModulusSizedNumber::LIMBS;

/// Emulate a circuit-privacy conserving additively homomorphic encryption with
/// `PlaintextGroupElement` as the plaintext group using the Paillier encryption scheme.
impl
    AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        PlaintextGroupElement,
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for EncryptionKey
{
    type PublicParameters = ();

    fn public_parameters(&self) -> Self::PublicParameters {
        Self::PublicParameters::default()
    }

    fn new(
        _encryption_scheme_public_parameters: &Self::PublicParameters,
        _plaintext_group_public_parameters: &<PlaintextGroupElement as GroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
        >>::PublicParameters,
        randomness_group_public_parameters: &RandomnessPublicParameters,
        _ciphertext_group_public_parameters: &CiphertextPublicParameters,
    ) -> super::Result<Self> {
        // TODO: this actually now should always succeed and the check should be in evaluate()

        // In order to assure circuit-privacy, the computation in
        // [`Self::evaluate_linear_combination_with_randomness()`] must not overflow the Paillier
        // message space modulus.
        //
        // This computation is $\Enc(pk, \omega q; \eta) \bigoplus_{i=1}^\ell \left(  a_i \odot
        // \ct_i \right)$, where $\omega$ is uniformly chosen from $[0,\ellq 2^s)$.
        //
        // Thus, with the bound on $q$ being `PLAINTEXT_SPACE_SCALAR_LIMBS`,
        // on the dimension $\ell$ being U64::LIMBS (as `DIMENSION` is of type `usize`),
        // the bound on $\omega$ is therefore `(PLAINTEXT_SPACE_SCALAR_LIMBS +
        // StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS)`.
        //
        // Multiplying $\omega$ by $q$ thus adds an additional `PLAINTEXT_SPACE_SCALAR_LIMBS` to the
        // bound on $\omega$ (hence the multiplication by 2).
        //
        // Now, we have $\ell$ more additions,
        // each bounded to $q^2$ (as both the coefficients and the encrypted messaged of the
        // ciphertexts are bounded by $q$) which at most adds $log(\ell)$ bits, which we can bound
        // again by a `U64`.
        //
        // All of this must be `< LargeBiPrimeSizedNumber::LIMBS`.
        if let Some(evaluation_upper_bound) = PLAINTEXT_SPACE_SCALAR_LIMBS
            .checked_mul(2)
            .and_then(|x| x.checked_add(StatisticalSecuritySizedNumber::LIMBS))
            .and_then(|x| x.checked_add(U64::LIMBS))
            .and_then(|x| x.checked_add(U64::LIMBS))
        {
            if evaluation_upper_bound < LargeBiPrimeSizedNumber::LIMBS {
                return Ok(Self(tiresias::EncryptionKey::new(
                    randomness_group_public_parameters.modulus,
                )));
            }
        }
        // TODO: this is a wrong computation, we need to check it is smaller than the modulus N.
        Err(super::Error::UnsafePublicParameters)
    }

    fn encrypt_with_randomness(
        &self,
        plaintext: &PlaintextGroupElement,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // safe to `unwrap()` here, as encryption always returns a valid element in the
        // ciphertext group

        CiphertextGroupElement::new(
            self.0.encrypt_with_randomness(
                &(&<&PlaintextGroupElement as Into<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>>::into(
                    plaintext,
                ))
                    .into(),
                &randomness.into(),
            ),
            &CiphertextPublicParameters::new(self.0.n2),
        )
        .unwrap()
    }
}

impl
    AdditivelyHomomorphicDecryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        PlaintextGroupElement,
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for DecryptionKey
{
    fn decrypt(&self, ciphertext: &CiphertextGroupElement) -> PlaintextGroupElement {
        PlaintextGroupElement::new(
            self.0.decrypt(&ciphertext.into()),
            odd_moduli::PublicParameters::new(self.0.encryption_key.n),
        )
        .unwrap()
    }
}

impl From<tiresias::DecryptionKey> for DecryptionKey {
    fn from(value: tiresias::DecryptionKey) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{U256, U384};

    use super::*;
    use crate::{ahe, group::secp256k1};

    const N: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    const N2: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("5960383b5378ad0607f0f270ce7fb6dcaba6506f9fc56deeffaf605c9128db8ccf063e2e8221a8bdf82c027741a0303b08eb71fa6225a03df18f24c473dc6d4d3d30eb9c52a233bbfe967d04011b95e8de5bc482c3c217bcfdeb4df6f57af6ba9c6d66c69fb03a70a41fe1e87975c85343ef7d572ca06a0139706b23ed2b73ad72cb1b7e2e41840115651897c8757b3da9af3a60eebb6396ffd193738b4f04aa6ece638cef1bf4e9c45cf57f8debeda8598cbef732484752f5380737ba75ee00bf1b146817b9ab336d0ce5540395377347c653d1c9d272127ff12b9a0721b8ef13ecd8a8379f1b9a358de2af2c4cd97564dbd5328c2fc13d56ee30c8a101d333f5406afb1f4417b49d7a629d5076726877df11f05c998ae365e374a0141f0b99802214532c97c1ebf9faf6e277a8f29dbd8f3eab72266e60a77784249694819e42877a5e826745c97f84a5f37002b74d83fc064cf094be0e706a6710d47d253c4532e6aa4a679a75fa1d860b39085dab03186c67248e6c92223682f58bd41b67143e299329ce3a8045f3a0124c3d0ef9f0f49374d89b37d9c3321feb2ab4117df4f68246724ce41cd765326457968d848afcc0735531e5de7fea88cf2eb35ac68710c6e79d5ad25df6c0393c0267f56e8eac90a52637abe3e606769e70b20560eaf70e0d531b11dca299104fa933f887d85fb5f72386c196e40f559baee356b9");
    const SECRET_KEY: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");

    const RANDOMNESS_PUBLIC_PARAMETERS:
        multiplicative_group_of_integers_modulu_n::PublicParameters<
            { LargeBiPrimeSizedNumber::LIMBS },
        > = multiplicative_group_of_integers_modulu_n::PublicParameters::new(N);
    const CIPHERTEXT_PUBLIC_PARAMETERS:
        multiplicative_group_of_integers_modulu_n::PublicParameters<
            { PaillierModulusSizedNumber::LIMBS },
        > = multiplicative_group_of_integers_modulu_n::PublicParameters::new(N2);

    #[test]
    fn encrypt_decrypts() {
        let encryption_key = EncryptionKey::new(
            (),
            &secp256k1::scalar::PublicParameters::default(),
            &RANDOMNESS_PUBLIC_PARAMETERS,
            &CIPHERTEXT_PUBLIC_PARAMETERS,
        )
        .unwrap();

        let decryption_key = DecryptionKey::from(tiresias::DecryptionKey::new(
            tiresias::EncryptionKey::new(N),
            SECRET_KEY,
        ));

        ahe::tests::encrypt_decrypts(encryption_key, decryption_key, RANDOMNESS_PUBLIC_PARAMETERS)
    }

    #[test]
    fn evaluates() {
        let encryption_key = EncryptionKey::new(
            (),
            &secp256k1::scalar::PublicParameters::default(),
            &RANDOMNESS_PUBLIC_PARAMETERS,
            &CIPHERTEXT_PUBLIC_PARAMETERS,
        )
        .unwrap();

        let decryption_key = DecryptionKey::from(tiresias::DecryptionKey::new(
            tiresias::EncryptionKey::new(N),
            SECRET_KEY,
        ));

        ahe::tests::evaluates(encryption_key, decryption_key, RANDOMNESS_PUBLIC_PARAMETERS)
    }
}
