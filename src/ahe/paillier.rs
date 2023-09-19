// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{ConcatMixed, Uint, U64};
use group::{
    multiplicative_group_of_integers_modulu_n,
    paillier::{CiphertextGroupElement, RandomnessGroupElement},
};
use serde::{Deserialize, Serialize};
use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::{
    group,
    group::{GroupElement, KnownOrderGroupElement},
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    StatisticalSecuritySizedNumber,
};

#[derive(PartialEq, Clone)]
pub struct EncryptionKey<
    const MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    PlaintextSpaceGroupElement,
>(
    tiresias::EncryptionKey,
    PhantomData<PlaintextSpaceGroupElement>,
);

#[derive(PartialEq)]
pub struct DecryptionKey(tiresias::DecryptionKey);

/// The Public Parameters of the Paillier Additively Homomorphic Encryption Scheme.
#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    PlaintextSpaceGroupElement,
> {
    // The Paillier associated bi-prime $N$
    associated_bi_prime: LargeBiPrimeSizedNumber,
    #[serde(skip_serializing)]
    _plaintext_group_element_choice: PhantomData<PlaintextSpaceGroupElement>,
}

impl<
        const MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        PlaintextSpaceGroupElement,
    > PublicParameters<MASK_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>
{
    pub fn new(associated_bi_prime: LargeBiPrimeSizedNumber) -> Self {
        Self {
            associated_bi_prime,
            _plaintext_group_element_choice: PhantomData,
        }
    }
}

type RandomnessPublicParameters =
    multiplicative_group_of_integers_modulu_n::PublicParameters<{ LargeBiPrimeSizedNumber::LIMBS }>;
type CiphertextPublicParameters = multiplicative_group_of_integers_modulu_n::PublicParameters<
    { PaillierModulusSizedNumber::LIMBS },
>;

/// Emulate a circuit-privacy conserving additively homomorphic encryption with
/// `PlaintextSpaceGroupElement` as the plaintext group using the Paillier encryption scheme.
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
    > for EncryptionKey<MASK_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>
where
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    PlaintextSpaceGroupElement: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: for<'a> From<&'a PlaintextSpaceGroupElement>,
    // In order to ensure circuit-privacy we assure that the mask is a number of the size of the
    // plaintext concated with the statistical security parameter contacted with a U64 (which is a
    // bound on the log of DIMENSION)
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<
        <StatisticalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput,
        MixedOutput = Uint<MASK_LIMBS>,
    >,
{
    type PublicParameters =
        PublicParameters<MASK_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>;

    fn public_parameters(&self) -> Self::PublicParameters {
        Self::PublicParameters {
            associated_bi_prime: self.0.n,
            _plaintext_group_element_choice: PhantomData,
        }
    }

    // TODO: so long as we use tiresias types, we can't assure that the encryption key will be
    // created by calling `new()`. This might cause situations in which circuit-privacy is
    // compromised. We should either use new types or move this code to tirseias.
    fn new(
        encryption_scheme_public_parameters: &Self::PublicParameters,
        _plaintext_group_public_parameters: &PlaintextSpaceGroupElement::PublicParameters,
        _randomness_group_public_parameters: &RandomnessPublicParameters,
        _ciphertext_group_public_parameters: &CiphertextPublicParameters,
    ) -> super::Result<Self> {
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
                return Ok(Self(
                    tiresias::EncryptionKey::new(
                        encryption_scheme_public_parameters.associated_bi_prime,
                    ),
                    PhantomData,
                ));
            }
        }

        Err(super::Error::UnsafePublicParametersError)
    }

    fn encrypt_with_randomness(
        &self,
        plaintext: &PlaintextSpaceGroupElement,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // safe to `unwrap()` here, as encryption always returns a valid element in the
        // ciphertext group

        CiphertextGroupElement::new(
            self.0.encrypt_with_randomness(
                &(&<&PlaintextSpaceGroupElement as Into<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>>::into(
                    plaintext,
                ))
                    .into(),
                &randomness.into(),
            ),
            &CiphertextPublicParameters::new(self.0.n2),
        )
        .unwrap()
    }

    fn evaluate_linear_combination_with_randomness<const DIMENSION: usize>(
        &self,
        coefficients: &[PlaintextSpaceGroupElement; DIMENSION],
        ciphertexts: &[CiphertextGroupElement; DIMENSION],
        mask: &Uint<MASK_LIMBS>,
        randomness: &RandomnessGroupElement,
    ) -> CiphertextGroupElement {
        // Compute:
        //
        // $\ct = \Enc(pk, \omega q; \eta) \bigoplus_{i=1}^\ell \left(  a_i \odot \ct_i
        // \right)$
        //
        // Which is the linear combination masked by an encryption of a masked
        // multiplication of the order $q$ using fresh randomness.
        //
        // This method ensures circuit privacy.

        let plaintext_order = LargeBiPrimeSizedNumber::from(&coefficients[0].order());

        // \Enc(pk, \omega q; \eta): An encryption of a masked multiplication of the order $q$ with
        // fresh randomness.
        let encryption_of_mask_with_fresh_randomness = CiphertextGroupElement::new(
            self.0.encrypt_with_randomness(
                &LargeBiPrimeSizedNumber::from(mask).wrapping_mul(&plaintext_order),
                &randomness.into(),
            ),
            &CiphertextPublicParameters::new(self.0.n2),
        )
        .unwrap();

        coefficients.iter().zip(ciphertexts.iter()).fold(
            encryption_of_mask_with_fresh_randomness,
            |curr, (coefficient, ciphertext)| curr + ciphertext.scalar_mul(&coefficient.into()),
        )
    }
}

impl<
        const MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        PlaintextSpaceGroupElement,
    >
    AdditivelyHomomorphicDecryptionKey<
        MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        { LargeBiPrimeSizedNumber::LIMBS },
        { PaillierModulusSizedNumber::LIMBS },
        PlaintextSpaceGroupElement,
        RandomnessGroupElement,
        CiphertextGroupElement,
    > for DecryptionKey
where
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    PlaintextSpaceGroupElement:
        From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>> + From<LargeBiPrimeSizedNumber>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: for<'a> From<&'a PlaintextSpaceGroupElement>,
    // In order to ensure circuit-privacy we assure that the mask is a number of the size of the
    // plaintext concated with the statistical security parameter contacted with a U64 (which is a
    // bound on the log of DIMENSION)
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<
        <StatisticalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput,
        MixedOutput = Uint<MASK_LIMBS>,
    >,
{
    fn decrypt(&self, ciphertext: &CiphertextGroupElement) -> PlaintextSpaceGroupElement {
        self.0.decrypt(&ciphertext.into()).into()
    }
}
