// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{ConcatMixed, Uint, U64};
use group::{
    multiplicative_group_of_integers_modulu_n,
    paillier::{CiphertextGroupElement, RandomnessGroupElement},
};
use serde::{Deserialize, Serialize};
use tiresias::{DecryptionKey, EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::{
    group,
    group::{GroupElement, KnownOrderGroupElement},
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    StatisticalSecuritySizedNumber,
};

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
    > for EncryptionKey
where
    PlaintextSpaceGroupElement: KnownOrderGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        Value = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >,
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
            associated_bi_prime: self.n,
            _plaintext_group_element_choice: PhantomData,
        }
    }

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
        // ciphertexts are bounded by $q$ - TODO: how is this enforced in the paper? and perhaps we
        // should also enforce this here by bounding the `CiphertextGroupElement` to
        // PLAINTEXT_SPACE_SCALAR_LIMBS.) which at most adds $log(\ell)$ bits, which we can bound
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
                return Ok(EncryptionKey::new(
                    encryption_scheme_public_parameters.associated_bi_prime,
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
            self.encrypt_with_randomness(&(&plaintext.value()).into(), &randomness.into()),
            &CiphertextPublicParameters::new(self.n2),
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

        // TODO: assure bound computations are correct.
        // TODO: this throws an exception if coefficients is empty, maybe also check that N is right
        // in new()
        let plaintext_order = LargeBiPrimeSizedNumber::from(&coefficients[0].order());

        // \Enc(pk, \omega q; \eta): An encryption of a masked multiplication of the order $q$ with
        // fresh randomness.
        let encryption_of_mask_with_fresh_randomness = CiphertextGroupElement::new(
            self.encrypt_with_randomness(
                &LargeBiPrimeSizedNumber::from(mask).wrapping_mul(&plaintext_order),
                &randomness.into(),
            ),
            &CiphertextPublicParameters::new(self.n2),
        )
        .unwrap();

        coefficients.iter().zip(ciphertexts.iter()).fold(
            encryption_of_mask_with_fresh_randomness,
            |curr, (coefficient, ciphertext)| curr + ciphertext.scalar_mul(&coefficient.value()),
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
        EncryptionKey,
    > for DecryptionKey
where
    PlaintextSpaceGroupElement: KnownOrderGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        Value = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >,
    PlaintextSpaceGroupElement: From<LargeBiPrimeSizedNumber>,
    // In order to ensure circuit-privacy we assure that the mask is a number of the size of the
    // plaintext concated with the statistical security parameter contacted with a U64 (which is a
    // bound on the log of DIMENSION)
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: ConcatMixed<
        <StatisticalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput,
        MixedOutput = Uint<MASK_LIMBS>,
    >,
{
    fn decrypt(&self, ciphertext: &CiphertextGroupElement) -> PlaintextSpaceGroupElement {
        self.decrypt(&ciphertext.into()).into()
    }
}
