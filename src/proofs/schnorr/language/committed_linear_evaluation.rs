// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

// TODO
// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;

use core::array;
use std::marker::PhantomData;

use crypto_bigint::{Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    ahe,
    ahe::{
        CiphertextSpaceGroupElement, GroupsPublicParametersAccessors, RandomnessSpaceGroupElement,
    },
    commitments,
    commitments::{pedersen, HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        GroupElement as _, KnownOrderGroupElement,
    },
    helpers::flat_map_results,
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            enhanced::{ConstrainedWitnessGroupElement, DecomposableWitness, EnhanceableLanguage},
            language,
            language::GroupsPublicParameters,
        },
    },
    AdditivelyHomomorphicEncryptionKey,
};

pub const REPETITIONS: usize = 1;

/// Committed Linear Evaluation Schnorr Language
///
/// This language allows to prove a linear combination have been homomorphically evaluated on a
/// vector of ciphertexts. If one wishes to prove an affine evaluation instead of a linear one,
/// as is required in the paper, the first ciphertexts should be set to an encryption of one with
/// randomness zero ($\Enc(1; 0)$). This would allow the first coefficient to be evaluated as the
/// free variable of an affine transformation.
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group and additively homomorphic
/// encryption scheme in this language, we choose to provide a fully generic
/// implementation.
///
/// However knowledge-soundness proofs are group and encryption scheme dependent, and thus we can
/// only assure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
///
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier`.
pub type Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> = private::Language<
    0,
    0,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    SCALAR_LIMBS,
    DIMENSION,
    GroupElement,
    EncryptionKey,
>;

pub type EnhancedLanguage<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    CommitmentScheme,
    GroupElement,
    EncryptionKey,
> = schnorr::enhanced::EnhancedLanguage<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    SCALAR_LIMBS,
    CommitmentScheme,
    ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    private::Language<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >,
>;

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<REPETITIONS>
    for private::Language<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >
where
    group::Value<GroupElement::Scalar>: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
{
    type WitnessSpaceGroupElement = direct_product::FourWayGroupElement<
        self_product::GroupElement<DIMENSION, EncryptionKey::PlaintextSpaceGroupElement>,
        GroupElement::Scalar,
        EncryptionKey::PlaintextSpaceGroupElement,
        EncryptionKey::RandomnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement =
        direct_product::GroupElement<EncryptionKey::CiphertextSpaceGroupElement, GroupElement>;

    type PublicParameters = PublicParameters<
        DIMENSION,
        group::PublicParameters<GroupElement::Scalar>,
        GroupElement::PublicParameters,
        GroupElement::Value,
        group::PublicParameters<EncryptionKey::PlaintextSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::RandomnessSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::CiphertextSpaceGroupElement>,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        EncryptionKey::PublicParameters,
    >;

    const NAME: &'static str = "Committed Linear Evaluation";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> crate::proofs::Result<Self::StatementSpaceGroupElement> {
        let group_order = GroupElement::Scalar::order_from_public_parameters(
            language_public_parameters.scalar_group_public_parameters(),
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let commitment_scheme =
            Pedersen::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        let ciphertexts =
            flat_map_results(
                language_public_parameters.ciphertexts.clone().map(|value| {
                    ahe::CiphertextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                        value,
                        language_public_parameters.encryption_scheme_public_parameters.ciphertext_space_public_parameters())
                }),
            )?;

        let evaluated_ciphertext = encryption_key
            .evaluate_circuit_private_linear_combination_with_randomness(
                witness.coefficients().into(),
                &ciphertexts,
                &group_order,
                witness.mask(),
                witness.encryption_randomness(),
            )?;

        let coefficients: [_; DIMENSION] = (*witness.coefficients()).into();

        // TODO: here it's ok to go through modulation right?
        let coefficients = flat_map_results(coefficients.map(|coefficient| {
            GroupElement::Scalar::new(
                coefficient.value().into(),
                language_public_parameters.scalar_group_public_parameters(),
            )
        }))?;

        let commitment =
            commitment_scheme.commit(&coefficients.into(), witness.commitment_randomness());

        Ok((evaluated_ciphertext, commitment).into())
    }
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        direct_product::GroupElement<
            GroupElement::Scalar,
            ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >,
    >
    for private::Language<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    group::Value<GroupElement::Scalar>: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
{
    fn compose_witness(
        constrained_witness: &ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
        unbounded_witness: &direct_product::GroupElement<
            GroupElement::Scalar,
            RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement> {
        if NUM_RANGE_CLAIMS != RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK {
            return Err(proofs::Error::InvalidParameters);
        }

        let constrained_witness: [_; NUM_RANGE_CLAIMS] = constrained_witness.clone().into();
        let mut constrained_witness = constrained_witness.into_iter();

        let coefficients: [[_; RANGE_CLAIMS_PER_SCALAR]; DIMENSION] =
            flat_map_results(array::from_fn(|_| {
                flat_map_results(array::from_fn(|_| {
                    constrained_witness
                        .next()
                        .ok_or(proofs::Error::InvalidParameters)
                }))
            }))?;

        let coefficients = flat_map_results(coefficients.map(|coefficient| {
            <EncryptionKey::PlaintextSpaceGroupElement as DecomposableWitness<
                RANGE_CLAIMS_PER_SCALAR,
                SCALAR_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
            >>::compose(
                &coefficient.into(),
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
                crypto_bigint::U128::BITS, // TODO
            )
        }))?
        .into();

        let mask: [_; RANGE_CLAIMS_PER_MASK] = flat_map_results(array::from_fn(|_| {
            constrained_witness
                .next()
                .ok_or(proofs::Error::InvalidParameters)
        }))?;

        let mask = <EncryptionKey::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_MASK,
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
        >>::compose(
            &mask.into(),
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            crypto_bigint::U128::BITS, // TODO
        )?;

        let (commitment_randomness, encryption_randomness) = unbounded_witness.clone().into();

        Ok((
            coefficients,
            commitment_randomness,
            mask,
            encryption_randomness,
        )
            .into())
    }

    fn decompose_witness(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<(
        ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
        direct_product::GroupElement<
            GroupElement::Scalar,
            RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >,
    )> {
        if NUM_RANGE_CLAIMS != RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK {
            return Err(proofs::Error::InvalidParameters);
        }

        let (coefficients, commitment_randomness, mask, encryption_randomness) =
            witness.clone().into();

        let coefficients: [_; DIMENSION] = coefficients.into();

        let constrained_witness = coefficients.into_iter().flat_map(|coefficient| {
            <[_; RANGE_CLAIMS_PER_SCALAR]>::from(coefficient.decompose(crypto_bigint::U128::BITS))
        });

        let decomposed_mask: [_; RANGE_CLAIMS_PER_MASK] =
            mask.decompose(crypto_bigint::U128::BITS).into();

        let constrained_witness: Vec<_> = constrained_witness
            .chain(decomposed_mask.into_iter())
            .collect();

        let constrained_witness: [_; NUM_RANGE_CLAIMS] =
            constrained_witness.try_into().ok().unwrap();

        Ok((
            constrained_witness.into(),
            (commitment_randomness, encryption_randomness).into(),
        ))
    }
}

/// The Public Parameters of the Committed Linear Evaluation Schnorr Language
///
/// In order to prove an affine transformation, set `ciphertexts[0]` to an encryption of one with
/// randomness zero ($\Enc(1; 0)$).
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const DIMENSION: usize,
    ScalarPublicParameters,
    GroupPublicParameters,
    GroupElementValue,
    PlaintextSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CiphertextSpacePublicParameters,
    CiphertextSpaceValue: Serialize,
    EncryptionKeyPublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::FourWayPublicParameters<
            self_product::PublicParameters<DIMENSION, PlaintextSpacePublicParameters>,
            ScalarPublicParameters,
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    >,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub commitment_scheme_public_parameters: pedersen::PublicParameters<
        DIMENSION,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,

    #[serde(with = "crate::helpers::const_generic_array_serialization")]
    pub ciphertexts: [CiphertextSpaceValue; DIMENSION],
}

impl<
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::FourWayPublicParameters<
                self_product::PublicParameters<DIMENSION, PlaintextSpacePublicParameters>,
                ScalarPublicParameters,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
    >
    for PublicParameters<
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::FourWayPublicParameters<
            self_product::PublicParameters<DIMENSION, PlaintextSpacePublicParameters>,
            ScalarPublicParameters,
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters: AsRef<
            ahe::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    >
    PublicParameters<
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
{
    pub fn new<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement,
        EncryptionKey,
    >(
        scalar_group_public_parameters: ScalarPublicParameters,
        group_public_parameters: GroupPublicParameters,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        commitment_scheme_public_parameters: commitments::PublicParameters<
            SCALAR_LIMBS,
            Pedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >,
        ciphertexts: [ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;
            DIMENSION],
    ) -> Self
    where
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + KnownOrderGroupElement<SCALAR_LIMBS>,
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = EncryptionKeyPublicParameters,
        >,
        EncryptionKey::PlaintextSpaceGroupElement:
            group::GroupElement<PublicParameters = PlaintextSpacePublicParameters>,
        EncryptionKey::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        EncryptionKey::CiphertextSpaceGroupElement: group::GroupElement<
            Value = CiphertextSpaceValue,
            PublicParameters = CiphertextSpacePublicParameters,
        >,
    {
        Self {
            groups_public_parameters:
                GroupsPublicParameters {
                    witness_space_public_parameters:
                        (
                            self_product::PublicParameters::<
                                DIMENSION,
                                PlaintextSpacePublicParameters,
                            >::new(
                                encryption_scheme_public_parameters
                                    .plaintext_space_public_parameters()
                                    .clone(),
                            ),
                            scalar_group_public_parameters,
                            encryption_scheme_public_parameters
                                .plaintext_space_public_parameters()
                                .clone(),
                            encryption_scheme_public_parameters
                                .randomness_space_public_parameters()
                                .clone(),
                        )
                            .into(),
                    statement_space_public_parameters: (
                        encryption_scheme_public_parameters
                            .ciphertext_space_public_parameters()
                            .clone(),
                        group_public_parameters,
                    )
                        .into(),
                },
            encryption_scheme_public_parameters,
            commitment_scheme_public_parameters,
            ciphertexts,
        }
    }

    pub fn plaintext_space_public_parameters(&self) -> &PlaintextSpacePublicParameters {
        let (_, _, plaintext_space_public_parameters, _): (&_, &_, &_, &_) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        plaintext_space_public_parameters
    }

    pub fn randomness_space_public_parameters(&self) -> &RandomnessSpacePublicParameters {
        let (_, randomness_space_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        randomness_space_public_parameters
    }

    pub fn scalar_group_public_parameters(&self) -> &ScalarPublicParameters {
        let (_, scalar_group_public_parameters, ..): (&_, &_, &_, &_) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        scalar_group_public_parameters
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        group_public_parameters
    }
}

pub trait WitnessAccessors<
    const DIMENSION: usize,
    Scalar: group::GroupElement,
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn coefficients(&self) -> &self_product::GroupElement<DIMENSION, PlaintextSpaceGroupElement>;

    fn mask(&self) -> &PlaintextSpaceGroupElement;
    fn commitment_randomness(&self) -> &Scalar;
    fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        const DIMENSION: usize,
        Scalar: group::GroupElement,
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<DIMENSION, Scalar, PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::FourWayGroupElement<
        self_product::GroupElement<DIMENSION, PlaintextSpaceGroupElement>,
        Scalar,
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
    >
{
    fn coefficients(&self) -> &self_product::GroupElement<DIMENSION, PlaintextSpaceGroupElement> {
        let (coefficients, ..): (&_, &_, &_, &_) = self.into();

        coefficients
    }

    fn mask(&self) -> &PlaintextSpaceGroupElement {
        let (_, _, mask, _): (&_, &_, &_, &_) = self.into();

        mask
    }
    fn commitment_randomness(&self) -> &Scalar {
        let (_, commitment_randomness, ..): (&_, &_, &_, &_) = self.into();

        commitment_randomness
    }
    fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (.., encryption_randomness): (&_, &_, &_, &_) = self.into();

        encryption_randomness
    }
}

pub trait StatementAccessors<
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    // TODO: name
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement;

    fn commitment(&self) -> &GroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement, GroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>
{
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn commitment(&self) -> &GroupElement {
        let (_, commitment): (&_, &_) = self.into();

        commitment
    }
}

pub(super) mod private {
    use super::*;

    #[derive(Clone, Serialize, Deserialize, PartialEq)]
    pub struct Language<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement,
        EncryptionKey,
    > {
        _group_element_choice: PhantomData<GroupElement>,
        _encryption_key_choice: PhantomData<EncryptionKey>,
    }
}

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::{array, iter};

    use crypto_bigint::{NonZero, Random, U128, U256, U64};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        ahe::paillier,
        commitments::Pedersen,
        group::{ristretto, secp256k1, self_product, Samplable},
        proofs::schnorr::{
            aggregation,
            enhanced::tests::{scalar_lower_bound, scalar_upper_bound},
            language,
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    // TODO?
    pub(crate) const MASK_LIMBS: usize =
        secp256k1::SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

    pub(crate) const DIMENSION: usize = 2;

    pub(crate) const RANGE_CLAIMS_PER_MASK: usize = 3; // TODO

    pub(crate) const NUM_RANGE_CLAIMS: usize =
        { DIMENSION * RANGE_CLAIMS_PER_SCALAR + RANGE_CLAIMS_PER_MASK };

    pub type Lang = Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { U256::LIMBS },
        { DIMENSION },
        secp256k1::GroupElement,
        paillier::EncryptionKey,
    >;

    pub type EnhancedLang = EnhancedLanguage<
        { NUM_RANGE_CLAIMS },
        { RANGE_CLAIMS_PER_SCALAR },
        { RANGE_CLAIMS_PER_MASK },
        { secp256k1::SCALAR_LIMBS },
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        { DIMENSION },
        Pedersen<
            { NUM_RANGE_CLAIMS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >,
        secp256k1::GroupElement,
        paillier::EncryptionKey,
    >;

    use crate::{
        commitments::pedersen,
        group::SamplableWithin,
        proofs::schnorr::enhanced::tests::{
            enhanced_language_public_parameters, RANGE_CLAIMS_PER_SCALAR,
        },
    };

    fn lower_bound() -> direct_product::FourWayGroupElement<
        self_product::GroupElement<DIMENSION, paillier::PlaintextSpaceGroupElement>,
        secp256k1::Scalar,
        paillier::PlaintextSpaceGroupElement,
        paillier::RandomnessSpaceGroupElement,
    > {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let commitment_randomness_lower_bound =
            secp256k1::Scalar::lower_bound(&secp256k1_scalar_public_parameters).unwrap();

        let mask_lower_bound = paillier::PlaintextSpaceGroupElement::new(
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::ZERO,
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let encryption_randomness_lower_bound = paillier::RandomnessSpaceGroupElement::lower_bound(
            paillier_public_parameters.randomness_space_public_parameters(),
        )
        .unwrap();

        (
            [scalar_lower_bound(); DIMENSION].into(),
            commitment_randomness_lower_bound,
            mask_lower_bound,
            encryption_randomness_lower_bound,
        )
            .into()
    }

    fn upper_bound() -> direct_product::FourWayGroupElement<
        self_product::GroupElement<DIMENSION, paillier::PlaintextSpaceGroupElement>,
        secp256k1::Scalar,
        paillier::PlaintextSpaceGroupElement,
        paillier::RandomnessSpaceGroupElement,
    > {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let commitment_randomness_upper_bound =
            secp256k1::Scalar::upper_bound(&secp256k1_scalar_public_parameters).unwrap();

        let mask_upper_bound = paillier::PlaintextSpaceGroupElement::new(
            (&Uint::<{ MASK_LIMBS }>::MAX).into(),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let encryption_randomness_upper_bound = paillier::RandomnessSpaceGroupElement::upper_bound(
            paillier_public_parameters.randomness_space_public_parameters(),
        )
        .unwrap();

        (
            [scalar_upper_bound(); DIMENSION].into(),
            commitment_randomness_upper_bound,
            mask_upper_bound,
            encryption_randomness_upper_bound,
        )
            .into()
    }

    pub(crate) fn public_parameters() -> language::PublicParameters<REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let plaintext = paillier::PlaintextSpaceGroupElement::new(
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64(42u64),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let ciphertexts = array::from_fn(|_| u64::from(U64::random(&mut OsRng)))
            .map(Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64)
            .map(|plaintext| {
                paillier::PlaintextSpaceGroupElement::new(
                    plaintext,
                    paillier_public_parameters.plaintext_space_public_parameters(),
                )
                .unwrap()
            })
            .map(|plaintext| {
                paillier_encryption_key
                    .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
                    .unwrap()
                    .1
                    .value()
            });

        // TODO: move this shared logic somewhere e.g. DRY
        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let message_generators = array::from_fn(|_| {
            let generator =
                secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap()
                    * generator;

            generator.value()
        });

        let randomness_generator =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap()
                * generator;

        // TODO: this is not safe; we need a proper way to derive generators
        let pedersen_public_parameters = pedersen::PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
            message_generators,
            randomness_generator.value(),
        );

        let language_public_parameters = PublicParameters::new::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            paillier_public_parameters,
            pedersen_public_parameters,
            ciphertexts,
        );

        language_public_parameters
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        language::tests::valid_proof_verifies::<REPETITIONS, Lang>(
            Some((lower_bound(), upper_bound())),
            language_public_parameters,
            batch_size,
        );
    }

    // TODO: all other tests
}

// #[cfg(feature = "benchmarking")]
// mod benches {
//     use criterion::Criterion;
//     use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
//
//     use super::*;
//     use crate::{
//         ahe::paillier,
//         commitments::Pedersen,
//         group::{ristretto, secp256k1},
//         proofs::{
//             range,
//             schnorr::{
//                 aggregation, language,
//                 language::committed_linear_evaluation::{
//                     tests::{
//                         public_parameters, Lang, DIMENSION, MASK_LIMBS, NUM_RANGE_CLAIMS,
//                         RANGE_CLAIMS_PER_MASK,
//                     },
//                     REPETITIONS,
//                 },
//             },
//         },
//         ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
//     };
//
//     pub(crate) fn benchmark(c: &mut Criterion) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::benchmark::<REPETITIONS, Lang>(language_public_parameters.clone(), None, c);
//
//         range::benchmark::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             { NUM_RANGE_CLAIMS },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             c,
//         );
//     }
// }
