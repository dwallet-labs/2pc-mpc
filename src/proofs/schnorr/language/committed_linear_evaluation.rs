// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// TODO
// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use core::array;
use std::marker::PhantomData;

use crypto_bigint::{Encoding, NonZero, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    homomorphic_encryption,
    homomorphic_encryption::{
        CiphertextSpaceGroupElement, GroupsPublicParametersAccessors, RandomnessSpaceGroupElement,
    },
    commitment,
    commitment::{multipedersen, HomomorphicCommitmentScheme, MultiPedersen},
    group,
    group::{direct_product, paillier, self_product, GroupElement as _, KnownOrderGroupElement},
    helpers::FlatMapResults,
    proofs,
    proofs::{
        range,
        range::CommitmentSchemeMessageSpaceGroupElement,
        schnorr,
        schnorr::{
            enhanced::{DecomposableWitness, EnhanceableLanguage},
            language,
            proof::SOUND_PROOFS_REPETITIONS,
            language::GroupsPublicParameters,
        },
    },
    traits::Reduce,
    AdditivelyHomomorphicEncryptionKey,
};

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
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Witness Space Group Element of the Committed Linear Evaluation Schnorr Language
pub type WitnessSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> = direct_product::FourWayGroupElement<
    self_product::GroupElement<DIMENSION, EncryptionKey::PlaintextSpaceGroupElement>,
    self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
    EncryptionKey::PlaintextSpaceGroupElement,
    EncryptionKey::RandomnessSpaceGroupElement,
>;

/// The Statement Space Group Element Committed Linear Evaluation Schnorr Language.
pub type StatementSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> = direct_product::GroupElement<
    EncryptionKey::CiphertextSpaceGroupElement,
    self_product::GroupElement<DIMENSION, GroupElement>,
>;

/// The Public Parameters of the Committed Linear Evaluation Schnorr Language.
///
/// In order to prove an affine transformation, set `ciphertexts[0]` to an encryption of one with
/// randomness zero ($\Enc(1; 0)$).
pub type PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> = private::PublicParameters<
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

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<SOUND_PROOFS_REPETITIONS>
    for Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >
{
    type WitnessSpaceGroupElement = WitnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    type StatementSpaceGroupElement = StatementSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    type PublicParameters = PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
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
            MultiPedersen::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        let ciphertexts = language_public_parameters.ciphertexts.map(|value| {
            homomorphic_encryption::CiphertextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                value,
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )
        }).flat_map_results()?;

        let evaluated_ciphertext = encryption_key
            .evaluate_circuit_private_linear_combination_with_randomness(
                witness.coefficients().into(),
                &ciphertexts,
                &group_order,
                witness.mask(),
                witness.encryption_randomness(),
            )?;

        let coefficients: [_; DIMENSION] = (*witness.coefficients()).into();

        let group_order =
            Option::<_>::from(NonZero::new(group_order)).ok_or(proofs::Error::InternalError)?;

        let coefficients = coefficients
            .map(|coefficient| {
                // TODO: here it's ok to go through modulation right?
                let coefficient = coefficient.value().into().reduce(&group_order).into();

                GroupElement::Scalar::new(
                    coefficient,
                    language_public_parameters.scalar_group_public_parameters(),
                )
            })
            .flat_map_results()?;

        let commitment =
            commitment_scheme.commit(&coefficients.into(), witness.commitment_randomness());

        Ok((evaluated_ciphertext, commitment).into())
    }
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        SOUND_PROOFS_REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            paillier::RandomnessSpaceGroupElement,
        >,
    >
    for Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        homomorphic_encryption::paillier::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: &[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        unbounded_witness: &direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            paillier::RandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement> {
        if NUM_RANGE_CLAIMS != RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK {
            return Err(proofs::Error::InvalidParameters);
        }

        let mut decomposed_witness = decomposed_witness.clone().into_iter();

        let coefficients: [[_; RANGE_CLAIMS_PER_SCALAR]; DIMENSION] = array::from_fn(|_| {
            array::from_fn(|_| {
                decomposed_witness
                    .next()
                    .ok_or(proofs::Error::InvalidParameters)
            })
            .flat_map_results()
        })
        .flat_map_results()?;

        let coefficients = coefficients
            .map(|coefficient| {
                <paillier::PlaintextSpaceGroupElement as DecomposableWitness<
                    RANGE_CLAIMS_PER_SCALAR,
                    SCALAR_LIMBS,
                    { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                >>::compose(
                    // TODO: make sure this is safe, e.g. SCALAR_LIMBS >=
                    // COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
                    &coefficient.map(|range_claim| (&range_claim).into()),
                    language_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                    range_claim_bits,
                )
            })
            .flat_map_results()?
            .into();

        let mask: [_; RANGE_CLAIMS_PER_MASK] = array::from_fn(|_| {
            decomposed_witness
                .next()
                .ok_or(proofs::Error::InvalidParameters)
        })
        .flat_map_results()?;

        let mask = <paillier::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_MASK,
            SCALAR_LIMBS,
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            // TODO: make sure this is safe, e.g. SCALAR_LIMBS >=
            // COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
            &mask.map(|range_claim| (&range_claim).into()),
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        let (commitment_randomness, encryption_randomness) = (*unbounded_witness).into();

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
        range_claim_bits: usize,
    ) -> proofs::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            paillier::RandomnessSpaceGroupElement,
        >,
    )> {
        if NUM_RANGE_CLAIMS != (RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK) {
            return Err(proofs::Error::InvalidParameters);
        }

        let (coefficients, commitment_randomness, mask, encryption_randomness) =
            witness.clone().into();

        let coefficients: [_; DIMENSION] = coefficients.into();

        let range_proof_commitment_message = coefficients.into_iter().flat_map(|coefficient| {
            <[_; RANGE_CLAIMS_PER_SCALAR]>::from(coefficient.decompose(range_claim_bits))
        });

        let decomposed_mask: [_; RANGE_CLAIMS_PER_MASK] = mask.decompose(range_claim_bits).into();

        let range_proof_commitment_message: Vec<_> = range_proof_commitment_message
            .chain(decomposed_mask.into_iter())
            .collect();

        let range_proof_commitment_message: [_; NUM_RANGE_CLAIMS] =
            range_proof_commitment_message.try_into().ok().unwrap();

        Ok((
            range_proof_commitment_message.into(),
            (commitment_randomness, encryption_randomness).into(),
        ))
    }
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
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
            >,
        >,
    >
    for private::PublicParameters<
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
            self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CiphertextSpacePublicParameters,
            self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
        >,
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
            homomorphic_encryption::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    >
    private::PublicParameters<
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
        commitment_scheme_public_parameters: commitment::PublicParameters<
            SCALAR_LIMBS,
            MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >,
        ciphertexts: [homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;
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
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    self_product::PublicParameters::<DIMENSION, _>::new(
                        encryption_scheme_public_parameters
                            .plaintext_space_public_parameters()
                            .clone(),
                    ),
                    self_product::PublicParameters::<DIMENSION, _>::new(
                        scalar_group_public_parameters,
                    ),
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
                    self_product::PublicParameters::<DIMENSION, _>::new(group_public_parameters),
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

        &scalar_group_public_parameters.public_parameters
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        &group_public_parameters.public_parameters
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
    fn commitment_randomness(&self) -> &self_product::GroupElement<DIMENSION, Scalar>;
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
        self_product::GroupElement<DIMENSION, Scalar>,
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
    fn commitment_randomness(&self) -> &self_product::GroupElement<DIMENSION, Scalar> {
        let (_, commitment_randomness, ..): (&_, &_, &_, &_) = self.into();

        commitment_randomness
    }
    fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (.., encryption_randomness): (&_, &_, &_, &_) = self.into();

        encryption_randomness
    }
}

pub trait StatementAccessors<
    const DIMENSION: usize,
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    // TODO: name
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement;

    fn commitments(&self) -> &self_product::GroupElement<DIMENSION, GroupElement>;
}

impl<
        const DIMENSION: usize,
        CiphertextSpaceGroupElement: group::GroupElement,
        GroupElement: group::GroupElement,
    > StatementAccessors<DIMENSION, CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<
        CiphertextSpaceGroupElement,
        self_product::GroupElement<DIMENSION, GroupElement>,
    >
{
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn commitments(&self) -> &self_product::GroupElement<DIMENSION, GroupElement> {
        let (_, commitments): (&_, &_) = self.into();

        commitments
    }
}

pub(super) mod private {
    use super::*;

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
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
            >,
        >,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        pub commitment_scheme_public_parameters: multipedersen::PublicParameters<
            DIMENSION,
            GroupElementValue,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,

        #[serde(with = "crate::helpers::const_generic_array_serialization")]
        pub ciphertexts: [CiphertextSpaceValue; DIMENSION],
    }
}

pub type EnhancedProof<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
    UnboundedWitnessSpaceGroupElement,
    RangeProof,
    ProtocolContext,
> = schnorr::enhanced::Proof<
    SOUND_PROOFS_REPETITIONS,
    NUM_RANGE_CLAIMS,
    MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::{array, iter};

    use crypto_bigint::{NonZero, Random, U128, U256, U64};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        homomorphic_encryption::paillier,
        commitment::pedersen,
        group::{ristretto, secp256k1, self_product, Samplable},
        proofs::schnorr::{aggregation, language},
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    // TODO?
    pub(crate) const MASK_LIMBS: usize =
        secp256k1::SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

    pub(crate) const DIMENSION: usize = 2;

    // TODO: it's ok to take next power of two here right
    pub(crate) const RANGE_CLAIMS_PER_MASK: usize =
        { (Uint::<MASK_LIMBS>::BITS / range::bulletproofs::RANGE_CLAIM_BITS).next_power_of_two() };

    pub(crate) const NUM_RANGE_CLAIMS: usize =
        { DIMENSION * RANGE_CLAIMS_PER_SCALAR + RANGE_CLAIMS_PER_MASK };

    pub type Lang = Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        { RANGE_CLAIMS_PER_SCALAR },
        { RANGE_CLAIMS_PER_MASK },
        { DIMENSION },
        secp256k1::GroupElement,
        paillier::EncryptionKey,
    >;

    use crate::proofs::schnorr::language::enhanced::tests::{
        enhanced_language_public_parameters, generate_scalar_plaintext, RANGE_CLAIMS_PER_SCALAR,
    };

    pub(crate) fn public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters = homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();

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

        let pedersen_public_parameters = pedersen::PublicParameters::derive::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
        )
        .unwrap()
        .into();

        let language_public_parameters = PublicParameters::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { DIMENSION },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >::new::<
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

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let coefficients = array::from_fn(|_| generate_scalar_plaintext()).into();

            let first_commitment_randomness = secp256k1::Scalar::sample(
                &language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let second_commitment_randomness = secp256k1::Scalar::sample(
                &language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let mask = Uint::<MASK_LIMBS>::random(&mut OsRng);
            let mask = paillier::PlaintextSpaceGroupElement::new(
                (&mask).into(),
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            )
            .unwrap();

            let encryption_randomness = paillier::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (
                coefficients,
                [first_commitment_randomness, second_commitment_randomness].into(),
                mask,
                encryption_randomness,
            )
                .into()
        })
        .take(batch_size)
        .collect()
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        schnorr::proof::enhanced::tests::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                paillier::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 2)]
    #[case(8, 1)]
    #[case(8, 4)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        schnorr::proof::enhanced::tests::aggregates::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                paillier::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    // TODO: all other tests
}

// TODO: benchmarking
// #[cfg(feature = "benchmarking")]
// mod benches {
//     use criterion::Criterion;
//     use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
//
//     use super::*;
//     use crate::{
//         homomorphic_encryption::paillier,
//         commitment::Pedersen,
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
//
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             c,
//         );
//     }
// }
