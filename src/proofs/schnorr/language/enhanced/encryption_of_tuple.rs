// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Uint};
use language::GroupsPublicParameters;
use schnorr::language;
use serde::{Deserialize, Serialize};

use super::EnhancedLanguage;
use crate::{
    ahe,
    ahe::GroupsPublicParametersAccessors as _,
    commitments::{GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme},
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        BoundedGroupElement, GroupElement as _, KnownOrderScalar, Samplable,
    },
    proofs,
    proofs::{
        range, range::CommitmentPublicParametersAccessor as _, schnorr, schnorr::aggregation,
    },
    AdditivelyHomomorphicEncryptionKey, ComputationalSecuritySizedNumber,
    StatisticalSecuritySizedNumber,
};

pub(crate) const REPETITIONS: usize = 1;

/// Encryption of a Tuple Schnorr Language
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
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Language<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
    _range_proof_choice: PhantomData<RangeProof>,
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof,
    > schnorr::Language<REPETITIONS>
    for Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Mul<Scalar, Output = Scalar>
        + for<'r> Mul<&'r Scalar, Output = Scalar>
        + Copy,
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<super::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
    >,
{
    type WitnessSpaceGroupElement = super::EnhancedLanguageWitness<
        REPETITIONS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self,
    >;

    type StatementSpaceGroupElement = super::EnhancedLanguageStatement<
        REPETITIONS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self,
    >;

    type PublicParameters = PublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        Scalar::PublicParameters,
        range::CommitmentSchemeRandomnessSpacePublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >,
        range::CommitmentSchemeCommitmentSpacePublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >,
        RangeProof::PublicParameters,
        ahe::RandomnessSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        ahe::CiphertextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        ahe::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;
    const NAME: &'static str = "Encryption of a Tuple";
    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        // TODO: variable names
        let (scalar_witness_mask_base_element, commitment_randomness, encryptions_randomnesses) =
            witness.into();

        let [encryption_randomness, evaluation_randomness]: &[ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;
             2] = encryptions_randomnesses.into();

        let scalar_group_order = Scalar::order_from_public_parameters(
            &language_public_parameters.scalar_group_public_parameters,
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(
            language_public_parameters
                .range_proof_public_parameters
                .commitment_public_parameters(),
        )?;

        let ciphertext =
            ahe::CiphertextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                language_public_parameters.ciphertext,
                &language_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        let scalar_witness_mask_base: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR] = (*scalar_witness_mask_base_element).into();

        let scalar_witness_mask_base: [Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR] =
            scalar_witness_mask_base.map(|element| Uint::<WITNESS_MASK_LIMBS>::from(element));

        let scalar: Scalar = super::witness_mask_base_to_scalar::<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            SCALAR_LIMBS,
            Scalar,
        >(
            scalar_witness_mask_base,
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        let scalar_plaintext: ahe::PlaintextSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        > = super::witness_mask_base_to_scalar::<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            ahe::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >(
            scalar_witness_mask_base,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;

        let scalar_commitment_message = range::CommitmentSchemeMessageSpaceGroupElement::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >::new(
            scalar_witness_mask_base_element.value().into(),
            &language_public_parameters
                .range_proof_public_parameters
                .commitment_public_parameters()
                .message_space_public_parameters(),
        )?;

        // TODO: Need to check that WITNESS_MASK_LIMBS is actually in a size fitting the range proof
        // commitment scheme without going through modulation, and to implement `From` to
        // transition.
        Ok((
            commitment_scheme.commit(&scalar_commitment_message, commitment_randomness),
            [
                encryption_key.encrypt_with_randomness(&scalar_plaintext, encryption_randomness),
                encryption_key.evaluate_circuit_private_linear_combination_with_randomness(
                    &[scalar_plaintext],
                    &[ciphertext],
                    &scalar_group_order,
                    &scalar_plaintext.neutral(),
                    evaluation_randomness,
                )?,
            ]
            .into(),
        )
            .into())
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar: group::GroupElement,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof,
    >
    EnhancedLanguage<
        REPETITIONS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
    >
    for Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Mul<Scalar, Output = Scalar>
        + for<'r> Mul<&'r Scalar, Output = Scalar>
        + Copy,
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<super::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
    >,
{
    type UnboundedWitnessSpaceGroupElement = self_product::GroupElement<
        2,
        ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;

    type RemainingStatementSpaceGroupElement = self_product::GroupElement<
        2,
        ahe::CiphertextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;

    type RangeProof = RangeProof;
}

/// The Public Parameters of the Encryption of a Tuple Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const WITNESS_MASK_LIMBS: usize,
    ScalarPublicParameters,
    RangeProofCommitmentRandomnessSpacePublicParameters,
    RangeProofCommitmentSpacePublicParameters,
    RangeProofPublicParameters,
    EncryptionRandomnessPublicParameters,
    CiphertextPublicParameters,
    EncryptionKeyPublicParameters,
    CiphertextSpaceValue,
> where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    pub groups_public_parameters: super::GroupsPublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        self_product::PublicParameters<2, EncryptionRandomnessPublicParameters>,
        self_product::PublicParameters<2, CiphertextPublicParameters>,
    >,
    pub range_proof_public_parameters: RangeProofPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub ciphertext: CiphertextSpaceValue,
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const WITNESS_MASK_LIMBS: usize,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters: Clone,
        EncryptionRandomnessPublicParameters: Clone,
        CiphertextPublicParameters: Clone,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    PublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        EncryptionRandomnessPublicParameters,
        CiphertextPublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    pub fn new<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement: group::GroupElement,
        EncryptionKey,
        RangeProof,
    >(
        scalar_group_public_parameters: Scalar::PublicParameters,
        range_proof_public_parameters: RangeProof::PublicParameters,
        encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
        ciphertext: ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    ) -> Self
    where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + KnownOrderScalar<SCALAR_LIMBS>
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Mul<Scalar, Output = Scalar>
            + for<'r> Mul<&'r Scalar, Output = Scalar>
            + Copy,
        Scalar::Value: From<Uint<SCALAR_LIMBS>>,
        range::CommitmentSchemeMessageSpaceValue<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >: From<super::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
        RangeProof: proofs::RangeProof<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            PublicParameters = RangeProofPublicParameters,
        >,
        range::CommitmentSchemeRandomnessSpaceGroupElement<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >: group::GroupElement<
            PublicParameters = RangeProofCommitmentRandomnessSpacePublicParameters,
        >,
        range::CommitmentSchemeCommitmentSpaceGroupElement<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >: group::GroupElement<PublicParameters = RangeProofCommitmentSpacePublicParameters>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = EncryptionKeyPublicParameters,
        >,
        EncryptionKey::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = EncryptionRandomnessPublicParameters>,
        EncryptionKey::CiphertextSpaceGroupElement: group::GroupElement<
            Value = CiphertextSpaceValue,
            PublicParameters = CiphertextPublicParameters,
        >,
        EncryptionKeyPublicParameters: AsRef<
            ahe::GroupsPublicParameters<
                ahe::PlaintextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
                ahe::RandomnessSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
                ahe::CiphertextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
            >,
        >,
    {
        // TODO: is this the right value? must be for everything?
        let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
            + ComputationalSecuritySizedNumber::BITS
            + StatisticalSecuritySizedNumber::BITS;

        let unbounded_witness_space_public_parameters = self_product::PublicParameters::<2, _>::new(
            encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let remaining_statement_space_public_parameters =
            self_product::PublicParameters::<2, _>::new(
                encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters()
                    .clone(),
            );

        Self {
            groups_public_parameters: super::GroupsPublicParameters::<
                RANGE_CLAIMS_PER_SCALAR,
                WITNESS_MASK_LIMBS,
                RangeProofCommitmentRandomnessSpacePublicParameters,
                RangeProofCommitmentSpacePublicParameters,
                self_product::PublicParameters<2, EncryptionRandomnessPublicParameters>,
                self_product::PublicParameters<2, CiphertextPublicParameters>,
            >::new::<
                REPETITIONS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                Language<
                    SCALAR_LIMBS,
                    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    RANGE_CLAIM_LIMBS,
                    WITNESS_MASK_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    Scalar,
                    GroupElement,
                    EncryptionKey,
                    RangeProof,
                >,
            >(
                range_proof_public_parameters.clone(),
                unbounded_witness_space_public_parameters,
                remaining_statement_space_public_parameters,
                sampling_bit_size,
            ),
            range_proof_public_parameters,
            encryption_scheme_public_parameters,
            scalar_group_public_parameters,
            ciphertext,
        }
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const WITNESS_MASK_LIMBS: usize,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        EncryptionRandomnessPublicParameters,
        CiphertextPublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    AsRef<
        super::GroupsPublicParameters<
            RANGE_CLAIMS_PER_SCALAR,
            WITNESS_MASK_LIMBS,
            RangeProofCommitmentRandomnessSpacePublicParameters,
            RangeProofCommitmentSpacePublicParameters,
            self_product::PublicParameters<2, EncryptionRandomnessPublicParameters>,
            self_product::PublicParameters<2, CiphertextPublicParameters>,
        >,
    >
    for PublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        EncryptionRandomnessPublicParameters,
        CiphertextPublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &super::GroupsPublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        self_product::PublicParameters<2, EncryptionRandomnessPublicParameters>,
        self_product::PublicParameters<2, CiphertextPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

/// The Witness Space Group Element of an Encryption of a Tuple Schnorr Language.
pub type WitnessSpaceGroupElement<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
> = language::WitnessSpaceGroupElement<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
>;

/// The Statement Space Group Element of an Encryption of a Tuple Schnorr Language.
pub type StatementSpaceGroupElement<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
> = language::StatementSpaceGroupElement<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
>;

/// The Public Parameters of an Encryption of a Tuple Schnorr Language.
pub type LanguagePublicParameters<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
> = language::PublicParameters<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
>;

/// An Encryption of a Tuple Schnorr Proof.
pub type Proof<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
    ProtocolContext,
> = schnorr::Proof<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
    ProtocolContext,
>;

/// An Encryption of a Tuple Schnorr Proof Aggregation Commitment Round Party.
pub type ProofAggregationCommitmentRoundParty<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
    ProtocolContext,
> = aggregation::commitment_round::Party<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
    ProtocolContext,
>;

/// An Encryption of a Tuple Schnorr Proof Aggregation Decommitment Round Party.
pub type ProofAggregationDecommitmentRoundParty<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
    ProtocolContext,
> = aggregation::decommitment_round::Party<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
    ProtocolContext,
>;

/// An Encryption of a Tuple Schnorr Proof Aggregation Decommitment.
pub type Decommitment<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
> = aggregation::decommitment_round::Decommitment<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
>;

/// An Encryption of a Tuple Schnorr Proof Aggregation Proof Share Round Party.
pub type ProofAggregationProofShareRoundParty<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
    ProtocolContext,
> = aggregation::proof_share_round::Party<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
    ProtocolContext,
>;

/// An Encryption of a Tuple Schnorr Proof Aggregation Proof Share.
pub type ProofShare<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
> = aggregation::proof_share_round::ProofShare<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
>;

/// An Encryption of a Tuple Schnorr Proof Aggregation Proof Aggregation Round Party.
pub type ProofAggregationProofAggregationRoundParty<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
    ProtocolContext,
> = aggregation::proof_aggregation_round::Party<
    REPETITIONS,
    Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
    ProtocolContext,
>;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::array;

    use crypto_bigint::{NonZero, Random};
    use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        ahe::paillier,
        group::{ristretto, secp256k1, self_product},
        proofs::{
            range,
            range::bulletproofs,
            schnorr::{aggregation, language},
            RangeProof,
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub(crate) type Lang = Language<
        { secp256k1::SCALAR_LIMBS },
        { ristretto::SCALAR_LIMBS },
        RANGE_CLAIMS_PER_SCALAR,
        { range::bulletproofs::RANGE_CLAIM_LIMBS },
        { WITNESS_MASK_LIMBS },
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        paillier::EncryptionKey,
        bulletproofs::RangeProof,
    >;

    pub(crate) fn public_parameters() -> (
        language::PublicParameters<REPETITIONS, Lang>,
        language::enhanced::RangeProofPublicParameters<
            REPETITIONS,
            { ristretto::SCALAR_LIMBS },
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Lang,
        >,
    ) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            range::bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let plaintext = paillier::PlaintextGroupElement::new(
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64(42u64),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let ciphertext = paillier_encryption_key
            .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
            .unwrap()
            .1
            .value();

        let language_public_parameters = PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            paillier::EncryptionKey,
            bulletproofs::RangeProof,
        >(
            secp256k1_scalar_public_parameters,
            bulletproofs_public_parameters.clone(),
            paillier_public_parameters,
            ciphertext,
        );

        (language_public_parameters, bulletproofs_public_parameters)
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let (language_public_parameters, range_proof_public_parameters) = public_parameters();

        language::enhanced::tests::valid_proof_verifies::<
            REPETITIONS,
            { ristretto::SCALAR_LIMBS },
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Lang,
        >(
            &language_public_parameters,
            &range_proof_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let (language_public_parameters, _) = public_parameters();
        let witnesses = language::enhanced::tests::generate_witnesses_for_aggregation::<
            REPETITIONS,
            { ristretto::SCALAR_LIMBS },
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Lang,
        >(&language_public_parameters, number_of_parties, batch_size);

        aggregation::tests::aggregates::<REPETITIONS, Lang>(&language_public_parameters, witnesses)
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
        let (language_public_parameters, range_proof_public_parameters) = public_parameters();

        language::enhanced::tests::proof_with_out_of_range_witness_fails::<
            REPETITIONS,
            { ristretto::SCALAR_LIMBS },
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Lang,
        >(
            &language_public_parameters,
            &range_proof_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let (language_public_parameters, _) = public_parameters();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        language::tests::invalid_proof_fails_verification::<REPETITIONS, Lang>(
            None,
            None,
            language_public_parameters,
            batch_size,
        )
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;
    use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};

    use super::*;
    use crate::{
        ahe::paillier,
        group::{ristretto, secp256k1},
        proofs::{
            range,
            schnorr::{
                aggregation, language,
                language::encryption_of_tuple::tests::{public_parameters, Lang},
            },
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub(crate) fn benchmark(c: &mut Criterion) {
        let (language_public_parameters, range_proof_public_parameters) = public_parameters();

        language::benchmark::<REPETITIONS, Lang>(language_public_parameters.clone(), c);

        range::benchmark::<
            REPETITIONS,
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Lang,
        >(
            &language_public_parameters,
            &range_proof_public_parameters,
            c,
        );

        aggregation::benchmark_enhanced::<
            REPETITIONS,
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Lang,
        >(language_public_parameters, c);
    }
}
