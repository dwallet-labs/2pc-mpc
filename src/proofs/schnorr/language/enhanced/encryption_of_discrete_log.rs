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
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        BoundedGroupElement, CyclicGroupElement, GroupElement as _, Samplable,
    },
    proofs,
    proofs::{range, schnorr, schnorr::aggregation},
    AdditivelyHomomorphicEncryptionKey, ComputationalSecuritySizedNumber,
    StatisticalSecuritySizedNumber,
};

pub(crate) const REPETITIONS: usize = 1;

/// Encryption of Discrete Log Schnorr Language
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
#[derive(Clone, Serialize, Deserialize)]
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
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
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
        GroupElement::PublicParameters,
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
        GroupElement::Value,
    >;

    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let (
            discrete_log_in_witness_mask_base_element,
            commitment_randomness,
            encryption_randomness,
        ) = witness.into();

        let (_, group_public_parameters) = (&language_public_parameters
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        let (_, group_public_parameters) = group_public_parameters.into();

        let base = GroupElement::new(
            language_public_parameters.generator,
            group_public_parameters,
        )?;

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(
            language_public_parameters
                .range_proof_public_parameters
                .as_ref(),
        )?;

        let discrete_log_in_witness_mask_base: [power_of_two_moduli::GroupElement<
            WITNESS_MASK_LIMBS,
        >; RANGE_CLAIMS_PER_SCALAR] = (*discrete_log_in_witness_mask_base_element).into();

        let discrete_log_in_witness_mask_base: [Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR] =
            discrete_log_in_witness_mask_base
                .map(|element| Uint::<WITNESS_MASK_LIMBS>::from(element));

        let discrete_log_scalar: Scalar = super::witness_mask_base_to_scalar::<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            SCALAR_LIMBS,
            Scalar,
        >(
            discrete_log_in_witness_mask_base,
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        let discrete_log_plaintext: ahe::PlaintextSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        > = super::witness_mask_base_to_scalar::<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            ahe::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >(
            discrete_log_in_witness_mask_base,
            &language_public_parameters
                .encryption_scheme_public_parameters
                .as_ref()
                .plaintext_space_public_parameters,
        )?;

        let discrete_log_commitment_message = range::CommitmentSchemeMessageSpaceGroupElement::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >::new(
            discrete_log_in_witness_mask_base_element.value().into(),
            // TODO: no as-ref
            &language_public_parameters
                .range_proof_public_parameters
                .as_ref()
                .as_ref()
                .message_space_public_parameters,
        )?;

        // TODO: Need to check that WITNESS_MASK_LIMBS is actually in a size fitting the range proof
        // commitment scheme without going through modulation, and to implement `From` to
        // transition.
        Ok((
            commitment_scheme.commit(&discrete_log_commitment_message, commitment_randomness),
            (
                encryption_key
                    .encrypt_with_randomness(&discrete_log_plaintext, encryption_randomness),
                discrete_log_scalar * base,
            )
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
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
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
    type UnboundedWitnessSpaceGroupElement =
        ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;

    type RemainingStatementSpaceGroupElement = direct_product::GroupElement<
        ahe::CiphertextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        GroupElement,
    >;

    type RangeProof = RangeProof;
}

/// The Public Parameters of the Encryption of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const WITNESS_MASK_LIMBS: usize,
    GroupElementPublicParameters,
    ScalarPublicParameters,
    RangeProofCommitmentRandomnessSpacePublicParameters,
    RangeProofCommitmentSpacePublicParameters,
    RangeProofPublicParameters,
    EncryptionRandomnessPublicParameters,
    CiphertextPublicParameters,
    EncryptionKeyPublicParameters,
    GroupElementValue,
> where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    pub groups_public_parameters: super::GroupsPublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        EncryptionRandomnessPublicParameters,
        direct_product::PublicParameters<CiphertextPublicParameters, GroupElementPublicParameters>,
    >,
    pub range_proof_public_parameters: RangeProofPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    // The base of the discrete log
    pub generator: GroupElementValue,
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const WITNESS_MASK_LIMBS: usize,
        GroupElementPublicParameters,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters: Clone,
        EncryptionRandomnessPublicParameters: Clone,
        CiphertextPublicParameters: Clone,
        EncryptionKeyPublicParameters,
        GroupElementValue,
    >
    PublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        GroupElementPublicParameters,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        EncryptionRandomnessPublicParameters,
        CiphertextPublicParameters,
        EncryptionKeyPublicParameters,
        GroupElementValue,
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
        GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof,
    >(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        range_proof_public_parameters: RangeProof::PublicParameters,
        encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    ) -> Self
    where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        GroupElement: group::GroupElement<
                Value = GroupElementValue,
                PublicParameters = GroupElementPublicParameters,
            > + CyclicGroupElement,
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + BoundedGroupElement<SCALAR_LIMBS>
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
        EncryptionKey::CiphertextSpaceGroupElement:
            group::GroupElement<PublicParameters = CiphertextPublicParameters>,
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

        // TODO: maybe we don't want the generator all the time?
        let generator = GroupElement::generator_from_public_parameters(&group_public_parameters);

        let unbounded_witness_space_public_parameters = encryption_scheme_public_parameters
            .as_ref()
            .randomness_space_public_parameters
            .clone();

        let remaining_statement_space_public_parameters = (
            encryption_scheme_public_parameters
                .as_ref()
                .ciphertext_space_public_parameters
                .clone(),
            group_public_parameters,
        )
            .into();

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
            generator,
        }
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const WITNESS_MASK_LIMBS: usize,
        GroupElementPublicParameters,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        EncryptionRandomnessPublicParameters,
        CiphertextPublicParameters,
        EncryptionKeyPublicParameters,
        GroupElementValue,
    >
    AsRef<
        super::GroupsPublicParameters<
            RANGE_CLAIMS_PER_SCALAR,
            WITNESS_MASK_LIMBS,
            RangeProofCommitmentRandomnessSpacePublicParameters,
            RangeProofCommitmentSpacePublicParameters,
            EncryptionRandomnessPublicParameters,
            direct_product::PublicParameters<
                CiphertextPublicParameters,
                GroupElementPublicParameters,
            >,
        >,
    >
    for PublicParameters<
        RANGE_CLAIMS_PER_SCALAR,
        WITNESS_MASK_LIMBS,
        GroupElementPublicParameters,
        ScalarPublicParameters,
        RangeProofCommitmentRandomnessSpacePublicParameters,
        RangeProofCommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        EncryptionRandomnessPublicParameters,
        CiphertextPublicParameters,
        EncryptionKeyPublicParameters,
        GroupElementValue,
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
        EncryptionRandomnessPublicParameters,
        direct_product::PublicParameters<CiphertextPublicParameters, GroupElementPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

/// The Witness Space Group Element of an Encryption of Discrete Log Schnorr Language.
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

/// The Statement Space Group Element of an Encryption of Discrete Log Schnorr Language.
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

/// The Public Parameters of an Encryption of Discrete Log Schnorr Language.
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

/// An Encryption of Discrete Log Schnorr Proof.
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

/// An Encryption of Discrete Log Schnorr Proof Aggregation Commitment Round Party.
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

/// An Encryption of Discrete Log Schnorr Proof Aggregation Decommitment Round Party.
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

/// An Encryption of Discrete Log Schnorr Proof Aggregation Decommitment.
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

/// An Encryption of Discrete Log Schnorr Proof Aggregation Proof Share Round Party.
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

/// An Encryption of Discrete Log Schnorr Proof Aggregation Proof Share.
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

/// An Encryption of Discrete Log Schnorr Proof Proof Aggregation Round Party.
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
            range::RangeProof,
            schnorr::{aggregation, language},
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
            secp256k1_group_public_parameters,
            bulletproofs_public_parameters.clone(),
            paillier_public_parameters,
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
                language::encryption_of_discrete_log::tests::{public_parameters, Lang},
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
