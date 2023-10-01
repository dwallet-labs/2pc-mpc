// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{array, marker::PhantomData, ops::Mul};

use crypto_bigint::{Encoding, Uint};
use language::GroupsPublicParameters;
use schnorr::language;
use serde::Serialize;

use crate::{
    ahe, commitments,
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        BoundedGroupElement, GroupElement as _, KnownOrderScalar, Samplable,
    },
    helpers::flat_map_results,
    proofs,
    proofs::{range, schnorr},
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
#[derive(Clone, Serialize)]
pub struct Language<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const DIMENSION: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    CommitmentScheme,
    RangeProof,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
    _commitment_choice: PhantomData<CommitmentScheme>,
    _range_proof_choice: PhantomData<RangeProof>,
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        CommitmentScheme,
        RangeProof,
    > schnorr::Language
    for Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        DIMENSION,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        MessageSpaceGroupElement = self_product::GroupElement<DIMENSION, Scalar>,
        RandomnessSpaceGroupElement = Scalar,
        CommitmentSpaceGroupElement = GroupElement,
    >,
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >,
    range::CommitmentSchemeMessageSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<[Uint<WITNESS_MASK_LIMBS>; NUM_RANGE_CLAIMS]>,
{
    type WitnessSpaceGroupElement = super::EnhancedLanguageWitness<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self,
    >;
    type StatementSpaceGroupElement = super::EnhancedLanguageStatement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self,
    >;

    type PublicParameters = PublicParameters<
        DIMENSION,
        language::WitnessSpacePublicParameters<Self>,
        language::StatementSpacePublicParameters<Self>,
        commitments::PublicParameters<SCALAR_LIMBS, CommitmentScheme>,
        range::CommitmentSchemePublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >,
        ahe::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        group::PublicParameters<Scalar>,
        ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;

    const NAME: &'static str = "Committed Linear Evaluation";

    fn group_homomorphism(
        witness: &language::WitnessSpaceGroupElement<Self>,
        language_public_parameters: &language::PublicParameters<Self>,
    ) -> proofs::Result<language::StatementSpaceGroupElement<Self>> {
        if NUM_RANGE_CLAIMS != RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK
            || RANGE_CLAIMS_PER_SCALAR * RANGE_CLAIM_LIMBS < SCALAR_LIMBS
            || RANGE_CLAIMS_PER_MASK * RANGE_CLAIM_LIMBS < MASK_LIMBS
        {
            return Err(proofs::Error::InvalidParameters);
        }

        let (
            coefficients_and_mask_in_witness_mask_base,
            range_proof_commitment_randomness,
            remaining_witness,
        ) = witness.into();

        let (commitment_randomness, encryption_randomness) = remaining_witness.into();

        let scalar_group_public_parameters = &language_public_parameters
            .commitment_scheme_public_parameters
            .as_ref()
            .randomness_space_public_parameters;

        let scalar_group_order =
            Scalar::order_from_public_parameters(scalar_group_public_parameters);

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        let range_proof_commitment_scheme = RangeProof::CommitmentScheme::new(
            &language_public_parameters.range_proof_commitment_scheme_public_parameters,
        )?;

        let ciphertexts =
            flat_map_results(language_public_parameters.ciphertexts.clone().map(|value| {
                ahe::CiphertextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                    value,
                    &language_public_parameters.encryption_scheme_public_parameters.as_ref().ciphertext_space_public_parameters,
                )
            }))?;

        let coefficients_and_mask_in_witness_mask_base: [power_of_two_moduli::GroupElement<
            WITNESS_MASK_LIMBS,
        >; NUM_RANGE_CLAIMS] = (*coefficients_and_mask_in_witness_mask_base).into();

        let coefficients_and_mask_in_witness_mask_base: [Uint<WITNESS_MASK_LIMBS>;
            NUM_RANGE_CLAIMS] =
            coefficients_and_mask_in_witness_mask_base.map(Uint::<WITNESS_MASK_LIMBS>::from);

        let mut coefficients_and_mask_in_witness_mask_base_iter =
            coefficients_and_mask_in_witness_mask_base.into_iter();

        let coefficients_in_witness_mask_base: [[Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR];
            DIMENSION] = flat_map_results(array::from_fn(|_| {
            flat_map_results(array::from_fn(|_| {
                coefficients_and_mask_in_witness_mask_base_iter
                    .next()
                    .ok_or(proofs::Error::InvalidParameters)
            }))
        }))?;

        let coefficients_as_scalar = flat_map_results(coefficients_in_witness_mask_base.map(
            |coefficient_in_witness_base| {
                super::witness_mask_base_to_scalar::<
                    RANGE_CLAIMS_PER_SCALAR,
                    RANGE_CLAIM_LIMBS,
                    WITNESS_MASK_LIMBS,
                    SCALAR_LIMBS,
                    Scalar,
                >(coefficient_in_witness_base, &scalar_group_public_parameters)
            },
        ))?;

        let coefficients_as_plaintext_elements = flat_map_results(
            coefficients_in_witness_mask_base.map(|coefficient_in_witness_base| {
                super::witness_mask_base_to_scalar::<
                    RANGE_CLAIMS_PER_SCALAR,
                    RANGE_CLAIM_LIMBS,
                    WITNESS_MASK_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    ahe::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
                >(
                    coefficient_in_witness_base,
                    &language_public_parameters
                        .encryption_scheme_public_parameters
                        .as_ref()
                        .plaintext_space_public_parameters,
                )
            }),
        )?;

        let mask_in_witness_mask_base: [Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_MASK] =
            flat_map_results(array::from_fn(|_| {
                coefficients_and_mask_in_witness_mask_base_iter
                    .next()
                    .ok_or(proofs::Error::InvalidParameters)
            }))?;

        let mask = super::witness_mask_base_to_scalar::<
            RANGE_CLAIMS_PER_MASK,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            ahe::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >(
            mask_in_witness_mask_base,
            &language_public_parameters
                .encryption_scheme_public_parameters
                .as_ref()
                .plaintext_space_public_parameters,
        )?;

        Ok((
            range_proof_commitment_scheme.commit(
                &coefficients_and_mask_in_witness_mask_base.into(),
                range_proof_commitment_randomness,
            ),
            (
                encryption_key.evaluate_circuit_private_linear_combination_with_randomness(
                    &coefficients_as_plaintext_elements,
                    &ciphertexts,
                    &scalar_group_order,
                    &mask,
                    encryption_randomness,
                )?,
                commitment_scheme.commit(&coefficients_as_scalar.into(), commitment_randomness),
            )
                .into(),
        )
            .into())
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        CommitmentScheme,
        RangeProof,
    >
    schnorr::EnhancedLanguage<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
    >
    for Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        DIMENSION,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        MessageSpaceGroupElement = self_product::GroupElement<DIMENSION, Scalar>,
        RandomnessSpaceGroupElement = Scalar,
        CommitmentSpaceGroupElement = GroupElement,
    >,
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >,
    range::CommitmentSchemeMessageSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<[Uint<WITNESS_MASK_LIMBS>; NUM_RANGE_CLAIMS]>,
{
    type UnboundedWitnessSpaceGroupElement = direct_product::GroupElement<
        // The commitment randomness
        Scalar,
        // The encryption randomness
        ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;

    type RemainingStatementSpaceGroupElement = direct_product::GroupElement<
        // The resultant ciphertext of the homomorphic evaluation
        ahe::CiphertextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        // The commitment on the evaluation coefficients
        commitments::CommitmentSpaceGroupElement<SCALAR_LIMBS, CommitmentScheme>,
    >;

    type RangeProof = RangeProof;
}

/// The Public Parameters of the Committed Linear Evaluation Schnorr Language
///
/// In order to prove an affine transformation, set `ciphertexts[0]` to an encryption of one with
/// randomness zero ($\Enc(1; 0)$).
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const DIMENSION: usize,
    WitnessSpacePublicParameters,
    StatementSpacePublicParameters,
    CommitmentSchemePublicParameters,
    ProofCommitmentSchemePublicParameters,
    EncryptionKeyPublicParameters,
    ScalarPublicParameters,
    CiphertextSpaceValue: Serialize,
> {
    pub groups_public_parameters:
        GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub range_proof_commitment_scheme_public_parameters: ProofCommitmentSchemePublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub scalar_group_public_parameters: ScalarPublicParameters,

    #[serde(with = "crate::helpers::const_generic_array_serialization")]
    pub ciphertexts: [CiphertextSpaceValue; DIMENSION],
}

impl<
        const DIMENSION: usize,
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
        ProofCommitmentSchemePublicParameters,
        EncryptionKeyPublicParameters,
        ScalarPublicParameters,
        CiphertextSpaceValue: Serialize,
    > AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
    for PublicParameters<
        DIMENSION,
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
        ProofCommitmentSchemePublicParameters,
        EncryptionKeyPublicParameters,
        ScalarPublicParameters,
        CiphertextSpaceValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
        &self.groups_public_parameters
    }
}
