// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;
use std::ops::Mul;

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use crate::{AdditivelyHomomorphicEncryptionKey, ahe, commitments, group, proofs};
use crate::commitments::HomomorphicCommitmentScheme;
use crate::group::{direct_product, Samplable};
use crate::proofs::{range, schnorr};
use crate::helpers::const_generic_array_serialization;

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
#[derive(Clone)]
pub struct Language<
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
    const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
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
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
    const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
    const WITNESS_MASK_LIMBS: usize,
    const DIMENSION: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement: group::GroupElement,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    CommitmentScheme: HomomorphicCommitmentScheme,
    RangeProof: proofs::RangeProof<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS>,
>
schnorr::Language
for Language<
    MASK_LIMBS,
    RANGE_CLAIMS_PER_SCALAR,
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
        Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output=GroupElement>
        + for<'r> Mul<&'r GroupElement, Output=GroupElement>
        + Copy,
        Scalar::Value: From<[Uint<RANGE_CLAIM_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>,
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: From<Scalar>,
{
    type WitnessSpaceGroupElement =
    super::EnhancedLanguageWitness<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Self>;
    type StatementSpaceGroupElement =
    super::EnhancedLanguageStatement<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Self>;

    type PublicParameters = PublicParameters<
        DIMENSION,
        super::WitnessSpacePublicParameters<Self>,
        super::StatementSpacePublicParameters<Self>,
        commitments::PublicParameters<CommitmentScheme>,
        range::CommitmentSchemePublicParameters<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >,
        ahe::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        group::PublicParameters<Scalar>,
        ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;

    const NAME: &'static str = "Committed Linear Evaluation";

    fn group_homomorphism(
        _witness: &super::WitnessSpaceGroupElement<Self>,
        _language_public_parameters: &super::PublicParameters<Self>,
    ) -> proofs::Result<super::StatementSpaceGroupElement<Self>> {
        // let (coefficients, commitment_randomness, mask, encryption_randomness) = witness.into();
        //
        // let (_, scalar_group_public_parameters, _, randomness_group_public_parameters) =
        //     witness_space_public_parameters.into();
        //
        // let scalar_group_order =
        //     Scalar::order_from_public_parameters(&scalar_group_public_parameters);
        //
        // let (ciphertext_group_public_parameters, group_public_parameters) =
        //     public_value_space_public_parameters.into();
        //
        // let encryption_key = EncryptionKey::new(
        //     &language_public_parameters.encryption_scheme_public_parameters,
        //     scalar_group_public_parameters,
        //     randomness_group_public_parameters,
        //     ciphertext_group_public_parameters,
        // )?;
        //
        // let commitment_scheme = CommitmentScheme::new(
        //     &language_public_parameters.commitment_scheme_public_parameters,
        //     group_public_parameters,
        // )?;
        //
        // let ciphertexts =
        //     flat_map_results(language_public_parameters.ciphertexts.clone().map(|value| {
        //         CiphertextSpaceGroupElement::new(value, ciphertext_group_public_parameters)
        //     }))?;
        //
        // Ok((
        //     encryption_key.evaluate_circuit_private_linear_combination_with_randomness(
        //         coefficients.into(),
        //         &ciphertexts,
        //         &scalar_group_order,
        //         &mask.into(),
        //         encryption_randomness,
        //     )?,
        //     commitment_scheme.commit(coefficients, commitment_randomness),
        // )
        //     .into())
        todo!()
    }

    fn public_parameters_to_group_parameters(
        language_public_parameters: &super::PublicParameters<Self>,
    ) -> &super::GroupsPublicParameters<
        super::WitnessSpacePublicParameters<Self>,
        super::StatementSpacePublicParameters<Self>,
    > {
        language_public_parameters.as_ref()
    }
}


impl<
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
    const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
    const WITNESS_MASK_LIMBS: usize,
    const DIMENSION: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement: group::GroupElement,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    CommitmentScheme: HomomorphicCommitmentScheme,
    RangeProof: proofs::RangeProof<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS>,
>
schnorr::EnhancedLanguage<RANGE_CLAIMS_PER_SCALAR,
    RANGE_CLAIM_LIMBS,
    WITNESS_MASK_LIMBS,
>
for Language<
    MASK_LIMBS,
    RANGE_CLAIMS_PER_SCALAR,
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
        Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output=GroupElement>
        + for<'r> Mul<&'r GroupElement, Output=GroupElement>
        + Copy,
        Scalar::Value: From<[Uint<RANGE_CLAIM_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>,
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: From<Scalar>,
{
    type UnboundedWitnessSpaceGroupElement =
    direct_product::GroupElement<
        Scalar, // The commitment randomness
        ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>, // The encryption randomness
    >;

    type RemainingStatementSpaceGroupElement = direct_product::GroupElement<
        ahe::CiphertextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>, // The resultant ciphertext of the homomorphic evaluation
        commitments::CommitmentSpaceGroupElement<CommitmentScheme>, // The commitment on the evaluation coefficients
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
    super::GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub range_proof_commitment_scheme_public_parameters: ProofCommitmentSchemePublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub scalar_group_public_parameters: ScalarPublicParameters,

    #[serde(with = "const_generic_array_serialization")]
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
> AsRef<super::GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
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
    ) -> &super::GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>
    {
        &self.groups_public_parameters
    }
}