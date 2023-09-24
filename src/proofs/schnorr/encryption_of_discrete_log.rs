// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe,
    ahe::{CiphertextSpaceGroupElement, PlaintextSpaceGroupElement},
    commitments,
    commitments::CommitmentSpaceGroupElement,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        GroupElement as _, Samplable,
    },
    proofs,
    proofs::{
        range::CommitmentScheme,
        schnorr,
        schnorr::{EnhancedLanguage, HomomorphicCommitmentScheme},
    },
    AdditivelyHomomorphicEncryptionKey,
};

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
#[derive(Clone)]
pub struct Language<
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
    const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
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

// TODO: do type aliases of type aliases: public parameters of randomness of ...
// TODO: should I unite now the public parameters of the groups with commitment & encryption
// schemes?
/// The Public Parameters of the Encryption of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    CommitmentSchemePublicParameters,
    CommitmentRandomnessPublicParameters,
    EncryptionKeyPublicParameters,
    PlaintextPublicParameters,
    EncryptionRandomnessPublicParameters,
    CiphertextPublicParameters,
    ScalarPublicParameters,
    GroupElementValue,
> {
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub commitment_randomness_group_public_parameters: CommitmentRandomnessPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub plaintext_group_public_parameters: PlaintextPublicParameters,
    pub encryption_randomness_group_public_parameters: EncryptionRandomnessPublicParameters,
    pub ciphertext_group_public_parameters: CiphertextPublicParameters,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub generator: GroupElementValue,
    // The base of discrete log */
    // todo
    // todo: range claim. */
}

impl<
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
        const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS>,
    >
    schnorr::Language<
        direct_product::ThreeWayGroupElement<
            self_product::GroupElement<
                RANGE_CLAIMS_PER_SCALAR,
                power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
            >,
            commitments::RandomnessSpaceGroupElement<RangeProof::CommitmentScheme>,
            ahe::RandomnessSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,
        direct_product::GroupElement<
            CommitmentSpaceGroupElement<RangeProof::CommitmentScheme>,
            direct_product::GroupElement<
                CiphertextSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
                GroupElement,
            >,
        >,
    >
    for Language<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    Scalar::Value: From<[Uint<RANGE_CLAIM_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: From<Scalar>,
{
    type PublicParameters = PublicParameters<
        commitments::PublicParameters<RangeProof::CommitmentScheme>,
        group::PublicParameters<
            commitments::RandomnessSpaceGroupElement<RangeProof::CommitmentScheme>,
        >,
        EncryptionKey::PublicParameters,
        group::PublicParameters<
            PlaintextSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,
        group::PublicParameters<
            ahe::RandomnessSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,
        group::PublicParameters<
            CiphertextSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,
        Scalar::PublicParameters,
        GroupElement::Value,
    >;
    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &direct_product::ThreeWayGroupElement<
            self_product::GroupElement<
                RANGE_CLAIMS_PER_SCALAR,
                power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
            >,
            commitments::RandomnessSpaceGroupElement<RangeProof::CommitmentScheme>,
            ahe::RandomnessSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &direct_product::ThreeWayPublicParameters<
            self_product::PublicParameters<
                RANGE_CLAIMS_PER_SCALAR,
                group::PublicParameters<power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>>,
            >,
            group::PublicParameters<
                commitments::RandomnessSpaceGroupElement<RangeProof::CommitmentScheme>,
            >,
            group::PublicParameters<
                ahe::RandomnessSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
            >,
        >,
        public_value_space_public_parameters: &direct_product::PublicParameters<
            group::PublicParameters<CommitmentSpaceGroupElement<RangeProof::CommitmentScheme>>,
            direct_product::PublicParameters<
                group::PublicParameters<
                    CiphertextSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
                >,
                GroupElement::PublicParameters,
            >,
        >,
    ) -> proofs::Result<
        direct_product::GroupElement<
            CommitmentSpaceGroupElement<RangeProof::CommitmentScheme>,
            direct_product::GroupElement<
                CiphertextSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
                GroupElement,
            >,
        >,
    > {
        let (discrete_log_parts, commitment_randomness, encryption_randomness) = witness.into();

        let (commitment_public_parameters, group_public_parameters) =
            public_value_space_public_parameters.into();
        let (_, group_public_parameters) = group_public_parameters.into();

        let base = GroupElement::new(
            language_public_parameters.generator.clone(),
            group_public_parameters,
        )?;

        let encryption_key = EncryptionKey::new(
            &language_public_parameters.encryption_scheme_public_parameters,
            &language_public_parameters.plaintext_group_public_parameters,
            &language_public_parameters.encryption_randomness_group_public_parameters,
            &language_public_parameters.ciphertext_group_public_parameters,
        )?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            commitment_public_parameters,
        )?;

        let discrete_log_parts_array: [power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR] = (*discrete_log_parts).into();
        let discrete_log: Scalar::Value = discrete_log_parts_array
            .map(|element| Uint::<RANGE_CLAIM_LIMBS>::from(element))
            .into();

        let discrete_log = Scalar::new(
            discrete_log,
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        let discrete_log_plaintext =
            PlaintextSpaceGroupElement::<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>::new(
                Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(discrete_log),
                &language_public_parameters.plaintext_group_public_parameters,
            )?;

        Ok((
            commitment_scheme.commit(&discrete_log_parts, commitment_randomness),
            (
                encryption_key
                    .encrypt_with_randomness(&discrete_log_plaintext, encryption_randomness),
                discrete_log * base,
            )
                .into(),
        )
            .into())
    }
}

impl<
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
        const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar: group::GroupElement,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS>,
    >
    EnhancedLanguage<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        ahe::RandomnessSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
        direct_product::GroupElement<
            CiphertextSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
            GroupElement,
        >,
        RangeProof,
    >
    for Language<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    Scalar::Value: From<[Uint<RANGE_CLAIM_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: From<Scalar>,
{
}

/// An Encryption of Discrete Log Schnorr Proof
// TODO: enhanced proof.
pub type Proof<
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
    ProtocolContext,
> = schnorr::Proof<
    direct_product::ThreeWayGroupElement<
        self_product::GroupElement<
            RANGE_CLAIMS_PER_SCALAR,
            power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
        >,
        commitments::RandomnessSpaceGroupElement<
            CommitmentScheme<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, RangeProof>,
        >,
        ahe::RandomnessSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >,
    direct_product::GroupElement<
        CommitmentSpaceGroupElement<
            CommitmentScheme<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, RangeProof>,
        >,
        direct_product::GroupElement<
            CiphertextSpaceGroupElement<EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS>,
            GroupElement,
        >,
    >,
    Language<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >,
    ProtocolContext,
>;
