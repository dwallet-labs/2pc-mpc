// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe, commitments,
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product,
        GroupElement as _, Samplable,
    },
    proofs,
    proofs::{
        schnorr,
        schnorr::{EnhancedLanguage, EnhancedLanguagePublicValue, EnhancedLanguageWitness},
    },
    AdditivelyHomomorphicEncryptionKey,
};

// TODO: should I unite now the public parameters of the groups with commitment & encryption
type UnboundedWitnessSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, EncryptionKey> =
    ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;

type RemainingPublicValueSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = direct_product::GroupElement<
    ahe::CiphertextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    GroupElement,
>;

type Witness<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    EncryptionKey,
    RangeProof,
> = EnhancedLanguageWitness<
    RANGE_CLAIMS_PER_SCALAR,
    RANGE_CLAIM_LIMBS,
    UnboundedWitnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    RangeProof,
>;

type PublicValue<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
    RangeProof,
> = EnhancedLanguagePublicValue<
    RANGE_CLAIMS_PER_SCALAR,
    RANGE_CLAIM_LIMBS,
    RemainingPublicValueSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
    RangeProof,
>;

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
        Witness<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            RangeProof,
        >,
        PublicValue<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
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
        ahe::PlaintextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        ahe::RandomnessSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        ahe::CiphertextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        Scalar::PublicParameters,
        GroupElement::Value,
    >;
    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &Witness<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            RangeProof,
        >,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &group::PublicParameters<
            Witness<
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
                RangeProof,
            >,
        >,
        public_value_space_public_parameters: &group::PublicParameters<
            PublicValue<
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
                RangeProof,
            >,
        >,
    ) -> proofs::Result<
        PublicValue<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
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
            ahe::PlaintextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(discrete_log),
                &language_public_parameters.plaintext_group_public_parameters,
            )?;

        Ok((
            commitment_scheme.commit(discrete_log_parts, commitment_randomness),
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
        UnboundedWitnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        RemainingPublicValueSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
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
    Witness<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
        RangeProof,
    >,
    PublicValue<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
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
