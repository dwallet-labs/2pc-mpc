// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{ConcatMixed, Uint};
use serde::Serialize;

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{
        additive_group_of_integers_modulu_n, direct_product, self_product_group,
        CyclicGroupElement, KnownOrderGroupElement, Samplable,
    },
    helpers::const_generic_array_serialization,
    proofs::schnorr,
    AdditivelyHomomorphicEncryptionKey,
};

/// Committed Affine Evaluation Schnorr Language
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group and additively homomorphic
/// encryption scheme (TODO: right?) in this language, we choose to provide a fully generic
/// implementation.
///
/// However knowledge-soundness proofs are group and encryption scheme dependent, and thus we can
/// only assure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`. (TODO: still ?)
///
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier`.
// also TODO: for commitments, say the same?
pub struct Language<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNCTION_DEGREE: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    CommitmentScheme,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _randomness_group_element_choice: PhantomData<RandomnessSpaceGroupElement>,
    _ciphertext_group_element_choice: PhantomData<CiphertextSpaceGroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

/// The Public Parameters of the Committed Affine Evaluation Schnorr Language
#[derive(Debug, PartialEq, Serialize)]
pub struct PublicParameters<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNCTION_DEGREE: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    CommitmentScheme,
> where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    RandomnessSpaceGroupElement: group::GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>
        + Samplable<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: group::GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
    >,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        Scalar,
        Scalar,
        GroupElement,
    >,
{
    encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    randomness_group_public_parameters: RandomnessSpaceGroupElement::PublicParameters,
    ciphertext_group_public_parameters: CiphertextSpaceGroupElement::PublicParameters,
    commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    // The base of discrete log
    generator: GroupElement::Value,
    #[serde(with = "const_generic_array_serialization")]
    ciphertexts: [CiphertextSpaceGroupElement::Value; FUNCTION_DEGREE],
}

impl<
        const MASK_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
        const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNCTION_DEGREE: usize,
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
    >
    schnorr::Language<
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        direct_product::FourWayGroupElement<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            MASK_LIMBS,
            WITNESS_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product_group::GroupElement<FUNCTION_DEGREE, SCALAR_LIMBS, Scalar>,
            Scalar,
            additive_group_of_integers_modulu_n::GroupElement<MASK_LIMBS>,
            RandomnessSpaceGroupElement,
        >,
        direct_product::GroupElement<
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            CiphertextSpaceGroupElement,
            GroupElement,
        >,
    >
    for Language<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        FUNCTION_DEGREE,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
    >
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    RandomnessSpaceGroupElement: group::GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>
        + Samplable<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: group::GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
    Uint<SCALAR_LIMBS>:
        ConcatMixed<Uint<RANDOMNESS_SPACE_SCALAR_LIMBS>, MixedOutput = Uint<WITNESS_SCALAR_LIMBS>>,
    Uint<CIPHERTEXT_SPACE_SCALAR_LIMBS>:
        ConcatMixed<Uint<SCALAR_LIMBS>, MixedOutput = Uint<PUBLIC_VALUE_SCALAR_LIMBS>>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
    >,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        Scalar,
        Scalar,
        GroupElement,
    >,
{
    type PublicParameters = PublicParameters<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        FUNCTION_DEGREE,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
    >;
    const NAME: &'static str = "Committed Affine Evaluation";

    fn group_homomorphism(
        witness: &direct_product::FourWayGroupElement<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            MASK_LIMBS,
            WITNESS_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product_group::GroupElement<FUNCTION_DEGREE, SCALAR_LIMBS, Scalar>,
            Scalar,
            additive_group_of_integers_modulu_n::GroupElement<MASK_LIMBS>,
            RandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        witness_space_public_parameters: &direct_product::PublicParameters<
            SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            Scalar,
            RandomnessSpaceGroupElement,
        >,
        public_value_space_public_parameters: &direct_product::PublicParameters<
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            CiphertextSpaceGroupElement,
            GroupElement,
        >,
    ) -> group::Result<
        direct_product::GroupElement<
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            CiphertextSpaceGroupElement,
            GroupElement,
        >,
    > {
        let (discrete_log, randomness): (&Scalar, &RandomnessSpaceGroupElement) = witness.into();

        let (scalar_group_public_parameters, _) = witness_space_public_parameters.into();

        let (_, group_public_parameters) = public_value_space_public_parameters.into();

        let base = GroupElement::new(
            language_public_parameters.generator.clone(),
            group_public_parameters,
        )?;

        let encryption_key = EncryptionKey::new(
            &language_public_parameters.encryption_scheme_public_parameters,
            scalar_group_public_parameters,
            &language_public_parameters.randomness_group_public_parameters,
            &language_public_parameters.ciphertext_group_public_parameters,
        );

        let commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            &group_public_parameters,
        )?;

        Ok((
            encryption_key.encrypt_with_randomness(discrete_log, randomness),
            base * discrete_log,
        )
            .into())
    }
}

/// A Committed Affine Evaluation Schnorr Proof
#[allow(dead_code)]
pub type Proof<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNCTION_DEGREE: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    CommitmentScheme,
    ProtocolContext,
> = schnorr::Proof<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    direct_product::GroupElement<
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
    >,
    direct_product::GroupElement<
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        CiphertextSpaceGroupElement,
        GroupElement,
    >,
    Language<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        FUNCTION_DEGREE,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
    >,
    ProtocolContext,
>;
