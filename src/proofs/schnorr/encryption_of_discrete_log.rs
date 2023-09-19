// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::Uint;
use serde::Serialize;

use crate::{
    group,
    group::{direct_product, CyclicGroupElement, KnownOrderGroupElement, Samplable},
    proofs,
    proofs::schnorr,
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
pub struct Language<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _randomness_group_element_choice: PhantomData<RandomnessSpaceGroupElement>,
    _ciphertext_group_element_choice: PhantomData<CiphertextSpaceGroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Public Parameters of the Encryption of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
> where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    Scalar: From<Uint<SCALAR_LIMBS>>,
    Uint<SCALAR_LIMBS>: for<'a> From<&'a Scalar>,
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
{
    encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    randomness_group_public_parameters: RandomnessSpaceGroupElement::PublicParameters,
    ciphertext_group_public_parameters: CiphertextSpaceGroupElement::PublicParameters,
    generator: GroupElement::Value, // The base of discrete log
}

impl<
        const MASK_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
        const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >
    schnorr::Language<
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        direct_product::GroupElement<
            WITNESS_SCALAR_LIMBS,
            SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            Scalar,
            RandomnessSpaceGroupElement,
        >,
        direct_product::GroupElement<
            PUBLIC_VALUE_SCALAR_LIMBS,
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
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    Scalar: From<Uint<SCALAR_LIMBS>>,
    Uint<SCALAR_LIMBS>: for<'a> From<&'a Scalar>,
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
{
    type PublicParameters = PublicParameters<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >;
    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &direct_product::GroupElement<
            WITNESS_SCALAR_LIMBS,
            SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            Scalar,
            RandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        witness_space_public_parameters: &direct_product::PublicParameters<
            WITNESS_SCALAR_LIMBS,
            SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            Scalar,
            RandomnessSpaceGroupElement,
        >,
        public_value_space_public_parameters: &direct_product::PublicParameters<
            PUBLIC_VALUE_SCALAR_LIMBS,
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            CiphertextSpaceGroupElement,
            GroupElement,
        >,
    ) -> proofs::Result<
        direct_product::GroupElement<
            PUBLIC_VALUE_SCALAR_LIMBS,
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
        )?;

        Ok((
            encryption_key.encrypt_with_randomness(discrete_log, randomness),
            base * discrete_log,
        )
            .into())
    }
}

/// An Encryption of Discrete Log Schnorr Proof
#[allow(dead_code)]
pub type Proof<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    ProtocolContext,
> = schnorr::Proof<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    direct_product::GroupElement<
        WITNESS_SCALAR_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
    >,
    direct_product::GroupElement<
        PUBLIC_VALUE_SCALAR_LIMBS,
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
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;
