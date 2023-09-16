// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{ConcatMixed, Uint};
use serde::Serialize;

use crate::{
    group,
    group::{direct_product, CyclicGroupElement, KnownOrderGroupElement, Samplable},
    proofs::schnorr,
    AdditivelyHomomorphicEncryptionKey,
};

/// Encryption of Discrete Log Schnorr Language
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
#[derive(Debug, PartialEq, Serialize)]
pub struct PublicParameters<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
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
{
    encryption_key_public_parameters: EncryptionKey::PublicParameters,
    generator: GroupElement::Value, // The base of discrete log

    #[serde(skip_serializing)]
    _randomness_group_element_choice: PhantomData<RandomnessSpaceGroupElement>,
    #[serde(skip_serializing)]
    _ciphertext_group_element_choice: PhantomData<CiphertextSpaceGroupElement>,
    #[serde(skip_serializing)]
    _encryption_key_choice: PhantomData<EncryptionKey>,
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
    >
    for Language<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
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
{
    type PublicParameters = PublicParameters<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >;
    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &direct_product::GroupElement<
            SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            Scalar,
            RandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &direct_product::PublicParameters<
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

        let (_, group_public_parameters) = public_value_space_public_parameters.into();

        let base = GroupElement::new(
            language_public_parameters.generator.clone(),
            group_public_parameters,
        )?;

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_key_public_parameters);

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
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;
