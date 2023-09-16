// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{
    group,
    group::{
        direct_product, paillier::CiphertextGroupElement, self_product_group, CyclicGroupElement,
        KnownOrderGroupElement, Samplable,
    },
    proofs::schnorr,
    AdditivelyHomomorphicEncryptionKey,
};

/// Encryption of Discrete Log Schnorr Language
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However knowledge-soundness proofs are group dependent, and thus we can only assure security for
/// groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
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

/// The Public Parameters of the Commitment of Discrete Log Schnorr Language
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
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >
    schnorr::Language<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        direct_product::GroupElement<
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            RandomnessSpaceGroupElement,
            Scalar,
        >,
        direct_product::GroupElement<
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            CiphertextGroupElement,
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
        witness: &self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &direct_product::GroupElement<
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            RandomnessSpaceGroupElement,
            Scalar,
        >,
        public_value_space_public_parameters: &direct_product::PublicParameters<
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            RandomnessSpaceGroupElement,
            Scalar,
        >,
    ) -> group::Result<
        direct_product::GroupElement<
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            CiphertextGroupElement,
            GroupElement,
        >,
    > {
        todo!()
        // let [value, randomness]: &[Scalar; 2] = witness.into();
        //
        // let base = GroupElement::new(
        //     language_public_parameters.generator.clone(),
        //     &public_value_space_public_parameters.public_parameters,
        // )?;
        //
        // let commitment_scheme = EncryptionKey::new(
        //     &language_public_parameters.commitment_scheme_public_parameters,
        //     &public_value_space_public_parameters.public_parameters,
        // )?;
        //
        // Ok([Encryption_scheme.commit(value, randomness), base * value].into())
    }
}
// /// A Encryption of Discrete Log Schnorr Proof
// #[allow(dead_code)]
// pub type Proof<const SCALAR_LIMBS: usize, Scalar, GroupElement, EncryptionKey, ProtocolContext> =
//     schnorr::Proof<
//         SCALAR_LIMBS,
//         SCALAR_LIMBS,
//         self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
//         self_product_group::GroupElement<2, SCALAR_LIMBS, GroupElement>,
//         Language<SCALAR_LIMBS, Scalar, GroupElement, EncryptionKey>,
//         ProtocolContext,
//     >;
