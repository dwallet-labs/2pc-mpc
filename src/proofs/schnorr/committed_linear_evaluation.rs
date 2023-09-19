// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{ConcatMixed, Encoding, Uint};
use serde::Serialize;

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{
        additive_group_of_integers_modulu_n, direct_product, self_product_group,
        CyclicGroupElement, KnownOrderGroupElement, Samplable,
    },
    helpers::{const_generic_array_serialization, flat_map_results},
    proofs,
    proofs::schnorr,
    AdditivelyHomomorphicEncryptionKey,
};

/// Committed Linear Evaluation Schnorr Language
///
/// This language allows to prove a linear combination have been homomorphically evaluated on a
/// vector of ciphertexts. If one wishes to prove an affine evaluation instead of a linear one, as
/// is required in the paper, the first ciphertexts should be set to an encryption of one with
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
pub struct Language<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
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

/// The Public Parameters of the Committed Linear Evaluation Schnorr Language
///
/// In order to prove an affine transformation, set `ciphertexts[0]` to an encryption of one with
/// randomness zero ($\Enc(1; 0)$).
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    Scalar,
    RandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    CommitmentScheme,
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
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        self_product_group::GroupElement<DIMENSION, SCALAR_LIMBS, Scalar>,
        Scalar,
        GroupElement,
    >,
{
    encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,

    #[serde(with = "const_generic_array_serialization")]
    ciphertexts: [CiphertextSpaceGroupElement::Value; DIMENSION],
}

impl<
        const MASK_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
        const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
        const DIMENSION: usize,
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
            WITNESS_SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            MASK_LIMBS,
            WITNESS_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product_group::GroupElement<DIMENSION, SCALAR_LIMBS, Scalar>,
            Scalar,
            additive_group_of_integers_modulu_n::GroupElement<MASK_LIMBS>,
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
        DIMENSION,
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
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
    Uint<MASK_LIMBS>: Encoding,
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
        self_product_group::GroupElement<DIMENSION, SCALAR_LIMBS, Scalar>,
        Scalar,
        GroupElement,
    >,
{
    type PublicParameters = PublicParameters<
        MASK_LIMBS,
        SCALAR_LIMBS,
        RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        DIMENSION,
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
    >;
    const NAME: &'static str = "Committed Linear Evaluation";

    fn group_homomorphism(
        witness: &direct_product::FourWayGroupElement<
            WITNESS_SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            MASK_LIMBS,
            WITNESS_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product_group::GroupElement<DIMENSION, SCALAR_LIMBS, Scalar>,
            Scalar,
            additive_group_of_integers_modulu_n::GroupElement<MASK_LIMBS>,
            RandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        witness_space_public_parameters: &<direct_product::FourWayGroupElement<
            WITNESS_SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            MASK_LIMBS,
            WITNESS_SCALAR_LIMBS,
            RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product_group::GroupElement<DIMENSION, SCALAR_LIMBS, Scalar>,
            Scalar,
            additive_group_of_integers_modulu_n::GroupElement<MASK_LIMBS>,
            RandomnessSpaceGroupElement,
        > as group::GroupElement<WITNESS_SCALAR_LIMBS>>::PublicParameters,
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
        let (coefficients, commitment_randomness, mask, encryption_randomness) = witness.into();

        let (_, scalar_group_public_parameters, _, randomness_group_public_parameters) =
            witness_space_public_parameters.into();

        let (ciphertext_group_public_parameters, group_public_parameters) =
            public_value_space_public_parameters.into();

        let encryption_key = EncryptionKey::new(
            &language_public_parameters.encryption_scheme_public_parameters,
            scalar_group_public_parameters,
            randomness_group_public_parameters,
            ciphertext_group_public_parameters,
        )?;

        let commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            group_public_parameters,
        )?;

        let ciphertexts =
            flat_map_results(language_public_parameters.ciphertexts.clone().map(|value| {
                CiphertextSpaceGroupElement::new(value, ciphertext_group_public_parameters)
            }))?;

        Ok((
            encryption_key.evaluate_linear_combination_with_randomness(
                coefficients.into(),
                &ciphertexts,
                &mask.retrieve(),
                encryption_randomness,
            )?,
            commitment_scheme.commit(coefficients, commitment_randomness),
        )
            .into())
    }
}

/// A Committed Linear Evaluation Schnorr Proof
#[allow(dead_code)]
pub type Proof<
    const MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
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
        DIMENSION,
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        RandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
    >,
    ProtocolContext,
>;
