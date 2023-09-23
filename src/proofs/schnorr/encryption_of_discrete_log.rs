// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use crate::{
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        CyclicGroupElement, KnownOrderGroupElement, Samplable,
    },
    proofs,
    proofs::{schnorr, schnorr::HomomorphicCommitmentScheme},
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
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS: usize, /* TODO: is the commitment randomness
                                                            * always like the witness? perhaps,
                                                            * better to change to batched
                                                            * commitment with the array in the
                                                            * commitment scheme trait not in
                                                            * pedersen. */
    const COMMITMENT_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const REMAINING_PUBLIC_VALUE_SCALAR_LIMBS: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    Scalar,
    PlaintextSpaceGroupElement,
    EncryptionRandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    CommitmentRandomnessSpaceGroupElement,
    CommitmentSpaceGroupElement,
    RangeProofCommitmentScheme,
    RangeProof,
> {
    _scalar_choice: PhantomData<Scalar>,
    _plaintext_group_choice: PhantomData<PlaintextSpaceGroupElement>,
    _group_element_choice: PhantomData<GroupElement>,
    _randomness_group_element_choice: PhantomData<EncryptionRandomnessSpaceGroupElement>,
    _ciphertext_group_element_choice: PhantomData<CiphertextSpaceGroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
    _commitment_randomness_group_element_choice: PhantomData<CommitmentRandomnessSpaceGroupElement>,
    _commitment_group_element_choice: PhantomData<CommitmentSpaceGroupElement>,
    _commitment_choice: PhantomData<RangeProofCommitmentScheme>,
    _range_proof_choice: PhantomData<RangeProof>,
}

/// The Public Parameters of the Encryption of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const COMMITMENT_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const REMAINING_PUBLIC_VALUE_SCALAR_LIMBS: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    Scalar,
    PlaintextSpaceGroupElement,
    EncryptionRandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    CommitmentRandomnessSpaceGroupElement,
    CommitmentSpaceGroupElement,
    RangeProofCommitmentScheme,
    RangeProof,
> where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    Scalar::Value:
        From<Uint<SCALAR_LIMBS>> + From<[Uint<RANGE_CLAIM_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>,
    Uint<SCALAR_LIMBS>: From<Scalar> + for<'a> From<&'a Scalar>,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        From<PlaintextSpaceGroupElement> + for<'a> From<&'a PlaintextSpaceGroupElement>,
    PlaintextSpaceGroupElement::Value: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
    EncryptionRandomnessSpaceGroupElement: group::GroupElement<ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS>
        + Samplable<ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: group::GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        EncryptionRandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
    >,
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    CommitmentRandomnessSpaceGroupElement:
        group::GroupElement<COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CommitmentSpaceGroupElement: group::GroupElement<COMMITMENT_SPACE_SCALAR_LIMBS>,
    RangeProofCommitmentScheme: HomomorphicCommitmentScheme<
        RANGE_CLAIM_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        self_product::GroupElement<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
        >,
        EncryptionRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
    >,
    RangeProof: proofs::RangeProof<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        EncryptionRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
        RangeProofCommitmentScheme,
    >,
{
    pub commitment_scheme_public_parameters: RangeProofCommitmentScheme::PublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub plaintext_group_public_parameters: PlaintextSpaceGroupElement::PublicParameters,
    pub randomness_group_public_parameters: EncryptionRandomnessSpaceGroupElement::PublicParameters,
    pub ciphertext_group_public_parameters: CiphertextSpaceGroupElement::PublicParameters,
    pub scalar_group_public_parameters: Scalar::PublicParameters,
    pub generator: GroupElement::Value, // The base of discrete log

    _commitment_randomness_group_element_choice: PhantomData<CommitmentRandomnessSpaceGroupElement>,
    _commitment_group_element_choice: PhantomData<CommitmentSpaceGroupElement>,
    _range_proof_choice: PhantomData<RangeProof>,
    // todo
    // todo: range claim.
}

impl<
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
        const COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
        const COMMITMENT_SPACE_SCALAR_LIMBS: usize,
        const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
        const REMAINING_PUBLIC_VALUE_SCALAR_LIMBS: usize,
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        Scalar,
        PlaintextSpaceGroupElement,
        EncryptionRandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
        RangeProofCommitmentScheme,
        RangeProof,
    >
    schnorr::Language<
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        direct_product::GroupElement<
            WITNESS_SCALAR_LIMBS,
            RANGE_CLAIM_LIMBS,
            ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product::GroupElement<
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
            >,
            EncryptionRandomnessSpaceGroupElement,
        >,
        direct_product::GroupElement<
            PUBLIC_VALUE_SCALAR_LIMBS,
            COMMITMENT_SPACE_SCALAR_LIMBS,
            REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
            CommitmentSpaceGroupElement,
            direct_product::GroupElement<
                REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
                CIPHERTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                CiphertextSpaceGroupElement,
                GroupElement,
            >,
        >,
    >
    for Language<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        PlaintextSpaceGroupElement,
        EncryptionRandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
        RangeProofCommitmentScheme,
        RangeProof,
    >
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    Scalar::Value:
        From<Uint<SCALAR_LIMBS>> + From<[Uint<RANGE_CLAIM_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>,
    Uint<SCALAR_LIMBS>: From<Scalar> + for<'a> From<&'a Scalar>,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    PlaintextSpaceGroupElement:
        KnownOrderGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, PlaintextSpaceGroupElement>,
    PlaintextSpaceGroupElement::Value: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        From<PlaintextSpaceGroupElement> + for<'a> From<&'a PlaintextSpaceGroupElement>,
    EncryptionRandomnessSpaceGroupElement: group::GroupElement<ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS>
        + Samplable<ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CiphertextSpaceGroupElement: group::GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        EncryptionRandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
    >,
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    CommitmentRandomnessSpaceGroupElement:
        group::GroupElement<COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CommitmentSpaceGroupElement: group::GroupElement<COMMITMENT_SPACE_SCALAR_LIMBS>,
    RangeProofCommitmentScheme: HomomorphicCommitmentScheme<
        RANGE_CLAIM_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        self_product::GroupElement<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
        >,
        EncryptionRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
    >,
    RangeProof: proofs::RangeProof<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        EncryptionRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
        RangeProofCommitmentScheme,
    >,
{
    type PublicParameters = PublicParameters<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        PlaintextSpaceGroupElement,
        EncryptionRandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
        RangeProofCommitmentScheme,
        RangeProof,
    >;
    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &direct_product::GroupElement<
            WITNESS_SCALAR_LIMBS,
            RANGE_CLAIM_LIMBS,
            ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product::GroupElement<
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
            >,
            EncryptionRandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        witness_space_public_parameters: &direct_product::PublicParameters<
            WITNESS_SCALAR_LIMBS,
            RANGE_CLAIM_LIMBS,
            ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
            self_product::GroupElement<
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
            >,
            EncryptionRandomnessSpaceGroupElement,
        >,
        public_value_space_public_parameters: &direct_product::PublicParameters<
            PUBLIC_VALUE_SCALAR_LIMBS,
            COMMITMENT_SPACE_SCALAR_LIMBS,
            REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
            CommitmentSpaceGroupElement,
            direct_product::GroupElement<
                REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
                CIPHERTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                CiphertextSpaceGroupElement,
                GroupElement,
            >,
        >,
    ) -> proofs::Result<
        direct_product::GroupElement<
            PUBLIC_VALUE_SCALAR_LIMBS,
            COMMITMENT_SPACE_SCALAR_LIMBS,
            REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
            CommitmentSpaceGroupElement,
            direct_product::GroupElement<
                REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
                CIPHERTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                CiphertextSpaceGroupElement,
                GroupElement,
            >,
        >,
    > {
        let (discrete_log_parts, encryption_randomness) = witness.into();

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
            &language_public_parameters.randomness_group_public_parameters,
            &language_public_parameters.ciphertext_group_public_parameters,
        )?;

        let commitment_scheme = RangeProofCommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            commitment_public_parameters,
        )?;

        let discrete_log_parts: [power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR] = (*discrete_log_parts).into();
        let discrete_log: Scalar::Value = discrete_log_parts
            .map(|element| Uint::<RANGE_CLAIM_LIMBS>::from(element))
            .into();

        let discrete_log = Scalar::new(
            discrete_log,
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        // Ok((commitment_scheme.commit(&[value].into(), commitment_randomness),
        //                 (
        //     encryption_key.encrypt_with_randomness(discrete_log, encryption_randomness),
        //     base * discrete_log,
        // )
        //     .into()).into()

        todo!()
    }
}

/// An Encryption of Discrete Log Schnorr Proof
pub type Proof<
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const COMMITMENT_SPACE_SCALAR_LIMBS: usize,
    const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize,
    const REMAINING_PUBLIC_VALUE_SCALAR_LIMBS: usize,
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    Scalar,
    PlaintextSpaceGroupElement,
    EncryptionRandomnessSpaceGroupElement,
    CiphertextSpaceGroupElement,
    GroupElement,
    EncryptionKey,
    CommitmentRandomnessSpaceGroupElement,
    CommitmentSpaceGroupElement,
    RangeProofCommitmentScheme,
    RangeProof,
    ProtocolContext,
> = schnorr::Proof<
    WITNESS_SCALAR_LIMBS,
    PUBLIC_VALUE_SCALAR_LIMBS,
    direct_product::GroupElement<
        WITNESS_SCALAR_LIMBS,
        RANGE_CLAIM_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        self_product::GroupElement<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>,
        >,
        EncryptionRandomnessSpaceGroupElement,
    >,
    direct_product::GroupElement<
        PUBLIC_VALUE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
        CommitmentSpaceGroupElement,
        direct_product::GroupElement<
            REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
            CIPHERTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            CiphertextSpaceGroupElement,
            GroupElement,
        >,
    >,
    Language<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        ENCRYPTION_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_RANDOMNESS_SPACE_SCALAR_LIMBS,
        COMMITMENT_SPACE_SCALAR_LIMBS,
        CIPHERTEXT_SPACE_SCALAR_LIMBS,
        REMAINING_PUBLIC_VALUE_SCALAR_LIMBS,
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        Scalar,
        PlaintextSpaceGroupElement,
        EncryptionRandomnessSpaceGroupElement,
        CiphertextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
        CommitmentRandomnessSpaceGroupElement,
        CommitmentSpaceGroupElement,
        RangeProofCommitmentScheme,
        RangeProof,
    >,
    ProtocolContext,
>;
