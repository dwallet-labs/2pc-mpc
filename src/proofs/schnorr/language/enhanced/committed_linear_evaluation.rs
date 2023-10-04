// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{array, marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
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
        GroupElement as _, KnownOrderScalar, Samplable,
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
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<super::ConstrainedWitnessValue<NUM_RANGE_CLAIMS, WITNESS_MASK_LIMBS>>,
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

        let a = coefficients_and_mask_in_witness_mask_base;
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

        let coefficients_and_mask_commitment_message =
            range::CommitmentSchemeMessageSpaceGroupElement::<
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RANGE_CLAIM_LIMBS,
                RangeProof,
            >::new(
                a.value().into(),
                &language_public_parameters
                    .range_proof_commitment_scheme_public_parameters
                    .as_ref()
                    .message_space_public_parameters,
            )?;

        Ok((
            range_proof_commitment_scheme.commit(
                &coefficients_and_mask_commitment_message,
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
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<super::ConstrainedWitnessValue<NUM_RANGE_CLAIMS, WITNESS_MASK_LIMBS>>,
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

#[cfg(any(test, feature = "benchmarking"))]
mod tests {
    use std::array;

    use crypto_bigint::{NonZero, Random, U64};
    use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        ahe::paillier,
        commitments::{pedersen, Pedersen},
        group::{ristretto, secp256k1, self_product},
        proofs::{
            range,
            schnorr::{aggregation, language},
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub(crate) const MASK_LIMBS: usize =
        secp256k1::SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

    // TODO: what's the real dimension in the paper?
    pub(crate) const DIMENSION: usize = 2;

    pub(crate) const RANGE_CLAIMS_PER_MASK: usize = 6;

    pub(crate) const NUM_RANGE_CLAIMS: usize =
        RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK;

    pub(crate) fn public_parameters() -> (
        language::PublicParameters<
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                NUM_RANGE_CLAIMS,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >,
        language::enhanced::RangeProofPublicParameters<
            { ristretto::SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                NUM_RANGE_CLAIMS,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >,
    ) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            range::bulletproofs::PublicParameters::<NUM_RANGE_CLAIMS>::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N);

        let paillier_encryption_key =
            paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let ciphertexts = array::from_fn(|_| u64::from(U64::random(&mut OsRng)))
            .map(Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64)
            .map(|plaintext| {
                paillier::PlaintextGroupElement::new(
                    plaintext,
                    &paillier_public_parameters
                        .as_ref()
                        .plaintext_space_public_parameters,
                )
                .unwrap()
            })
            .map(|plaintext| {
                paillier_encryption_key
                    .encrypt(
                        &plaintext,
                        &paillier_public_parameters
                            .as_ref()
                            .randomness_space_public_parameters,
                        &mut OsRng,
                    )
                    .unwrap()
                    .1
                    .value()
            });

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let message_generators = array::from_fn(|_| {
            (secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
                * generator)
                .value()
        });

        let randomness_generator =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
                * generator;

        // TODO: this is not safe; we need a proper way to derive generators
        let pedersen_public_parameters = pedersen::public_parameters::<
            DIMENSION,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
            message_generators,
            randomness_generator.value(),
        );

        // TODO: think how we can generalize this with `new()` for `PublicParameters` (of encryption
        // of discrete log).

        let witness_space_public_parameters = (
            self_product::PublicParameters::<NUM_RANGE_CLAIMS, ()>::new(()),
            bulletproofs_public_parameters
                .as_ref()
                .as_ref()
                .randomness_space_public_parameters
                .clone(),
            (
                secp256k1_scalar_public_parameters.clone(),
                paillier_public_parameters
                    .as_ref()
                    .randomness_space_public_parameters
                    .clone(),
            )
                .into(),
        )
            .into();

        let statement_space_public_parameters = (
            bulletproofs_public_parameters
                .as_ref()
                .as_ref()
                .commitment_space_public_parameters
                .clone(),
            (
                paillier_public_parameters
                    .as_ref()
                    .ciphertext_space_public_parameters
                    .clone(),
                secp256k1_group_public_parameters.clone(),
            )
                .into(),
        )
            .into();

        let groups_public_parameters = GroupsPublicParameters {
            witness_space_public_parameters,
            statement_space_public_parameters,
        };

        let language_public_parameters = PublicParameters {
            groups_public_parameters,
            commitment_scheme_public_parameters: pedersen_public_parameters,
            range_proof_commitment_scheme_public_parameters: bulletproofs_public_parameters
                .as_ref()
                .clone(),
            encryption_scheme_public_parameters: paillier_public_parameters,
            scalar_group_public_parameters: secp256k1_scalar_public_parameters,
            ciphertexts,
        };

        (language_public_parameters, bulletproofs_public_parameters)
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let (language_public_parameters, range_proof_public_parameters) = public_parameters();

        language::enhanced::tests::valid_proof_verifies::<
            { ristretto::SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >(
            &language_public_parameters,
            &range_proof_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let (language_public_parameters, _) = public_parameters();
        let witnesses = language::enhanced::tests::generate_witnesses_for_aggregation::<
            { ristretto::SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >(&language_public_parameters, number_of_parties, batch_size);

        aggregation::tests::aggregates::<
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >(&language_public_parameters, witnesses)
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
        let (language_public_parameters, range_proof_public_parameters) = public_parameters();

        language::enhanced::tests::proof_with_out_of_range_witness_fails::<
            { ristretto::SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >(
            &language_public_parameters,
            &range_proof_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let (language_public_parameters, _) = public_parameters();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        language::tests::invalid_proof_fails_verification::<
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >(None, None, language_public_parameters, batch_size)
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;
    use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};

    use super::*;
    use crate::{
        ahe::paillier,
        commitments::Pedersen,
        group::{ristretto, secp256k1},
        proofs::{
            range,
            schnorr::{
                language,
                language::committed_linear_evaluation::tests::{
                    public_parameters, DIMENSION, MASK_LIMBS, NUM_RANGE_CLAIMS,
                    RANGE_CLAIMS_PER_MASK,
                },
            },
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub(crate) fn benchmark(c: &mut Criterion) {
        let (language_public_parameters, range_proof_public_parameters) = public_parameters();

        language::benchmark::<
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >(language_public_parameters.clone(), c);

        range::benchmark::<
            { ristretto::SCALAR_LIMBS },
            { NUM_RANGE_CLAIMS },
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { MASK_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                { NUM_RANGE_CLAIMS },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { DIMENSION },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                Pedersen<
                    { DIMENSION },
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
                bulletproofs::RangeProof,
            >,
        >(
            &language_public_parameters,
            &range_proof_public_parameters,
            c,
        );
    }
}
