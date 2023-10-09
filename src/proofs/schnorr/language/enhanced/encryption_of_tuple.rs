// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Uint};
use language::GroupsPublicParameters;
use schnorr::language;
use serde::Serialize;

use super::EnhancedLanguage;
use crate::{
    ahe,
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        BoundedGroupElement, GroupElement as _, KnownOrderScalar, Samplable,
    },
    proofs,
    proofs::{range, schnorr},
    AdditivelyHomomorphicEncryptionKey,
};

/// Encryption of a Tuple Schnorr Language
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
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
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

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof,
    > schnorr::Language
    for Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Mul<Scalar, Output = Scalar>
        + for<'r> Mul<&'r Scalar, Output = Scalar>
        + Copy,
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<super::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
    >,
{
    type WitnessSpaceGroupElement = super::EnhancedLanguageWitness<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self,
    >;

    type StatementSpaceGroupElement = super::EnhancedLanguageStatement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self,
    >;

    type PublicParameters = PublicParameters<
        language::WitnessSpacePublicParameters<Self>,
        language::StatementSpacePublicParameters<Self>,
        range::CommitmentSchemePublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >,
        ahe::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        group::PublicParameters<Scalar>,
        ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;
    const NAME: &'static str = "Encryption of a Tuple";
    fn group_homomorphism(
        witness: &language::WitnessSpaceGroupElement<Self>,
        language_public_parameters: &language::PublicParameters<Self>,
    ) -> proofs::Result<language::StatementSpaceGroupElement<Self>> {
        // TODO: variable names
        let (scalar_witness_mask_base_element, commitment_randomness, encryptions_randomnesses) =
            witness.into();

        let [encryption_randomness, evaluation_randomness]: &[ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;
             2] = encryptions_randomnesses.into();

        let scalar_group_order = Scalar::order_from_public_parameters(
            &language_public_parameters.scalar_group_public_parameters,
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
        )?;

        let ciphertext =
            ahe::CiphertextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                language_public_parameters.ciphertext,
                &language_public_parameters
                    .encryption_scheme_public_parameters
                    .as_ref()
                    .ciphertext_space_public_parameters,
            )?;

        let scalar_witness_mask_base: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR] = (*scalar_witness_mask_base_element).into();

        let scalar_witness_mask_base: [Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR] =
            scalar_witness_mask_base.map(|element| Uint::<WITNESS_MASK_LIMBS>::from(element));

        let scalar: Scalar = super::witness_mask_base_to_scalar::<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            SCALAR_LIMBS,
            Scalar,
        >(
            scalar_witness_mask_base,
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        let scalar_plaintext: ahe::PlaintextSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        > = super::witness_mask_base_to_scalar::<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            ahe::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >(
            scalar_witness_mask_base,
            &language_public_parameters
                .encryption_scheme_public_parameters
                .as_ref()
                .plaintext_space_public_parameters,
        )?;

        let scalar_commitment_message = range::CommitmentSchemeMessageSpaceGroupElement::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >::new(
            scalar_witness_mask_base_element.value().into(),
            &language_public_parameters
                .commitment_scheme_public_parameters
                .as_ref()
                .message_space_public_parameters,
        )?;

        // TODO: Need to check that WITNESS_MASK_LIMBS is actually in a size fitting the range proof
        // commitment scheme without going through modulation, and to implement `From` to
        // transition.
        Ok((
            commitment_scheme.commit(&scalar_commitment_message, commitment_randomness),
            [
                encryption_key.encrypt_with_randomness(&scalar_plaintext, encryption_randomness),
                encryption_key.evaluate_circuit_private_linear_combination_with_randomness(
                    &[scalar_plaintext],
                    &[ciphertext],
                    &scalar_group_order,
                    &scalar_plaintext.neutral(),
                    evaluation_randomness,
                )?,
            ]
            .into(),
        )
            .into())
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar: group::GroupElement,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof,
    >
    EnhancedLanguage<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
    >
    for Language<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Mul<Scalar, Output = Scalar>
        + for<'r> Mul<&'r Scalar, Output = Scalar>
        + Copy,
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<super::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
    >,
{
    type UnboundedWitnessSpaceGroupElement = self_product::GroupElement<
        2,
        ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;

    type RemainingStatementSpaceGroupElement = self_product::GroupElement<
        2,
        ahe::CiphertextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >;

    type RangeProof = RangeProof;
}

/// The Public Parameters of the Encryption of a Tuple Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    WitnessSpacePublicParameters,
    StatementSpacePublicParameters,
    CommitmentSchemePublicParameters,
    EncryptionKeyPublicParameters,
    ScalarPublicParameters,
    CiphertextSpaceValue,
> {
    pub groups_public_parameters:
        GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub ciphertext: CiphertextSpaceValue,
}

impl<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
        EncryptionKeyPublicParameters,
        ScalarPublicParameters,
        CiphertextSpaceValue,
    > AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
    for PublicParameters<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
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
pub(crate) mod tests {
    use std::array;

    use crypto_bigint::{NonZero, Random};
    use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        ahe::paillier,
        group::{ristretto, secp256k1, self_product},
        proofs::{
            range,
            range::bulletproofs::RANGE_CLAIM_BITS,
            schnorr::{aggregation, language},
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub(crate) fn public_parameters() -> (
        language::PublicParameters<
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                bulletproofs::RangeProof,
            >,
        >,
        language::enhanced::RangeProofPublicParameters<
            { ristretto::SCALAR_LIMBS },
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                bulletproofs::RangeProof,
            >,
        >,
    ) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            range::bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        // TODO: think how we can generalize this with `new()` for `PublicParameters` (of encryption
        // of discrete log).

        let constrained_witness_public_parameters =
            power_of_two_moduli::PublicParameters::<WITNESS_MASK_LIMBS> {
                sampling_bit_size: RANGE_CLAIM_BITS
                    + ComputationalSecuritySizedNumber::BITS
                    + StatisticalSecuritySizedNumber::BITS,
            };

        let witness_space_public_parameters = (
            self_product::PublicParameters::<
                RANGE_CLAIMS_PER_SCALAR,
                power_of_two_moduli::PublicParameters<WITNESS_MASK_LIMBS>,
            >::new(constrained_witness_public_parameters),
            bulletproofs_public_parameters
                .as_ref()
                .as_ref()
                .randomness_space_public_parameters
                .clone(),
            self_product::PublicParameters::<
                2,
                ahe::RandomnessSpacePublicParameters<
                    { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                    paillier::EncryptionKey,
                >,
            >::new(
                paillier_public_parameters
                    .as_ref()
                    .randomness_space_public_parameters
                    .clone(),
            ),
        )
            .into();

        let statement_space_public_parameters = (
            bulletproofs_public_parameters
                .as_ref()
                .as_ref()
                .commitment_space_public_parameters
                .clone(),
            self_product::PublicParameters::<
                2,
                ahe::CiphertextSpacePublicParameters<
                    { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                    paillier::EncryptionKey,
                >,
            >::new(
                paillier_public_parameters
                    .as_ref()
                    .ciphertext_space_public_parameters
                    .clone(),
            )
            .into(),
        )
            .into();

        let groups_public_parameters = GroupsPublicParameters {
            witness_space_public_parameters,
            statement_space_public_parameters,
        };

        let plaintext = paillier::PlaintextGroupElement::new(
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64(42u64),
            &paillier_public_parameters
                .as_ref()
                .plaintext_space_public_parameters,
        )
        .unwrap();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let ciphertext = paillier_encryption_key
            .encrypt(
                &plaintext,
                &paillier_public_parameters
                    .as_ref()
                    .randomness_space_public_parameters,
                &mut OsRng,
            )
            .unwrap()
            .1
            .value();

        let language_public_parameters = PublicParameters {
            groups_public_parameters,
            commitment_scheme_public_parameters: bulletproofs_public_parameters.as_ref().clone(),
            encryption_scheme_public_parameters: paillier_public_parameters,
            scalar_group_public_parameters: secp256k1_scalar_public_parameters,
            ciphertext,
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
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { RANGE_CLAIMS_PER_SCALAR },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
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
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { RANGE_CLAIMS_PER_SCALAR },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                bulletproofs::RangeProof,
            >,
        >(&language_public_parameters, number_of_parties, batch_size);

        aggregation::tests::aggregates::<
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { RANGE_CLAIMS_PER_SCALAR },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
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
            RANGE_CLAIMS_PER_SCALAR,
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                { RANGE_CLAIMS_PER_SCALAR },
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
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
                RANGE_CLAIMS_PER_SCALAR,
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
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
        group::{ristretto, secp256k1},
        proofs::{
            range,
            schnorr::{
                aggregation, language, language::encryption_of_tuple::tests::public_parameters,
            },
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub(crate) fn benchmark(c: &mut Criterion) {
        let (language_public_parameters, range_proof_public_parameters) = public_parameters();

        // language::benchmark::<
        //     Language<
        //         { secp256k1::SCALAR_LIMBS },
        //         { ristretto::SCALAR_LIMBS },
        //         RANGE_CLAIMS_PER_SCALAR,
        //         { range::bulletproofs::RANGE_CLAIM_LIMBS },
        //         { WITNESS_MASK_LIMBS },
        //         { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        //         secp256k1::Scalar,
        //         secp256k1::GroupElement,
        //         paillier::EncryptionKey,
        //         bulletproofs::RangeProof,
        //     >,
        // >(language_public_parameters.clone(), c);

        range::benchmark::<
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { range::bulletproofs::RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            Language<
                { secp256k1::SCALAR_LIMBS },
                { ristretto::SCALAR_LIMBS },
                RANGE_CLAIMS_PER_SCALAR,
                { range::bulletproofs::RANGE_CLAIM_LIMBS },
                { WITNESS_MASK_LIMBS },
                { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                paillier::EncryptionKey,
                bulletproofs::RangeProof,
            >,
        >(
            &language_public_parameters,
            &range_proof_public_parameters,
            c,
        );

        // aggregation::benchmark_enhanced::<
        //     { ristretto::SCALAR_LIMBS },
        //     { RANGE_CLAIMS_PER_SCALAR },
        //     { range::bulletproofs::RANGE_CLAIM_LIMBS },
        //     WITNESS_MASK_LIMBS,
        //     Language<
        //         { secp256k1::SCALAR_LIMBS },
        //         { ristretto::SCALAR_LIMBS },
        //         RANGE_CLAIMS_PER_SCALAR,
        //         { range::bulletproofs::RANGE_CLAIM_LIMBS },
        //         { WITNESS_MASK_LIMBS },
        //         { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        //         secp256k1::Scalar,
        //         secp256k1::GroupElement,
        //         paillier::EncryptionKey,
        //         bulletproofs::RangeProof,
        //     >,
        // >(language_public_parameters, c);
    }
}
