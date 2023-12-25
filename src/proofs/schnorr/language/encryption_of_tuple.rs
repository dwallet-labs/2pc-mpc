// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Uint};
use language::GroupsPublicParameters;
use schnorr::language;
use serde::{Deserialize, Serialize};

use crate::{
    ahe,
    ahe::GroupsPublicParametersAccessors as _,
    commitments::{GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme},
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product,
        direct_product::ThreeWayPublicParameters, self_product, BoundedGroupElement,
        GroupElement as _, KnownOrderGroupElement, KnownOrderScalar, Samplable,
    },
    proofs,
    proofs::{
        range,
        range::CommitmentSchemeMessageSpaceGroupElement,
        schnorr,
        schnorr::{
            aggregation,
            enhanced::{
                DecomposableWitness, EnhanceableLanguage, EnhancedLanguageStatementAccessors as _,
                EnhancedLanguageWitnessAccessors as _,
            },
        },
    },
    AdditivelyHomomorphicEncryptionKey, ComputationalSecuritySizedNumber,
    StatisticalSecuritySizedNumber,
};

pub(crate) const REPETITIONS: usize = 1;

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
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

pub type EnhancedLanguage<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    CommitmentScheme,
    GroupElement,
    EncryptionKey,
> = schnorr::enhanced::EnhancedLanguage<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    SCALAR_LIMBS,
    CommitmentScheme,
    ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>,
>;

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<REPETITIONS>
    for Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>
{
    type WitnessSpaceGroupElement = direct_product::ThreeWayGroupElement<
        EncryptionKey::PlaintextSpaceGroupElement,
        EncryptionKey::RandomnessSpaceGroupElement,
        EncryptionKey::RandomnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement =
        self_product::GroupElement<2, EncryptionKey::CiphertextSpaceGroupElement>;

    type PublicParameters = PublicParameters<
        group::PublicParameters<GroupElement::Scalar>,
        group::PublicParameters<EncryptionKey::PlaintextSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::RandomnessSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::CiphertextSpaceGroupElement>,
        EncryptionKey::PublicParameters,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
    >;

    const NAME: &'static str = "Encryption of a Tuple";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let group_order = GroupElement::Scalar::order_from_public_parameters(
            &language_public_parameters.scalar_group_public_parameters,
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let ciphertext =
            ahe::CiphertextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                language_public_parameters.ciphertext,
                &language_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        // TODO: name?
        let encryption_of_multiplicant = encryption_key
            .encrypt_with_randomness(witness.multiplicant(), witness.multiplicant_randomness());

        // no mask needed, as we're not doing any homomorphic additions? TODO: why
        let mask = witness.multiplicant().neutral();

        // TODO: name?
        let encryption_of_multiplication = encryption_key
            .evaluate_circuit_private_linear_combination_with_randomness(
                &[*witness.multiplicant()],
                &[ciphertext],
                &group_order,
                &mask,
                witness.multiplication_randomness(),
            )?;

        Ok([encryption_of_multiplicant, encryption_of_multiplication].into())
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        REPETITIONS,
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        self_product::GroupElement<
            2,
            ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >,
    > for Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>
{
    fn compose_witness(
        decomposed_witness: &[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
             RANGE_CLAIMS_PER_SCALAR],
        unbounded_witness: &self_product::GroupElement<
            2,
            ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement> {
        // TODO: perhaps this was the bug, that I'm saying this is scalar here.
        let multiplicant = <EncryptionKey::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
        >>::compose(
            // TODO: make sure this is safe, e.g. SCALAR_LIMBS >=
            // COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
            &decomposed_witness.map(|range_claim| (&range_claim).into()),
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            crypto_bigint::U128::BITS,
            // TODO: why not working for U192
            // range_claim_bits::<SCALAR_LIMBS>(), // TODO: range proof's
        )?;

        let multiplicant_randomness = <&[_; 2]>::from(unbounded_witness)[0].clone();
        let multiplication_randomness = <&[_; 2]>::from(unbounded_witness)[1].clone();

        Ok((
            multiplicant,
            multiplicant_randomness,
            multiplication_randomness,
        )
            .into())
    }

    fn decompose_witness(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR],
        self_product::GroupElement<
            2,
            ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        >,
    )> {
        let multiplicant_value: Uint<SCALAR_LIMBS> =
            (&witness.multiplicant().value().into()).into();
        let multiplicant = GroupElement::Scalar::new(
            multiplicant_value.into(),
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        // Ok(discrete_log.decompose(range_claim_bits::<SCALAR_LIMBS>()))
        // TODO
        // Ok(discrete_log.decompose(crypto_bigint::U192::BITS))
        Ok((
            multiplicant.decompose(crypto_bigint::U128::BITS),
            [
                witness.multiplicant_randomness().clone(),
                witness.multiplication_randomness().clone(),
            ]
            .into(),
        ))
    }
}

/// The Public Parameters of the Encryption of a Tuple Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    ScalarPublicParameters,
    PlaintextSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CiphertextSpacePublicParameters,
    EncryptionKeyPublicParameters,
    CiphertextSpaceValue,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
    >,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    // TODO: name
    pub ciphertext: CiphertextSpaceValue,
}

impl<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::ThreeWayPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
        >,
    >
    for PublicParameters<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        ThreeWayPublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters: AsRef<
            ahe::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
        CiphertextSpaceValue,
    >
    PublicParameters<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
{
    pub fn new<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey,
    >(
        scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        ciphertext: CiphertextSpaceValue,
    ) -> Self
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = EncryptionKeyPublicParameters,
        >,
        EncryptionKey::PlaintextSpaceGroupElement:
            group::GroupElement<PublicParameters = PlaintextSpacePublicParameters>,
        EncryptionKey::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        EncryptionKey::CiphertextSpaceGroupElement:
            group::GroupElement<PublicParameters = CiphertextSpacePublicParameters>,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .plaintext_space_public_parameters()
                        .clone(),
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                )
                    .into(),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, EncryptionKey::CiphertextSpaceGroupElement>,
                >::new(
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                ),
            },
            scalar_group_public_parameters,
            encryption_scheme_public_parameters,
            ciphertext,
        }
    }
}

pub trait WitnessAccessors<
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    // TODO: names
    fn multiplicant(&self) -> &PlaintextSpaceGroupElement;

    fn multiplicant_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn multiplication_randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::ThreeWayGroupElement<
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
        RandomnessSpaceGroupElement,
    >
{
    fn multiplicant(&self) -> &PlaintextSpaceGroupElement {
        let (multiplicant, ..): (&_, &_, &_) = self.into();

        multiplicant
    }

    fn multiplicant_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, multiplicant_randomness, _): (&_, &_, &_) = self.into();

        multiplicant_randomness
    }

    fn multiplication_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, _, multiplication_randomness): (&_, &_, &_) = self.into();

        multiplication_randomness
    }
}

pub trait StatementAccessors<CiphertextSpaceGroupElement: group::GroupElement> {
    // TODO: names
    fn encryption_of_multiplicant(&self) -> &CiphertextSpaceGroupElement;

    fn encryption_of_multiplication(&self) -> &CiphertextSpaceGroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement>
    for self_product::GroupElement<2, CiphertextSpaceGroupElement>
{
    fn encryption_of_multiplicant(&self) -> &CiphertextSpaceGroupElement {
        let value: &[_; 2] = self.into();

        &value[0]
    }

    fn encryption_of_multiplication(&self) -> &CiphertextSpaceGroupElement {
        let value: &[_; 2] = self.into();

        &value[1]
    }
}

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::{array, iter};

    use crypto_bigint::{NonZero, Random, U128, U256};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        ahe::paillier,
        commitments::Pedersen,
        group::{ristretto, secp256k1, self_product},
        proofs::schnorr::{aggregation, language},
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub type Lang = Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { U256::LIMBS },
        secp256k1::GroupElement,
        paillier::EncryptionKey,
    >;

    pub type EnhancedLang = EnhancedLanguage<
        { RANGE_CLAIMS_PER_SCALAR },
        { secp256k1::SCALAR_LIMBS },
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        Pedersen<
            { RANGE_CLAIMS_PER_SCALAR },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >,
        secp256k1::GroupElement,
        paillier::EncryptionKey,
    >;

    use crate::{
        commitments::pedersen,
        proofs::schnorr::language::enhanced::tests::{
            enhanced_language_public_parameters, RANGE_CLAIMS_PER_SCALAR,
        },
    };

    pub(crate) fn public_parameters() -> language::PublicParameters<REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let plaintext = paillier::PlaintextSpaceGroupElement::new(
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64(42u64),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext = paillier_encryption_key
            .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
            .unwrap()
            .1
            .value();

        let language_public_parameters = PublicParameters::new::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >(
            secp256k1_scalar_public_parameters,
            paillier_public_parameters,
            ciphertext,
        );

        language_public_parameters
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        language::tests::valid_proof_verifies::<REPETITIONS, Lang>(
            language_public_parameters,
            batch_size,
        );
    }
}

// #[cfg(any(test, feature = "benchmarking"))]
// pub(crate) mod tests {
//     use crypto_bigint::{NonZero, Random};
//     use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
//     use paillier::tests::N;
//     use rand_core::OsRng;
//     use rstest::rstest;
//
//     use super::*;
//     use crate::{
//         ahe::paillier,
//         group::{ristretto, secp256k1, self_product},
//         proofs::{
//             range,
//             range::bulletproofs,
//             schnorr::{aggregation, language},
//             RangeProof,
//         },
//         ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
//     };
//
//     pub(crate) type Lang = Language<
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
//     >;
//
//     pub(crate) fn public_parameters() -> (
//         language::PublicParameters<REPETITIONS, Lang>,
//         language::enhanced::RangeProofPublicParameters<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >,
//     ) {
//         let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
//
//         let secp256k1_group_public_parameters =
//             secp256k1::group_element::PublicParameters::default();
//
//         let bulletproofs_public_parameters =
//             range::bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();
//
//         let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();
//
//         let plaintext = paillier::PlaintextGroupElement::new(
//             Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64(42u64),
//             paillier_public_parameters.plaintext_space_public_parameters(),
//         )
//         .unwrap();
//
//         let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();
//
//         let paillier_encryption_key =
//             paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();
//
//         let ciphertext = paillier_encryption_key
//             .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
//             .unwrap()
//             .1
//             .value();
//
//         let language_public_parameters = PublicParameters::new::<
//             { secp256k1::SCALAR_LIMBS },
//             { ristretto::SCALAR_LIMBS },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
//             secp256k1::Scalar,
//             secp256k1::GroupElement,
//             paillier::EncryptionKey,
//             bulletproofs::RangeProof,
//         >(
//             secp256k1_scalar_public_parameters,
//             bulletproofs_public_parameters.clone(),
//             paillier_public_parameters,
//             ciphertext,
//         );
//
//         (language_public_parameters, bulletproofs_public_parameters)
//     }
//
//     #[rstest]
//     #[case(1)]
//     #[case(2)]
//     #[case(3)]
//     fn valid_proof_verifies(#[case] batch_size: usize) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::enhanced::tests::valid_proof_verifies::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             batch_size,
//         )
//     }
//
//     #[rstest]
//     #[case(1, 1)]
//     #[case(1, 2)]
//     #[case(2, 1)]
//     #[case(2, 3)]
//     #[case(5, 2)]
//     fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
//         let (language_public_parameters, _) = public_parameters();
//         let witnesses = language::enhanced::tests::generate_witnesses_for_aggregation::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(&language_public_parameters, number_of_parties, batch_size);
//
//         aggregation::tests::aggregates::<REPETITIONS, Lang>(&language_public_parameters,
// witnesses)     }
//
//     #[rstest]
//     #[case(1)]
//     #[case(2)]
//     #[case(3)]
//     fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::enhanced::tests::proof_with_out_of_range_witness_fails::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             batch_size,
//         )
//     }
//
//     #[rstest]
//     #[case(1)]
//     #[case(2)]
//     #[case(3)]
//     fn invalid_proof_fails_verification(#[case] batch_size: usize) {
//         let (language_public_parameters, _) = public_parameters();
//
//         // No invalid values as secp256k1 statically defines group,
//         // `k256::AffinePoint` assures deserialized values are on curve,
//         // and `Value` can only be instantiated through deserialization
//         language::tests::invalid_proof_fails_verification::<REPETITIONS, Lang>(
//             None,
//             None,
//             language_public_parameters,
//             batch_size,
//         )
//     }
// }
//
// #[cfg(feature = "benchmarking")]
// mod benches {
//     use criterion::Criterion;
//     use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
//
//     use super::*;
//     use crate::{
//         ahe::paillier,
//         group::{ristretto, secp256k1},
//         proofs::{
//             range,
//             schnorr::{
//                 aggregation, language,
//                 language::encryption_of_tuple::tests::{public_parameters, Lang},
//             },
//         },
//         ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
//     };
//
//     pub(crate) fn benchmark(c: &mut Criterion) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::benchmark::<REPETITIONS, Lang>(language_public_parameters.clone(), None, c);
//
//         range::benchmark::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             { RANGE_CLAIMS_PER_SCALAR },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             c,
//         );
//
//         aggregation::benchmark_enhanced::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             { RANGE_CLAIMS_PER_SCALAR },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(language_public_parameters, None, c);
//     }
// }
