// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

// TODO
// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

pub const REPETITIONS: usize = 1;

use crate::{
    ahe,
    ahe::{paillier::EncryptionKey as PaillierEncryptionKey, GroupsPublicParametersAccessors},
    commitments::{HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{
        direct_product, paillier, BoundedGroupElement, CyclicGroupElement, GroupElement as _,
        GroupElement, KnownOrderGroupElement, KnownOrderScalar, Samplable, ScalarPublicParameters,
    },
    proofs,
    proofs::{
        range,
        range::CommitmentSchemeMessageSpaceGroupElement,
        schnorr,
        schnorr::{
            enhanced::{DecomposableWitness, EnhanceableLanguage},
            language,
            language::GroupsPublicParameters,
        },
    },
    AdditivelyHomomorphicEncryptionKey,
};

// TODO: doc that this is a language just for class groups, otherwise we need the enhanced version.
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
#[derive(Clone, PartialEq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<REPETITIONS>
    for Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>
{
    type WitnessSpaceGroupElement = direct_product::GroupElement<
        EncryptionKey::PlaintextSpaceGroupElement,
        EncryptionKey::RandomnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement =
        direct_product::GroupElement<EncryptionKey::CiphertextSpaceGroupElement, GroupElement>;

    type PublicParameters = PublicParameters<
        group::PublicParameters<GroupElement::Scalar>,
        GroupElement::PublicParameters,
        GroupElement::Value,
        group::PublicParameters<EncryptionKey::PlaintextSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::RandomnessSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::CiphertextSpaceGroupElement>,
        EncryptionKey::PublicParameters,
    >;

    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let base = GroupElement::new(
            language_public_parameters.generator,
            language_public_parameters.group_public_parameters(),
        )?;

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let encryption_of_discrete_log =
            encryption_key.encrypt_with_randomness(witness.discrete_log(), witness.randomness());

        let base_by_discrete_log = base.scalar_mul(&witness.discrete_log().value().into());

        Ok((encryption_of_discrete_log, base_by_discrete_log).into())
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        REPETITIONS,
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        paillier::RandomnessSpaceGroupElement,
    >
    for Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        GroupElement,
        ahe::paillier::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: &[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
             RANGE_CLAIMS_PER_SCALAR],
        randomness: &paillier::RandomnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement> {
        let discrete_log = <paillier::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            SCALAR_LIMBS,
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            // TODO: make sure this is safe, e.g. SCALAR_LIMBS >=
            // COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
            &decomposed_witness.map(|range_claim| (&range_claim).into()),
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        Ok((discrete_log, *randomness).into())
    }

    fn decompose_witness(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR],
        paillier::RandomnessSpaceGroupElement,
    )> {
        let discrete_log_value: Uint<SCALAR_LIMBS> = (&witness.discrete_log().value()).into();
        let discrete_log = GroupElement::Scalar::new(
            discrete_log_value.into(),
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        Ok((
            discrete_log.decompose(range_claim_bits),
            *witness.randomness(),
        ))
    }
}

/// The Public Parameters of the Encryption of Discrete Log Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    ScalarPublicParameters,
    GroupPublicParameters,
    GroupElementValue,
    PlaintextSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CiphertextSpacePublicParameters,
    EncryptionKeyPublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::PublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    >,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    // The base of the discrete log
    pub generator: GroupElementValue,
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
    >
    for PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
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
    >
    PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    pub fn new<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement,
        EncryptionKey,
    >(
        scalar_group_public_parameters: ScalarPublicParameters,
        group_public_parameters: GroupPublicParameters,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    ) -> Self
    where
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + CyclicGroupElement
            + KnownOrderGroupElement<SCALAR_LIMBS>,
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
        // TODO: maybe we don't want the generator all the time?
        let generator = GroupElement::generator_from_public_parameters(&group_public_parameters);
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .plaintext_space_public_parameters()
                        .clone(),
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                )
                    .into(),
                statement_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                    group_public_parameters,
                )
                    .into(),
            },
            scalar_group_public_parameters,
            encryption_scheme_public_parameters,
            generator,
        }
    }

    pub fn plaintext_space_public_parameters(&self) -> &PlaintextSpacePublicParameters {
        let (plaintext_space_public_parameters, _) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        plaintext_space_public_parameters
    }

    pub fn randomness_space_public_parameters(&self) -> &RandomnessSpacePublicParameters {
        let (_, randomness_space_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        randomness_space_public_parameters
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        group_public_parameters
    }
}

pub trait WitnessAccessors<
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement;

    fn randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::GroupElement<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement {
        let (plaintext, _): (&_, &_) = self.into();

        plaintext
    }

    fn randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness): (&_, &_) = self.into();

        randomness
    }
}

pub trait StatementAccessors<
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement;

    // TODO: name
    fn base_by_discrete_log(&self) -> &GroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement, GroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>
{
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn base_by_discrete_log(&self) -> &GroupElement {
        let (_, base_by_discrete_log): (&_, &_) = self.into();

        base_by_discrete_log
    }
}

pub type EnhancedProof<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    CommitmentScheme,
    GroupElement,
    EncryptionKey,
    ProtocolContext,
> = schnorr::enhanced::Proof<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    SCALAR_LIMBS,
    CommitmentScheme,
    ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>,
    ProtocolContext,
>;

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
        group::{ristretto, secp256k1, self_product},
        proofs::schnorr::{
            aggregation, language, language::enhanced::tests::generate_scalar_plaintext,
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub type Lang = Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { U256::LIMBS },
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

        let language_public_parameters = PublicParameters::new::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            paillier_public_parameters,
        );

        language_public_parameters
    }

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let discrete_log = generate_scalar_plaintext();

            let randomness = paillier::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (discrete_log, randomness).into()
        })
        .take(batch_size)
        .collect()
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        schnorr::proof::enhanced::tests::valid_proof_verifies::<
            REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            paillier::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    // #[rstest]
    // #[case(1, 1)]
    // #[case(1, 2)]
    // #[case(2, 1)]
    // #[case(2, 3)]
    // #[case(5, 2)]
    // fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
    //     let language_public_parameters = public_parameters();
    //
    //     let witnesses =
    //         iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
    //             .take(number_of_parties)
    //             .collect();
    //
    //     aggregation::tests::aggregates::<REPETITIONS, Lang>(&language_public_parameters,
    // witnesses); }

    // TODO
    // #[rstest]
    // #[case(1)]
    // #[case(2)]
    // #[case(3)]
    // fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
    //     let (language_public_parameters, range_proof_public_parameters) = public_parameters();
    //
    //     language::enhanced::tests::proof_with_out_of_range_witness_fails::<
    //         REPETITIONS,
    //         { ristretto::SCALAR_LIMBS },
    //         RANGE_CLAIMS_PER_SCALAR,
    //         { range::bulletproofs::RANGE_CLAIM_LIMBS },
    //         WITNESS_MASK_LIMBS,
    //         Lang,
    //     >(
    //         &language_public_parameters,
    //         &range_proof_public_parameters,
    //         batch_size,
    //     )
    // }

    // #[rstest]
    // #[case(1)]
    // #[case(2)]
    // #[case(3)]
    // fn invalid_proof_fails_verification(#[case] batch_size: usize) {
    //     let language_public_parameters = public_parameters();
    //
    //     // TODO: have invalid points
    //
    //     // TODO: this test passes even when other tests fails, we should check why.
    //
    //     // No invalid values as secp256k1 statically defines group,
    //     // `k256::AffinePoint` assures deserialized values are on curve,
    //     // and `Value` can only be instantiated through deserialization
    //     language::tests::invalid_proof_fails_verification::<REPETITIONS, Lang>(
    //         None,
    //         None,
    //         language_public_parameters,
    //         batch_size,
    //     )
    // }
}

// #[cfg(feature = "benchmarking")]
// mod benches {
//     use criterion::Criterion;
//
//     use super::*;
//     use crate::{
//         ahe::paillier,
//         group::{ristretto, secp256k1},
//         proofs::{
//             range,
//             schnorr::{
//                 aggregation, language,
//                 language::encryption_of_discrete_log::tests::{public_parameters, Lang},
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
