// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

// TODO
// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

pub use crate::proofs::lightning::enhanced_schnorr::REPETITIONS;
use crate::{
    ahe,
    ahe::{paillier::EncryptionKey as PaillierEncryptionKey, GroupsPublicParametersAccessors},
    commitments::{HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{
        direct_product, paillier, BoundedGroupElement, CyclicGroupElement, GroupElement as _,
        GroupElement, KnownOrderScalar, Samplable,
    },
    proofs,
    proofs::{
        lightning,
        lightning::{
            enhanced_schnorr::{
                ConstrainedWitnessGroupElement, DecomposableWitness, EnhanceableLanguage,
            },
            range_claim_bits,
        },
        schnorr,
        schnorr::language::GroupsPublicParameters,
    },
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
#[derive(Clone, PartialEq)]
pub struct Language<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, GroupElement, EncryptionKey> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

pub type EnhancedLanguage<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
> = lightning::enhanced_schnorr::EnhancedLanguage<
    NUM_RANGE_CLAIMS,
    SCALAR_LIMBS,
    Scalar,
    GroupElement,
    paillier::RandomnessSpaceGroupElement,
    Language<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }, GroupElement, PaillierEncryptionKey>,
>;

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<REPETITIONS>
    for Language<PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>
{
    type WitnessSpaceGroupElement = direct_product::GroupElement<
        EncryptionKey::PlaintextSpaceGroupElement,
        EncryptionKey::RandomnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement =
        direct_product::GroupElement<EncryptionKey::CiphertextSpaceGroupElement, GroupElement>;

    type PublicParameters = PublicParameters<
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

        let base_by_discrete_log = base.scalar_mul(&witness.discrete_log().value());

        Ok((encryption_of_discrete_log, base_by_discrete_log).into())
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const SCALAR_LIMBS: usize,
        Scalar: KnownOrderScalar<SCALAR_LIMBS> + Samplable,
        GroupElement: group::GroupElement,
    >
    EnhanceableLanguage<
        RANGE_CLAIMS_PER_SCALAR,
        SCALAR_LIMBS,
        Scalar,
        paillier::RandomnessSpaceGroupElement,
    > for Language<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }, GroupElement, PaillierEncryptionKey>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn convert_witness(
        constrained_witness: &ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS>,
        randomness: &paillier::RandomnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement> {
        let discrete_log = <Scalar as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            SCALAR_LIMBS,
        >>::compose_from_constrained_witness(
            constrained_witness,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits::<SCALAR_LIMBS>(),
        )?;

        Ok((discrete_log, *randomness).into())
    }
}

/// The Public Parameters of the Encryption of Discrete Log Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
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
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    // The base of the discrete log
    pub generator: GroupElementValue,
}

impl<
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
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    pub fn new<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, GroupElement, EncryptionKey>(
        group_public_parameters: GroupElement::PublicParameters,
        encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    ) -> Self
    where
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + CyclicGroupElement,
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
            encryption_scheme_public_parameters,
            generator,
        }
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

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use crypto_bigint::{NonZero, Random};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        ahe::paillier,
        group::{ristretto, secp256k1, self_product},
        proofs::schnorr::{aggregation, language},
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub type Lang = Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        secp256k1::GroupElement,
        paillier::EncryptionKey,
    >;

    pub(crate) fn public_parameters() -> language::PublicParameters<REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let language_public_parameters = PublicParameters::new::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >(
            secp256k1_group_public_parameters,
            paillier_public_parameters,
        );

        language_public_parameters
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        language::tests::valid_proof_verifies::<REPETITIONS, Lang>(
            language_public_parameters,
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
        let language_public_parameters = public_parameters();
        let witnesses = language::tests::generate_witnesses_for_aggregation::<REPETITIONS, Lang>(
            &language_public_parameters,
            number_of_parties,
            batch_size,
        );

        aggregation::tests::aggregates::<REPETITIONS, Lang>(&language_public_parameters, witnesses)
    }

    // // TODO
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

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        language::tests::invalid_proof_fails_verification::<REPETITIONS, Lang>(
            None,
            None,
            language_public_parameters,
            batch_size,
        )
    }
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
