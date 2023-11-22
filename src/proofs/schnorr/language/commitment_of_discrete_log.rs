// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
use serde::{Deserialize, Serialize};

use super::GroupsPublicParameters;
use crate::{
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{
        self_product, BoundedGroupElement, CyclicGroupElement, GroupElement, Samplable, Value,
    },
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            aggregation, language,
            language::{StatementSpacePublicParameters, WitnessSpacePublicParameters},
        },
    },
};

pub(crate) const REPETITIONS: usize = 1;

/// Commitment of Discrete Log Schnorr Language
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
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>
    schnorr::Language<REPETITIONS>
    for Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
where
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: CyclicGroupElement,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
        RandomnessSpaceGroupElement = Scalar,
        CommitmentSpaceGroupElement = GroupElement,
    >,
{
    type WitnessSpaceGroupElement = self_product::GroupElement<2, Scalar>;
    type StatementSpaceGroupElement = self_product::GroupElement<2, GroupElement>;

    type PublicParameters = PublicParameters<
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        CommitmentScheme::PublicParameters,
        GroupElement::Value,
    >;

    const NAME: &'static str = "Commitment of Discrete Log";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let base = GroupElement::new(
            language_public_parameters.generator,
            &language_public_parameters
                .groups_public_parameters
                .statement_space_public_parameters
                .public_parameters,
        )?;

        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok([
            commitment_scheme.commit(&[*value].into(), randomness),
            *value * base,
        ]
        .into())
    }
}

/// The Public Parameters of the Commitment of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    ScalarPublicParameters,
    GroupElementPublicParameters,
    CommitmentSchemePublicParameters,
    GroupElementValue,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<2, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupElementPublicParameters>,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub generator: GroupElementValue, // The base of discrete log
}

impl<
        ScalarPublicParameters,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<2, ScalarPublicParameters>,
            self_product::PublicParameters<2, GroupElementPublicParameters>,
        >,
    >
    for PublicParameters<
        ScalarPublicParameters,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<2, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupElementPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        ScalarPublicParameters,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
    PublicParameters<
        ScalarPublicParameters,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    pub fn new<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + BoundedGroupElement<SCALAR_LIMBS>
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: group::GroupElement<
                Value = GroupElementValue,
                PublicParameters = GroupElementPublicParameters,
            > + CyclicGroupElement,
        CommitmentScheme: HomomorphicCommitmentScheme<
            SCALAR_LIMBS,
            MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
            RandomnessSpaceGroupElement = Scalar,
            CommitmentSpaceGroupElement = GroupElement,
            PublicParameters = CommitmentSchemePublicParameters,
        >,
    {
        // TODO: maybe we don't want the generator all the time?
        let generator = GroupElement::generator_from_public_parameters(&group_public_parameters);
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, Scalar>,
                >::new(
                    scalar_group_public_parameters
                ),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, GroupElement>,
                >::new(group_public_parameters),
            },
            commitment_scheme_public_parameters,
            generator,
        }
    }
}

/// The Witness Space Group Element of a Commitment of Discrete Log Schnorr Language.
pub type WitnessSpaceGroupElement<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
> = language::WitnessSpaceGroupElement<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
>;

/// The Statement Space Group Element of a Commitment of Discrete Log Schnorr Language.
pub type StatementSpaceGroupElement<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
> = language::StatementSpaceGroupElement<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
>;

/// The Public Parameters of a Commitment of Discrete Log Schnorr Language.
pub type LanguagePublicParameters<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
> = language::PublicParameters<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
>;

/// A Commitment of Discrete Log Schnorr Proof.
pub type Proof<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme, ProtocolContext> =
    schnorr::Proof<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

/// A Commitment of Discrete Log Schnorr Proof Aggregation Commitment Round Party.
pub type ProofAggregationCommitmentRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
    ProtocolContext,
> = aggregation::commitment_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    ProtocolContext,
>;

/// A Commitment of Discrete Log Schnorr Proof Aggregation Decommitment Round Party.
pub type ProofAggregationDecommitmentRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
    ProtocolContext,
> = aggregation::decommitment_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    ProtocolContext,
>;

/// A Commitment of Discrete Log Schnorr Proof Aggregation Decommitment.
pub type Decommitment<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> =
    aggregation::decommitment_round::Decommitment<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

/// A Commitment of Discrete Log Schnorr Proof Share Round Party.
pub type ProofAggregationProofShareRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
    ProtocolContext,
> = aggregation::proof_share_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    ProtocolContext,
>;

/// A Commitment of Discrete Log Schnorr Proof Share.
pub type ProofShare<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> =
    aggregation::proof_share_round::ProofShare<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

/// A Commitment of Discrete Log Schnorr Proof Aggregation Proof Aggregation Round Party.
pub type ProofAggregationProofAggregationRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
    ProtocolContext,
> = aggregation::proof_aggregation_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    ProtocolContext,
>;

#[cfg(any(test, feature = "benchmarking"))]
mod tests {
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        commitments::{pedersen, Pedersen},
        group,
        group::{secp256k1, GroupElement, Samplable},
        proofs::schnorr::{aggregation, language},
    };

    pub(crate) type Lang = Language<
        { secp256k1::SCALAR_LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        Pedersen<1, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
    >;

    pub(crate) fn language_public_parameters() -> language::PublicParameters<REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let message_generator =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
                * generator;

        let randomness_generator =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
                * generator;

        // TODO: have some Default function for this
        // TODO: this is not safe; we need a proper way to derive generators
        let pedersen_public_parameters = pedersen::PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
            [message_generator.value()],
            randomness_generator.value(),
        );

        PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Pedersen<1, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            pedersen_public_parameters,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

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
        let language_public_parameters = language_public_parameters();
        let witnesses = language::tests::generate_witnesses_for_aggregation::<REPETITIONS, Lang>(
            &language_public_parameters,
            number_of_parties,
            batch_size,
        );

        aggregation::tests::aggregates::<REPETITIONS, Lang>(&language_public_parameters, witnesses)
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

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

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;

    use super::*;
    use crate::{
        commitments::Pedersen,
        group::secp256k1,
        proofs::schnorr::{
            aggregation, language,
            language::commitment_of_discrete_log::tests::{language_public_parameters, Lang},
        },
    };

    pub(crate) fn benchmark(c: &mut Criterion) {
        let language_public_parameters = language_public_parameters();

        language::benchmark::<REPETITIONS, Lang>(language_public_parameters.clone(), c);

        aggregation::benchmark::<REPETITIONS, Lang>(language_public_parameters, c);
    }
}
