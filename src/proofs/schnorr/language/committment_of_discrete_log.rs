// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
// pub use language::aliases::committment_of_discrete_log::*;
use serde::{Deserialize, Serialize};

use super::GroupsPublicParameters;
use crate::{
    commitment::HomomorphicCommitmentScheme,
    group,
    group::{
        self_product, BoundedGroupElement, CyclicGroupElement, GroupElement, Samplable, Value,
    },
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            aggregation, language, proof::SOUND_PROOFS_REPETITIONS,
            language::{StatementSpacePublicParameters, WitnessSpacePublicParameters},
        },
    },
};

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
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<
        const SCALAR_LIMBS: usize,
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
    > schnorr::Language<SOUND_PROOFS_REPETITIONS>
    for Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
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
        let base = GroupElement::new(
            language_public_parameters.base,
            &language_public_parameters
                .groups_public_parameters
                .statement_space_public_parameters
                .public_parameters,
        )?;

        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok([
            commitment_scheme.commit(
                &[witness.commitment_message().clone()].into(),
                witness.commitment_randomness(),
            ),
            witness.commitment_message().clone() * base,
        ]
        .into())
    }
}

pub trait WitnessAccessors<Scalar: group::GroupElement> {
    fn commitment_message(&self) -> &Scalar;

    fn commitment_randomness(&self) -> &Scalar;
}

impl<Scalar: group::GroupElement> WitnessAccessors<Scalar>
    for self_product::GroupElement<2, Scalar>
{
    fn commitment_message(&self) -> &Scalar {
        let value: &[Scalar; 2] = self.into();

        &value[0]
    }

    fn commitment_randomness(&self) -> &Scalar {
        let value: &[Scalar; 2] = self.into();

        &value[1]
    }
}

pub trait StatementAccessors<GroupElement: group::GroupElement> {
    fn committment_of_discrete_log(&self) -> &GroupElement;

    fn base_by_discrete_log(&self) -> &GroupElement;
}

impl<GroupElement: group::GroupElement> StatementAccessors<GroupElement>
    for self_product::GroupElement<2, GroupElement>
{
    fn committment_of_discrete_log(&self) -> &GroupElement {
        let value: &[_; 2] = self.into();

        &value[0]
    }

    fn base_by_discrete_log(&self) -> &GroupElement {
        let value: &[_; 2] = self.into();

        &value[1]
    }
}

/// The Public Parameters of the Commitment of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    ScalarPublicParameters,
    GroupPublicParameters,
    CommitmentSchemePublicParameters,
    GroupElementValue,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<2, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupPublicParameters>,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub base: GroupElementValue,
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<2, ScalarPublicParameters>,
            self_product::PublicParameters<2, GroupPublicParameters>,
        >,
    >
    for PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<2, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
    PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    pub fn new<
        const SCALAR_LIMBS: usize,
        Scalar: BoundedGroupElement<SCALAR_LIMBS>
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement,
        CommitmentScheme: HomomorphicCommitmentScheme<
            SCALAR_LIMBS,
            MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
            RandomnessSpaceGroupElement = Scalar,
            CommitmentSpaceGroupElement = GroupElement,
        >,
    >(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
        base: GroupElementValue,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
        CommitmentScheme: HomomorphicCommitmentScheme<
            SCALAR_LIMBS,
            PublicParameters = CommitmentSchemePublicParameters,
        >,
    {
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
            base,
        }
    }
}

#[cfg(any(test, feature = "benchmarking"))]
mod tests {
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        commitment::{pedersen, Pedersen},
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

    pub(crate) fn language_public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let pedersen_public_parameters = pedersen::PublicParameters::default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        let generator = secp256k1_group_public_parameters.generator;

        PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Pedersen<1, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            pedersen_public_parameters,
            generator,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        language::tests::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let witnesses = language::tests::generate_witnesses_for_aggregation::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            number_of_parties,
            batch_size,
        );

        aggregation::tests::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(&language_public_parameters, witnesses)
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
        language::tests::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        commitment::Pedersen,
        group::secp256k1,
        proofs::schnorr::{
            aggregation, language,
            language::committment_of_discrete_log::tests::{language_public_parameters, Lang},
        },
    };

    pub(crate) fn benchmark(c: &mut Criterion) {
        let language_public_parameters = language_public_parameters();

        language::benchmark::<SOUND_PROOFS_REPETITIONS, Lang>(language_public_parameters.clone(), None, c);

        aggregation::benchmark::<SOUND_PROOFS_REPETITIONS, Lang>(language_public_parameters, None, c);
    }
}
