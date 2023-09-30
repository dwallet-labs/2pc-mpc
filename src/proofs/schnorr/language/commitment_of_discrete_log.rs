// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use super::{GroupsPublicParameters, StatementSpacePublicParameters, WitnessSpacePublicParameters};
use crate::{
    commitments::HomomorphicCommitmentScheme,
    group::{self_product, BoundedGroupElement, CyclicGroupElement, Samplable},
    proofs,
    proofs::schnorr,
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
#[derive(Clone, Serialize)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> schnorr::Language
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
        WitnessSpacePublicParameters<Self>,
        StatementSpacePublicParameters<Self>,
        GroupElement::Value,
        CommitmentScheme::PublicParameters,
    >;

    const NAME: &'static str = "Commitment of Discrete Log";

    fn group_homomorphism(
        witness: &super::WitnessSpaceGroupElement<Self>,
        language_public_parameters: &super::PublicParameters<Self>,
    ) -> proofs::Result<super::StatementSpaceGroupElement<Self>> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let base = GroupElement::new(
            language_public_parameters.generator.clone(),
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
    WitnessSpacePublicParameters,
    StatementSpacePublicParameters,
    GroupElementValue,
    CommitmentSchemePublicParameters,
> {
    pub groups_public_parameters:
        GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub generator: GroupElementValue, // The base of discrete log
}

impl<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        GroupElementValue,
        CommitmentSchemePublicParameters,
    > AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
    for PublicParameters<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        GroupElementValue,
        CommitmentSchemePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
        &self.groups_public_parameters
    }
}