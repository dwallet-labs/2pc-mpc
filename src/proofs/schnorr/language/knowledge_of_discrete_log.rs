// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{group, group::Samplable, proofs, proofs::schnorr};

impl<Scalar, GroupElement> schnorr::Language for Language<Scalar, GroupElement>
where
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: group::GroupElement,
{
    type WitnessSpaceGroupElement = Scalar;
    type PublicValueSpaceGroupElement = GroupElement;

    type PublicParameters = PublicParameters<
        super::WitnessSpacePublicParameters<Self>,
        super::PublicValueSpacePublicParameters<Self>,
        group::Value<GroupElement>,
    >;

    const NAME: &'static str = "Knowledge of the Discrete Log";

    fn group_homomorphism(
        witness: &super::WitnessSpaceGroupElement<Self>,
        language_public_parameters: &super::PublicParameters<Self>,
    ) -> proofs::Result<super::PublicValueSpaceGroupElement<Self>> {
        let generator = GroupElement::new(
            language_public_parameters.generator.clone(),
            &language_public_parameters
                .as_ref()
                .public_value_space_public_parameters,
        )?;

        Ok(*witness * generator)
    }

    fn public_parameters_to_group_parameters(
        language_public_parameters: &super::PublicParameters<Self>,
    ) -> &super::GroupsPublicParameters<
        super::WitnessSpacePublicParameters<Self>,
        super::PublicValueSpacePublicParameters<Self>,
    > {
        language_public_parameters.as_ref()
    }
}

/// Knowledge of Discrete Log Schnorr Language.
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
#[derive(Clone)]
pub struct Language<Scalar, GroupElement> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
}

/// The Public Parameters of the Knowledge of Discrete Log Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    WitnessSpacePublicParameters,
    PublicValueSpacePublicParameters,
    GroupElementValue,
> {
    pub groups_public_parameters: super::GroupsPublicParameters<
        WitnessSpacePublicParameters,
        PublicValueSpacePublicParameters,
    >,
    pub generator: GroupElementValue,
}

impl<WitnessSpacePublicParameters, PublicValueSpacePublicParameters, GroupElementValue>
    AsRef<
        super::GroupsPublicParameters<
            WitnessSpacePublicParameters,
            PublicValueSpacePublicParameters,
        >,
    >
    for PublicParameters<
        WitnessSpacePublicParameters,
        PublicValueSpacePublicParameters,
        GroupElementValue,
    >
{
    fn as_ref(
        &self,
    ) -> &super::GroupsPublicParameters<
        WitnessSpacePublicParameters,
        PublicValueSpacePublicParameters,
    > {
        &self.groups_public_parameters
    }
}
