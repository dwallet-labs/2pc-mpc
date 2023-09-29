// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use crate::{
    commitments::{GroupsPublicParameters, HomomorphicCommitmentScheme},
    group,
    group::{self_product, CyclicGroupElement, KnownOrderGroupElement, Samplable},
    helpers::const_generic_array_serialization,
};

/// A Batched Pedersen Commitment
/// The public parameters ['PublicParameters'] for this commitment should be carefully constructed.
#[derive(PartialEq, Clone)]
pub struct Pedersen<
    const BATCH_SIZE: usize,
    const SCALAR_LIMBS: usize,
    Scalar: group::GroupElement,
    GroupElement: group::GroupElement,
> {
    /// The generators used for the messages
    message_generators: [GroupElement; BATCH_SIZE],
    /// The generator used for the randomness
    randomness_generator: GroupElement,

    _scalar_choice: PhantomData<Scalar>,
}

impl<const BATCH_SIZE: usize, const SCALAR_LIMBS: usize, Scalar, GroupElement>
    HomomorphicCommitmentScheme<SCALAR_LIMBS>
    for Pedersen<BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS>
        + CyclicGroupElement
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Samplable
        + Copy,
    GroupElement: CyclicGroupElement,
{
    type MessageSpaceGroupElement = MessageSpaceGroupElement<BATCH_SIZE, Scalar>;
    type RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<Scalar>;
    type CommitmentSpaceGroupElement = CommitmentSpaceGroupElement<GroupElement>;
    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        GroupElement::Value,
        MessageSpacePublicParameters<BATCH_SIZE, Scalar>,
        RandomnessSpacePublicParameters<Scalar>,
        CommitmentSpacePublicParameters<GroupElement>,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        let message_generators = public_parameters.message_generators.clone().map(|value| {
            GroupElement::new(
                value,
                &public_parameters
                    .as_ref()
                    .commitment_space_public_parameters,
            )
        });

        // Return the first error you encounter, or instantiate `Self`
        if let Some(Err(err)) = message_generators.iter().find(|res| res.is_err()) {
            return Err(err.clone());
        }

        let message_generators = message_generators.map(|res| res.unwrap());

        let randomness_generator = GroupElement::new(
            public_parameters.randomness_generator.clone(),
            &public_parameters
                .as_ref()
                .commitment_space_public_parameters,
        )?;

        Ok(Self {
            message_generators,
            randomness_generator,
            _scalar_choice: PhantomData,
        })
    }

    fn commit(
        &self,
        message: &self_product::GroupElement<BATCH_SIZE, Scalar>,
        randomness: &Scalar,
    ) -> GroupElement {
        self.message_generators
            .iter()
            .zip::<&[Scalar; BATCH_SIZE]>(message.into())
            .fold(
                self.randomness_generator.neutral(),
                |acc, (generator, value)| acc + (*value * generator),
            )
            + (*randomness * &self.randomness_generator)
    }
}

type MessageSpaceGroupElement<const BATCH_SIZE: usize, Scalar> =
    self_product::GroupElement<BATCH_SIZE, Scalar>;
type MessageSpacePublicParameters<const BATCH_SIZE: usize, Scalar> =
    group::PublicParameters<MessageSpaceGroupElement<BATCH_SIZE, Scalar>>;
type RandomnessSpaceGroupElement<Scalar> = Scalar;
type RandomnessSpacePublicParameters<Scalar> =
    group::PublicParameters<RandomnessSpaceGroupElement<Scalar>>;
type CommitmentSpaceGroupElement<GroupElement> = GroupElement;
type CommitmentSpacePublicParameters<GroupElement> =
    group::PublicParameters<CommitmentSpaceGroupElement<GroupElement>>;

/// The Public Parameters of a Pedersen Commitment
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    GroupElementValue,
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >,
    #[serde(with = "const_generic_array_serialization")]
    pub message_generators: [GroupElementValue; BATCH_SIZE],
    pub randomness_generator: GroupElementValue,
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue,
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    >
    for PublicParameters<
        BATCH_SIZE,
        GroupElementValue,
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    > {
        &self.groups_public_parameters
    }
}
