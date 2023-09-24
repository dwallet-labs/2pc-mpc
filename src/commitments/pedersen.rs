// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{self_product, CyclicGroupElement, Samplable},
    helpers::const_generic_array_serialization,
};

/// A Batched Pedersen Commitment
/// The public parameters ['PublicParameters'] for this commitment should be carefully constructed.
#[derive(PartialEq, Clone)]
pub struct Pedersen<const BATCH_SIZE: usize, Scalar, GroupElement> {
    /// The generators used for the messages
    message_generators: [GroupElement; BATCH_SIZE],
    /// The generator used for the randomness
    randomness_generator: GroupElement,

    _scalar_choice: PhantomData<Scalar>,
}

/// The Public Parameters of a Pedersen Commitment
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<const BATCH_SIZE: usize, GroupElementValue> {
    #[serde(with = "const_generic_array_serialization")]
    pub message_generators: [GroupElementValue; BATCH_SIZE],
    pub randomness_generator: GroupElementValue,
}

impl<const BATCH_SIZE: usize, Scalar, GroupElement> HomomorphicCommitmentScheme
    for Pedersen<BATCH_SIZE, Scalar, GroupElement>
where
    Scalar: CyclicGroupElement
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Samplable
        + Copy,
    GroupElement: CyclicGroupElement,
{
    type MessageSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>;
    type RandomnessSpaceGroupElement = Scalar;
    type CommitmentSpaceGroupElement = GroupElement;
    type PublicParameters = PublicParameters<BATCH_SIZE, GroupElement::Value>;

    fn public_parameters(&self) -> Self::PublicParameters {
        Self::PublicParameters {
            message_generators: self
                .message_generators
                .clone()
                .map(|element| element.value()),
            randomness_generator: self.randomness_generator.value(),
        }
    }

    fn new(
        commitment_public_parameters: &Self::PublicParameters,
        commitment_space_public_parameters: &GroupElement::PublicParameters,
    ) -> group::Result<Self> {
        let message_generators = commitment_public_parameters
            .message_generators
            .clone()
            .map(|value| GroupElement::new(value, commitment_space_public_parameters));

        // Return the first error you encounter, or instantiate `Self`
        if let Some(Err(err)) = message_generators.iter().find(|res| res.is_err()) {
            return Err(err.clone());
        }

        let message_generators = message_generators.map(|res| res.unwrap());

        let randomness_generator = GroupElement::new(
            commitment_public_parameters.randomness_generator.clone(),
            commitment_space_public_parameters,
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
