// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{self_product, CyclicGroupElement},
    helpers::const_generic_array_serialization,
};

/// The Public Parameters of a Pedersen Commitment
#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    const SCALAR_LIMBS: usize,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>,
> {
    #[serde(with = "const_generic_array_serialization")]
    message_generators: [GroupElement::Value; BATCH_SIZE],
    randomness_generator: GroupElement::Value,
}

/// A Batched Pedersen Commitment
/// The public parameters ['PublicParameters'] for this commitment should be carefully constructed.
#[derive(PartialEq, Clone)]
pub struct Pedersen<const BATCH_SIZE: usize, const SCALAR_LIMBS: usize, Scalar, GroupElement> {
    /// The generators used for the messages
    message_generators: [GroupElement; BATCH_SIZE],
    /// The generator used for the randomness
    randomness_generator: GroupElement,

    _scalar_choice: PhantomData<Scalar>,
}

impl<const BATCH_SIZE: usize, const SCALAR_LIMBS: usize, Scalar, GroupElement>
    HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        self_product::GroupElement<BATCH_SIZE, SCALAR_LIMBS, Scalar>,
        Scalar,
        GroupElement,
    > for Pedersen<BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: CyclicGroupElement<SCALAR_LIMBS>,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
{
    type PublicParameters = PublicParameters<BATCH_SIZE, SCALAR_LIMBS, GroupElement>;

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
        message: &self_product::GroupElement<BATCH_SIZE, SCALAR_LIMBS, Scalar>,
        randomness: &Scalar,
    ) -> GroupElement {
        self.message_generators
            .clone()
            .into_iter()
            .zip::<&[Scalar; BATCH_SIZE]>(message.into())
            .fold(
                self.randomness_generator.neutral(),
                |acc, (generator, value)| acc + (generator * value),
            )
            + self.randomness_generator.clone() * randomness
    }
}
