// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use core::fmt::Debug;
use std::{array, marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use crate::{
    commitments::{
        GroupsPublicParameters, GroupsPublicParametersAccessors, HomomorphicCommitmentScheme,
    },
    group,
    group::{
        self_product, BoundedGroupElement, HashToGroup, KnownOrderGroupElement, PrimeGroupElement,
        Samplable,
    },
    helpers::{const_generic_array_serialization, flat_map_results},
};

// TODO: scalar_mul_bounded

/// A Batched Pedersen Commitment
/// The public parameters ['PublicParameters'] for this commitment should be carefully constructed.
/// TODO: Safe for cyclic groups, but doesn't need generator(s). Known order?
#[derive(PartialEq, Clone, Debug, Eq)]
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
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Samplable
        + Copy,
    GroupElement: group::GroupElement,
{
    // TODO: actually we can use a different randomizer and message spaces, e.g. allowing infinite
    // range (integer commitments)
    type MessageSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>;
    type RandomnessSpaceGroupElement = Scalar;
    type CommitmentSpaceGroupElement = GroupElement;
    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        GroupElement::Value,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        if BATCH_SIZE == 0 {
            // TODO: this is not a group instantiation error, perhaps create different error or
            // change the group doc
            return Err(group::Error::InvalidPublicParameters);
        }

        let message_generators = public_parameters.message_generators.clone().map(|value| {
            GroupElement::new(
                value,
                public_parameters.commitment_space_public_parameters(),
            )
        });

        // Return the first error you encounter, or instantiate `Self`
        if let Some(Err(err)) = message_generators.iter().find(|res| res.is_err()) {
            return Err(err.clone());
        }

        let message_generators = message_generators.map(|res| res.unwrap());

        let randomness_generator = GroupElement::new(
            public_parameters.randomness_generator.clone(),
            &public_parameters.commitment_space_public_parameters(),
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

pub type MessageSpaceGroupElement<const BATCH_SIZE: usize, Scalar> =
    self_product::GroupElement<BATCH_SIZE, Scalar>;
pub type MessageSpacePublicParameters<const BATCH_SIZE: usize, Scalar> =
    group::PublicParameters<MessageSpaceGroupElement<BATCH_SIZE, Scalar>>;
pub type RandomnessSpaceGroupElement<Scalar> = Scalar;
pub type RandomnessSpacePublicParameters<Scalar> =
    group::PublicParameters<RandomnessSpaceGroupElement<Scalar>>;
pub type CommitmentSpaceGroupElement<GroupElement> = GroupElement;
pub type CommitmentSpacePublicParameters<GroupElement> =
    group::PublicParameters<CommitmentSpaceGroupElement<GroupElement>>;

/// The Public Parameters of a Pedersen Commitment
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    GroupElementValue,
    ScalarPublicParameters,
    GroupPublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
    #[serde(with = "const_generic_array_serialization")]
    pub message_generators: [GroupElementValue; BATCH_SIZE],
    pub randomness_generator: GroupElementValue,
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue: Clone,
        ScalarPublicParameters: Clone,
        GroupPublicParameters: Clone,
    >
    PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    pub fn default<
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + HashToGroup,
    >() -> group::Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
        ScalarPublicParameters: Default,
        GroupPublicParameters: Default,
    {
        Self::derive::<SCALAR_LIMBS, GroupElement>(
            ScalarPublicParameters::default(),
            GroupPublicParameters::default(),
        )
    }

    pub fn derive<
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + HashToGroup,
    >(
        scalar_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        group_public_parameters: group::PublicParameters<GroupElement>,
    ) -> group::Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
    {
        let mut message_generators = flat_map_results(array::from_fn(|i| {
            GroupElement::hash_to_group(
                // TODO: add organization name, repo name?
                format!("commitments/pedersen: message generator #{:?}", i).as_bytes(),
            )
        }))?;

        // TODO: we want this for sure?
        message_generators[0] =
            GroupElement::generator_from_public_parameters(&group_public_parameters)?;

        let message_generators = message_generators.map(|element| element.value());

        let randomness_generator =
            GroupElement::hash_to_group("commitments/pedersen: randomness generator".as_bytes())?
                .value();

        Ok(
            Self::new::<SCALAR_LIMBS, GroupElement::Scalar, GroupElement>(
                scalar_public_parameters,
                group_public_parameters,
                message_generators,
                randomness_generator,
            ),
        )
    }

    /// This function allows using custom Pedersen generators, which is extremely unsafe unless you
    /// know exactly what you're doing.
    ///
    /// It should be used, for example, for non-`PrimeGroupElement`
    /// groups for which security have been proven.
    ///
    /// Another use-case is for compatability reason, i.e. when needing to work with
    /// generators that were derived safely elsewhere.
    ///
    /// For any other, and all traditional use-cases such as Pedersen over elliptic curves, use
    /// [`Self::drive`] or [`Self::default`] instead.
    pub fn new<
        const SCALAR_LIMBS: usize,
        Scalar: group::GroupElement,
        GroupElement: group::GroupElement,
    >(
        scalar_public_parameters: group::PublicParameters<Scalar>,
        group_public_parameters: group::PublicParameters<GroupElement>,
        message_generators: [group::Value<GroupElement>; BATCH_SIZE],
        randomness_generator: group::Value<GroupElement>,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + BoundedGroupElement<SCALAR_LIMBS>
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Samplable
            + Copy,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                message_space_public_parameters: self_product::PublicParameters::new(
                    scalar_public_parameters.clone(),
                ),
                randomness_space_public_parameters: scalar_public_parameters,
                commitment_space_public_parameters: group_public_parameters,
            },
            message_generators,
            randomness_generator,
        }
    }

    pub fn with_altered_message_generators(
        &self,
        message_generators: [GroupElementValue; BATCH_SIZE],
    ) -> Self {
        Self {
            groups_public_parameters: self.groups_public_parameters.clone(),
            message_generators,
            randomness_generator: self.randomness_generator.clone(),
        }
    }

    pub fn with_altered_randomness_generator(
        &self,
        randomness_generator: GroupElementValue,
    ) -> Self {
        Self {
            groups_public_parameters: self.groups_public_parameters.clone(),
            message_generators: self.message_generators.clone(),
            randomness_generator,
        }
    }
}

impl<const BATCH_SIZE: usize, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,
    >
    for PublicParameters<
        BATCH_SIZE,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        ScalarPublicParameters,
        GroupPublicParameters,
    > {
        &self.groups_public_parameters
    }
}

#[cfg(test)]
mod tests {
    use bulletproofs::PedersenGens;
    use rand_core::OsRng;

    use super::*;
    use crate::{commitments, group::ristretto};

    #[test]
    fn commits() {
        let scalar_public_parameters = ristretto::scalar::PublicParameters::default();
        let group_public_parameters = ristretto::group_element::PublicParameters::default();

        let value = ristretto::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let randomness = ristretto::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        let commitment_generators = PedersenGens::default();

        let commitment_scheme_public_parameters = commitments::PublicParameters::<
            { ristretto::SCALAR_LIMBS },
            Pedersen<1, { ristretto::SCALAR_LIMBS }, ristretto::Scalar, ristretto::GroupElement>,
        >::new::<
            { ristretto::SCALAR_LIMBS },
            ristretto::Scalar,
            ristretto::GroupElement,
        >(
            scalar_public_parameters,
            group_public_parameters,
            [ristretto::GroupElement(commitment_generators.B)],
            ristretto::GroupElement(commitment_generators.B_blinding),
        );

        let commitment_scheme = Pedersen::<
            1,
            { ristretto::SCALAR_LIMBS },
            ristretto::Scalar,
            ristretto::GroupElement,
        >::new(&commitment_scheme_public_parameters)
        .unwrap();

        let expected_commitment =
            ristretto::GroupElement(commitment_generators.commit(value.0, randomness.0));

        let commitment = commitment_scheme.commit(&([value].into()), &randomness);

        assert_eq!(expected_commitment, commitment)
    }
}
