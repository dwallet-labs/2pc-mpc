// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use crate::{
    commitments::{
        GroupsPublicParameters, GroupsPublicParametersAccessors, HomomorphicCommitmentScheme,
    },
    group,
    group::{self_product, BoundedGroupElement, KnownOrderGroupElement, Samplable},
    helpers::const_generic_array_serialization,
};

// TODO: can we DRY this & pedersen to the same code?

// TODO: the message generator should be a random power of the randomness generator, which can be
// the generator of the group. we actually have a use-case here for a cyclic group without a
// generator. Maybe I can just drop the cyclic group requirement. actually we need also the
// randomness to be a different group than the message not sure we can use hashes to derive this

// TODO: scalar_mul_bounded

// TODO: doc, name
/// A Batched Pedersen Commitment
/// The public parameters ['PublicParameters'] for this commitment should be carefully constructed.
/// TODO: Safe for cyclic groups, but doesn't need generator(s). Known order?
#[derive(PartialEq, Clone)]
pub struct MultiPedersen<
    const BATCH_SIZE: usize,
    const SCALAR_LIMBS: usize,
    Scalar: group::GroupElement,
    GroupElement: group::GroupElement,
> {
    /// The generator used for the messages
    message_generator: GroupElement,
    /// The generator used for the randomness
    randomness_generator: GroupElement,

    _scalar_choice: PhantomData<Scalar>,
}

impl<const BATCH_SIZE: usize, const SCALAR_LIMBS: usize, Scalar, GroupElement>
    HomomorphicCommitmentScheme<SCALAR_LIMBS>
    for MultiPedersen<BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement>
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
    type RandomnessSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>;
    type CommitmentSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, GroupElement>;
    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        GroupElement::Value,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        if BATCH_SIZE == 0 {
            return Err(group::Error::InvalidPublicParameters);
        }

        let message_generator = GroupElement::new(
            public_parameters.message_generator,
            &public_parameters
                .commitment_space_public_parameters()
                .public_parameters,
        )?;

        let randomness_generator = GroupElement::new(
            public_parameters.randomness_generator,
            &public_parameters
                .commitment_space_public_parameters()
                .public_parameters,
        )?;

        Ok(Self {
            message_generator,
            randomness_generator,
            _scalar_choice: PhantomData,
        })
    }

    fn commit(
        &self,
        message: &Self::MessageSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Self::CommitmentSpaceGroupElement {
        let messages: [_; BATCH_SIZE] = (*message).into();
        let randomnesses: [_; BATCH_SIZE] = (*randomness).into();

        let commitments: [_; BATCH_SIZE] = messages
            .into_iter()
            .zip(randomnesses)
            .map(|(message, randomness)| {
                message * &self.message_generator + randomness * &self.randomness_generator
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();

        commitments.into()
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

// TODO: generate pedersen parameters from hash or what Avichay approves of, and don't allow any
// other instantiation.

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
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    >,
    pub message_generator: GroupElementValue,
    pub randomness_generator: GroupElementValue,
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue,
        ScalarPublicParameters: Clone,
        GroupPublicParameters,
    >
    PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    // TODO: derive this using hashes or whatever is safe.
    pub fn new<
        const SCALAR_LIMBS: usize,
        Scalar: group::GroupElement,
        GroupElement: group::GroupElement,
    >(
        scalar_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        message_generator: GroupElement::Value,
        randomness_generator: GroupElement::Value,
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
                randomness_space_public_parameters: self_product::PublicParameters::new(
                    scalar_public_parameters,
                ),
                commitment_space_public_parameters: self_product::PublicParameters::new(
                    group_public_parameters,
                ),
            },
            message_generator,
            randomness_generator,
        }
    }
}

impl<const BATCH_SIZE: usize, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
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
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

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

        let commitment_scheme_public_parameters =
            commitments::PublicParameters::<
                { ristretto::SCALAR_LIMBS },
                MultiPedersen<
                    1,
                    { ristretto::SCALAR_LIMBS },
                    ristretto::Scalar,
                    ristretto::GroupElement,
                >,
            >::new::<{ ristretto::SCALAR_LIMBS }, ristretto::Scalar, ristretto::GroupElement>(
                scalar_public_parameters,
                group_public_parameters,
                ristretto::GroupElement(commitment_generators.B),
                ristretto::GroupElement(commitment_generators.B_blinding),
            );

        let commitment_scheme = MultiPedersen::<
            1,
            { ristretto::SCALAR_LIMBS },
            ristretto::Scalar,
            ristretto::GroupElement,
        >::new(&commitment_scheme_public_parameters)
        .unwrap();

        let expected_commitment =
            ristretto::GroupElement(commitment_generators.commit(value.0, randomness.0));

        let commitment: [_; 1] = commitment_scheme
            .commit(&([value].into()), &([randomness].into()))
            .into();

        assert_eq!([expected_commitment], commitment)
    }
}
