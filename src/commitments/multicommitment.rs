// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::array;

use serde::{Deserialize, Serialize};

use crate::{
    commitments,
    commitments::{
        CommitmentSpaceGroupElement, CommitmentSpacePublicParameters, GroupsPublicParameters,
        GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme,
        MessageSpaceGroupElement, MessageSpacePublicParameters, RandomnessSpaceGroupElement,
        RandomnessSpacePublicParameters,
    },
    group,
    group::self_product,
};

/// The commitment scheme whose commitment algorithm maps `N` message space
/// elements and randomness space elements into `N` commitment space
/// elements by applying the underlying commitment algorithm of `CommitmentScheme`.
///
/// Useful because the `HomomorphicCommitmentScheme` trait abstracts away the idea of batch-sizes
/// and requires a single element for the groups; this forces our design to use a `self_product` of
/// element as that one element for all groups.
///
/// Note that this is a different (and less efficient) batching method than the one found e.g. in
/// Pedersen, but in some cases (e.g. for soundness issues) one is forced to use this method.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct MultiCommitment<
    const N: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
>(CommitmentScheme);
// TODO: is this generically true that I can use the same commitment scheme for this?

impl<
        const N: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
    > HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>
    for MultiCommitment<N, MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>
{
    type MessageSpaceGroupElement = self_product::GroupElement<
        N,
        MessageSpaceGroupElement<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
    >;
    type RandomnessSpaceGroupElement = self_product::GroupElement<
        N,
        RandomnessSpaceGroupElement<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
    >;
    type CommitmentSpaceGroupElement = self_product::GroupElement<
        N,
        CommitmentSpaceGroupElement<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
    >;
    // TODO: can these be the same public parameters for all? like the same message generator etc?
    // I think so, and I think this is even generically so.
    type PublicParameters = PublicParameters<
        N,
        commitments::PublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
        MessageSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
        RandomnessSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
        CommitmentSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        // TODO: this is generically true?

        if N == 0 {
            return Err(group::Error::InvalidPublicParameters);
        }

        CommitmentScheme::new(&public_parameters.public_parameters).map(|c| Self(c))
    }

    fn commit(
        &self,
        message: &Self::MessageSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Self::CommitmentSpaceGroupElement {
        let messages: &[MessageSpaceGroupElement<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>; N] =
            message.into();

        let randomnesses: &[RandomnessSpaceGroupElement<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>;
             N] = randomness.into();

        let commitments: [CommitmentSpaceGroupElement<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>;
            N] = array::from_fn(|i| self.0.commit(&messages[i], &randomnesses[i]));

        commitments.into()
    }
}

// TODO: if I can remove the size from the public parameters here & in self_product it would
// simplify code.
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<
    const N: usize,
    PP,
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
> {
    pub public_parameters: PP,
    pub size: usize,
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<N, MessageSpacePublicParameters>,
        self_product::PublicParameters<N, RandomnessSpacePublicParameters>,
        self_product::PublicParameters<N, CommitmentSpacePublicParameters>,
    >,
}

impl<
        const N: usize,
        PP,
        MessageSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
    >
    PublicParameters<
        N,
        PP,
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >
where
    PP: AsRef<
        GroupsPublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    >,
{
    pub fn new(public_parameters: PP) -> Self {
        let message_space_public_parameters =
            self_product::PublicParameters::<N, MessageSpacePublicParameters>::new(
                public_parameters.message_space_public_parameters().clone(),
            );

        let randomness_space_public_parameters =
            self_product::PublicParameters::<N, RandomnessSpacePublicParameters>::new(
                public_parameters
                    .randomness_space_public_parameters()
                    .clone(),
            );

        let commitment_space_public_parameters =
            self_product::PublicParameters::<N, CommitmentSpacePublicParameters>::new(
                public_parameters
                    .commitment_space_public_parameters()
                    .clone(),
            );

        Self {
            public_parameters,
            size: N,
            groups_public_parameters: GroupsPublicParameters {
                message_space_public_parameters,
                randomness_space_public_parameters,
                commitment_space_public_parameters,
            },
        }
    }
}

impl<
        const N: usize,
        PP,
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<N, MessageSpacePublicParameters>,
            self_product::PublicParameters<N, RandomnessSpacePublicParameters>,
            self_product::PublicParameters<N, CommitmentSpacePublicParameters>,
        >,
    >
    for PublicParameters<
        N,
        PP,
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<N, MessageSpacePublicParameters>,
        self_product::PublicParameters<N, RandomnessSpacePublicParameters>,
        self_product::PublicParameters<N, CommitmentSpacePublicParameters>,
    > {
        &self.groups_public_parameters
    }
}
