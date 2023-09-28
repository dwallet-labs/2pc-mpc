// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

pub use pedersen::Pedersen;
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{GroupElement, Samplable},
};

pub mod pedersen;

/// A Homomorphic Commitment Scheme
///
/// The commitment algorithm of a non-interactive commitment scheme $\Com_{\pp}$
/// defines a function $\calM_{\pp}\times \calR_{\pp} \rightarrow \calC_{\pp}$ for message space
/// $\calM_{\pp}$, randomness space $\calR_{\pp}$ and commitment space $\calC_{\pp}$.
///
/// In a homomorphic commitment $\calM,\calR$ and $\calC$ are all abelian groups,
/// and for all $\vec{m}_1, \vec{m}_2 \in \calM$, $\rho_1, \rho_2\in \calR$ we have
/// (in the following, `$+$' is defined differently for each group): $$ \Com(\vec{m}_1; \rho_1) +
/// \Com(\vec{m}_2; \rho_2) = \Com(\vec{m}_1 + \vec{m}_2; \rho_1 + \rho_2) $$
///
/// As defined in Definitions 2.4, 2.5 in the paper.
pub trait HomomorphicCommitmentScheme: Into<Self::PublicParameters> + PartialEq + Clone {
    /// The Message space group element of the commitment scheme
    type MessageSpaceGroupElement: GroupElement;
    /// The Randomness space group element of the commitment scheme
    type RandomnessSpaceGroupElement: GroupElement + Samplable;
    /// The Commitment space group element of the commitment scheme
    type CommitmentSpaceGroupElement: GroupElement;

    /// The public parameters of the commitment scheme $\Com_{\pp}$.
    ///
    /// Includes the public parameters of the message, randomness and commitment groups.
    ///
    /// Used in [`Self::commit()`] to define the commitment algorithm $\Com_{\pp}$.
    /// As such, it uniquely identifies the commitment-scheme (alongside the type `Self`) and will
    /// be used for Fiat-Shamir Transcripts).
    type PublicParameters: AsRef<
            GroupsPublicParameters<
                MessageSpacePublicParameters<Self>,
                RandomnessSpacePublicParameters<Self>,
                CommitmentSpacePublicParameters<Self>,
            >,
        > + Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + PartialEq;

    /// Returns the public parameters of this commitment scheme.
    fn public_parameters(&self) -> Self::PublicParameters {
        self.clone().into()
    }

    /// Instantiate the commitment scheme from its public parameters and the commitment space group
    /// public parameters.
    fn new(public_parameters: &Self::PublicParameters) -> group::Result<Self>;

    fn commit(
        &self,
        message: &Self::MessageSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Self::CommitmentSpaceGroupElement;
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<MessageSpacePublicParameters, RandomnessSpacePublicParameters, CommitmentSpacePublicParameters> {
    pub message_space_public_parameters: MessageSpacePublicParameters,
    pub randomness_space_public_parameters: RandomnessSpacePublicParameters,
    pub commitment_space_public_parameters: CommitmentSpacePublicParameters,
}

pub type PublicParameters<C> = <C as HomomorphicCommitmentScheme>::PublicParameters;
pub type MessageSpaceGroupElement<C> = <C as HomomorphicCommitmentScheme>::MessageSpaceGroupElement;
pub type MessageSpacePublicParameters<C> = group::PublicParameters<<C as HomomorphicCommitmentScheme>::MessageSpaceGroupElement>;
pub type MessageSpaceValue<C> = group::Value<<C as HomomorphicCommitmentScheme>::MessageSpaceGroupElement>;

pub type RandomnessSpaceGroupElement<C> = <C as HomomorphicCommitmentScheme>::RandomnessSpaceGroupElement;
pub type RandomnessSpacePublicParameters<C> = group::PublicParameters<<C as HomomorphicCommitmentScheme>::RandomnessSpaceGroupElement>;
pub type RandomnessSpaceValue<C> = group::Value<<C as HomomorphicCommitmentScheme>::RandomnessSpaceGroupElement>;
pub type CommitmentSpaceGroupElement<C> = <C as HomomorphicCommitmentScheme>::CommitmentSpaceGroupElement;
pub type CommitmentSpacePublicParameters<C> = group::PublicParameters<<C as HomomorphicCommitmentScheme>::CommitmentSpaceGroupElement>;
pub type CommitmentSpaceValue<C> = group::Value<<C as HomomorphicCommitmentScheme>::CommitmentSpaceGroupElement>;
