// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{group, group::GroupElement};

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
pub trait HomomorphicCommitmentScheme<
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANDOMNESS_SPACE_SCALAR_LIMBS: usize,
    const COMMITMENT_SPACE_SCALAR_LIMBS: usize,
    MessageSpaceGroupElement: GroupElement<MESSAGE_SPACE_SCALAR_LIMBS>,
    RandomnessSpaceGroupElement: GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>,
    CommitmentSpaceGroupElement: GroupElement<COMMITMENT_SPACE_SCALAR_LIMBS>,
>: PartialEq + Clone
{
    /// The public parameters of the commitment scheme $\Com_{\pp}$.
    ///
    /// Used for commitment-specific parameters (e.g., the bases $g_i$, $h$ in the case of
    /// Pedersen).
    ///
    /// Group public parameters are encoded separately in
    /// `MessageSpaceGroupElement::PublicParameters`,
    /// `RandomnessSpaceGroupElement::PublicParameters`
    /// `CommitmentSpaceGroupElement::PublicParameters`.
    ///
    /// Used in [`Self::commit()`] to define the commitment algorithm $\Com_{\pp}$.
    /// As such, it uniquely identifies the commitment-scheme (alongside the type `Self`) and will
    /// be used for Fiat-Shamir Transcripts).
    type PublicParameters: Serialize + for<'r> Deserialize<'r> + Clone + PartialEq;

    /// Returns the public parameters of this commitment scheme.
    fn public_parameters(&self) -> Self::PublicParameters;

    /// Instantiate the commitment scheme from its public parameters and the commitment space group
    /// public parameters.
    fn new(
        commitment_public_parameters: &Self::PublicParameters,
        commitment_space_public_parameters: &CommitmentSpaceGroupElement::PublicParameters,
    ) -> group::Result<Self>;

    fn commit(
        &self,
        message: &MessageSpaceGroupElement,
        randomness: &RandomnessSpaceGroupElement,
    ) -> CommitmentSpaceGroupElement;
}
