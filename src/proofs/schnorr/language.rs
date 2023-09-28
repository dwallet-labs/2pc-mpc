// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use proofs::Result;
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{GroupElement, Samplable},
    proofs,
};

pub mod commitment_of_discrete_log;
pub mod enhanced;
pub mod knowledge_of_decommitment;
pub mod knowledge_of_discrete_log;

pub use enhanced::{committed_linear_evaluation, encryption_of_discrete_log, EnhancedLanguage};

/// A Schnorr Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof`.
/// As defined in Appendix B. Schnorr Protocols in the paper.
pub trait Language: Clone {
    /// An element of the witness space $(\HH_\pp, +)$
    type WitnessSpaceGroupElement: GroupElement + Samplable;

    /// An element in the associated statement space $(\GG_\pp, \cdot)$,
    type StatementSpaceGroupElement: GroupElement;

    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$.
    ///
    /// Includes the public parameters of the witness, and statement groups.
    ///
    /// Group public parameters are encoded separately in
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `StatementSpaceGroupElement::PublicParameters`.
    type PublicParameters: AsRef<
            GroupsPublicParameters<
                group::PublicParameters<Self::WitnessSpaceGroupElement>,
                group::PublicParameters<Self::StatementSpaceGroupElement>,
            >,
        > + Serialize
        + PartialEq
        + Clone;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// A group homomorphism $\phi:\HH\to\GG$  from $(\HH_\pp, +)$, the witness space,
    /// to $(\GG_\pp,\cdot)$, the statement space space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement<Self>,
        language_public_parameters: &PublicParameters<Self>,
    ) -> Result<StatementSpaceGroupElement<Self>>;
}

pub(super) type PublicParameters<L> = <L as Language>::PublicParameters;
pub(super) type WitnessSpaceGroupElement<L> = <L as Language>::WitnessSpaceGroupElement;
pub(super) type WitnessSpacePublicParameters<L> = group::PublicParameters<WitnessSpaceGroupElement<L>>;
pub(super) type WitnessSpaceValue<L> = group::Value<WitnessSpaceGroupElement<L>>;

pub(super) type StatementSpaceGroupElement<L> = <L as Language>::StatementSpaceGroupElement;
pub(super) type StatementSpacePublicParameters<L> = group::PublicParameters<StatementSpaceGroupElement<L>>;
pub(super) type StatementSpaceValue<L> = group::Value<StatementSpaceGroupElement<L>>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
    pub witness_space_public_parameters: WitnessSpacePublicParameters,
    pub statement_space_public_parameters: StatementSpacePublicParameters,
}
