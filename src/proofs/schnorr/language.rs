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
pub mod knowledge_of_decommitment;
pub mod knowledge_of_discrete_log;

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
    type PublicParameters: Serialize + PartialEq + Clone;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// A group homomorphism $\phi:\HH\to\GG$  from $(\HH_\pp, +)$, the witness space,
    /// to $(\GG_\pp,\cdot)$, the statement space space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement<Self>,
        language_public_parameters: &PublicParameters<Self>,
    ) -> Result<StatementSpaceGroupElement<Self>>;

    // TODO: This is just a trick to enforce that the language public parameters indeed holds the
    // group public parameters as members. Wanted to use `AsRef` but couldn't because of
    // deriving issues. See: https://github.com/rust-lang/rust/commit/9cabe273d3adb06a19f63460deda96ae224b28bf
    fn public_parameters_to_group_parameters(
        language_public_parameters: &PublicParameters<Self>,
    ) -> &GroupsPublicParameters<
        WitnessSpacePublicParameters<Self>,
        StatementSpacePublicParameters<Self>,
    >;
}

pub(super) type PublicParameters<L> = <L as Language>::PublicParameters;
pub(super) type WitnessSpaceGroupElement<L> = <L as Language>::WitnessSpaceGroupElement;
pub(super) type WitnessSpacePublicParameters<L> =
    group::PublicParameters<WitnessSpaceGroupElement<L>>;
pub(super) type WitnessSpaceValue<L> = group::Value<WitnessSpaceGroupElement<L>>;

pub(super) type StatementSpaceGroupElement<L> = <L as Language>::StatementSpaceGroupElement;
pub(super) type StatementSpacePublicParameters<L> =
    group::PublicParameters<StatementSpaceGroupElement<L>>;
pub(super) type StatementSpaceValue<L> = group::Value<StatementSpaceGroupElement<L>>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
    pub witness_space_public_parameters: WitnessSpacePublicParameters,
    pub public_value_space_public_parameters: StatementSpacePublicParameters,
}
