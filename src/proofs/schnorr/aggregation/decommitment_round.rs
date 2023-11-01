// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::GroupElement,
    proofs,
    proofs::{
        schnorr,
        schnorr::{aggregation::proof_share_round, language},
    },
    Commitment, ComputationalSecuritySizedNumber, PartyID,
};

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Decommitment<const REPETITIONS: usize, Language: language::Language<REPETITIONS>> {
    pub(super) statements: Vec<group::Value<Language::StatementSpaceGroupElement>>,
    #[serde(with = "crate::helpers::const_generic_array_serialization")]
    pub(super) statement_masks: [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The language we are proving
    // TODO: lets have some consistency. Somewhere this is called Lang, and then no 'language::` is
    // necessairy. Here it's Language. Please just lets be consistent.
    Language: language::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    pub(super) party_id: PartyID,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > Party<REPETITIONS, Language, ProtocolContext>
{
    pub fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Commitment>,
    ) -> (
        Decommitment<REPETITIONS, Language>,
        proof_share_round::Party<REPETITIONS, Language, ProtocolContext>,
    ) {
        let commitments = commitments
            .into_iter()
            .filter(|(party_id, _)| *party_id != self.party_id)
            .collect();

        let decommitment = Decommitment::<REPETITIONS, Language> {
            statements: self
                .statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            // TODO: take this from previous round instead of computing values again here.
            statement_masks: self
                .statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
            commitment_randomness: self.commitment_randomness,
        };

        let proof_share_round_party =
            proof_share_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                witnesses: self.witnesses,
                statements: self.statements,
                randomizers: self.randomizers,
                statement_masks: self.statement_masks,
                commitments,
            };

        (decommitment, proof_share_round_party)
    }
}
