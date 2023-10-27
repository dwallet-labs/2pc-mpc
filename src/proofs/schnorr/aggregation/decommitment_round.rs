// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    group::GroupElement,
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            aggregation::proof_share_round,
            language,
            language::{StatementSpaceGroupElement, StatementSpaceValue, WitnessSpaceGroupElement},
        },
    },
    Commitment, ComputationalSecuritySizedNumber, PartyID,
};

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Decommitment<Language: schnorr::Language> {
    pub(super) statements: Vec<StatementSpaceValue<Language>>,
    pub(super) statement_mask: StatementSpaceValue<Language>,
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    pub(super) party_id: PartyID,
    pub(super) language_public_parameters: language::PublicParameters<Language>,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<WitnessSpaceGroupElement<Language>>,
    pub(super) statements: Vec<StatementSpaceGroupElement<Language>>,
    pub(super) randomizer: WitnessSpaceGroupElement<Language>,
    pub(super) statement_mask: StatementSpaceGroupElement<Language>,
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

impl<Language: schnorr::Language, ProtocolContext: Clone + Serialize>
    Party<Language, ProtocolContext>
{
    pub fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Commitment>,
    ) -> (
        Decommitment<Language>,
        proof_share_round::Party<Language, ProtocolContext>,
    ) {
        let commitments = commitments
            .into_iter()
            .filter(|(party_id, _)| *party_id != self.party_id)
            .collect();

        let decommitment = Decommitment::<Language> {
            statements: self
                .statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            statement_mask: self.statement_mask.value(),
            commitment_randomness: self.commitment_randomness,
        };

        let proof_share_round_party = proof_share_round::Party::<Language, ProtocolContext> {
            party_id: self.party_id,
            language_public_parameters: self.language_public_parameters,
            protocol_context: self.protocol_context,
            witnesses: self.witnesses,
            statements: self.statements,
            randomizer: self.randomizer,
            statement_mask: self.statement_mask,
            commitments,
        };

        (decommitment, proof_share_round_party)
    }
}
