// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::GroupElement as _,
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            aggregation::{commitment_round::Commitment, decommitment_round::Decommitment},
            language,
            language::{StatementSpaceGroupElement, WitnessSpaceGroupElement, WitnessSpaceValue},
            Proof,
        },
    },
    PartyID,
};

#[derive(Serialize, Deserialize)]
pub struct ProofShare<Language: schnorr::Language, ProtocolContext: Clone + Serialize>(
    pub(super) Proof<Language, ProtocolContext>,
);

pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    pub(super) language_public_parameters: language::PublicParameters<Language>,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<WitnessSpaceGroupElement<Language>>,
    pub(super) statements: Vec<StatementSpaceGroupElement<Language>>,
    pub(super) randomizer: WitnessSpaceGroupElement<Language>,
    pub(super) statement_mask: StatementSpaceGroupElement<Language>,
    pub(super) commitments: HashMap<PartyID, Commitment>,
}

impl<Language: schnorr::Language, ProtocolContext: Clone + Serialize>
    Party<Language, ProtocolContext>
{
    pub fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Decommitment<Language>>,
    ) -> proofs::Result<ProofShare<Language, ProtocolContext>> {
        // TODO: now we are using the same protocol context for us and for decommitments, this is
        // faulty and is a security issue. Instead, we must somehow construct the protocol
        // context from our own, but given their party id (and anyother information which we might
        // need.) Otherwise, we can't assure that we're putting the party id to the
        // transcript.

        let previous_round_party_ids: Vec<PartyID> = self.commitments.keys().map(|k| *k).collect();
        let current_round_party_ids: Vec<PartyID> = decommitments.keys().map(|k| *k).collect();

        if current_round_party_ids != previous_round_party_ids {
            return Err(super::Error::ParticipatingPartiesChangedFromPreviousRound)?;
        }

        let reconstructed_commitments: proofs::Result<HashMap<PartyID, Commitment>> = decommitments
            .iter()
            .map(|(party_id, decommitment)| {
                Commitment::commit_statements_and_statement_mask::<Language, ProtocolContext>(
                    // TODO: insert the party id of the other party somehow, and maybe other
                    // things.
                    &self.protocol_context,
                    &self.language_public_parameters,
                    decommitment.statements.clone(),
                    &decommitment.statement_mask,
                    &decommitment.commitment_randomness,
                )
                .map(|reconstructed_commitment| (*party_id, reconstructed_commitment))
            })
            .collect();

        let reconstructed_commitments: HashMap<PartyID, Commitment> = reconstructed_commitments?;

        let miscommitting_parties: Vec<PartyID> = current_round_party_ids
            .into_iter()
            .filter(|party_id| reconstructed_commitments[party_id] != self.commitments[party_id])
            .collect();

        if !miscommitting_parties.is_empty() {
            return Err(super::Error::WrongDecommitment(miscommitting_parties))?;
        }

        let statement_masks: group::Result<Vec<StatementSpaceGroupElement<Language>>> =
            decommitments
                .iter()
                .map(|(_, decommitment)| {
                    StatementSpaceGroupElement::<Language>::new(
                        decommitment.statement_mask,
                        &self
                            .language_public_parameters
                            .as_ref()
                            .statement_space_public_parameters,
                    )
                })
                .collect();

        let aggregated_statement_mask = statement_masks?.into_iter().fold(
            self.statement_mask,
            |aggregated_statement_mask, statement_mask| aggregated_statement_mask + statement_mask,
        );

        let number_of_statements = self.statements.len();

        let parties_committed_on_wrong_number_of_statements: Vec<PartyID> = decommitments
            .iter()
            .filter(|(_, decommitment)| decommitment.statements.len() != number_of_statements)
            .map(|(party_id, _)| *party_id)
            .collect();

        if !parties_committed_on_wrong_number_of_statements.is_empty() {
            return Err(super::Error::WrongNumberOfDecommittedStatements(
                miscommitting_parties,
            ))?;
        }

        let statements_vector: group::Result<Vec<Vec<StatementSpaceGroupElement<Language>>>> =
            decommitments
                .into_values()
                .map(|decommitment| {
                    decommitment
                        .statements
                        .into_iter()
                        .map(|statement_value| {
                            StatementSpaceGroupElement::<Language>::new(
                                statement_value,
                                &self
                                    .language_public_parameters
                                    .as_ref()
                                    .statement_space_public_parameters,
                            )
                        })
                        .collect()
                })
                .collect();

        let statements_vector = statements_vector?;

        let aggregated_statements: Vec<StatementSpaceGroupElement<Language>> = (0
            ..number_of_statements)
            .map(|i| {
                statements_vector
                    .iter()
                    .map(|statements| statements[i].clone())
                    .fold(
                        self.statements[i].clone(),
                        |aggregated_group_element, statement| aggregated_group_element + statement,
                    )
            })
            .collect();

        Ok(ProofShare(Proof::<Language, ProtocolContext>::prove_inner(
            // TODO: we don't need to pass any party id here. Maybe we should seperate these types.
            &self.protocol_context,
            &self.language_public_parameters,
            self.witnesses,
            aggregated_statements,
            self.randomizer,
            aggregated_statement_mask,
        )?))
    }

    pub fn aggregate_proof_shares(
        proof_shares: HashMap<PartyID, Decommitment<Language>>,
    ) -> proofs::Result<Proof<Language, ProtocolContext>> {
        // TODO: should move this to a finalization round?
        todo!()
    }
}
