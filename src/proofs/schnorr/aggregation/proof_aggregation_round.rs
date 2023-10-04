// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::{
    group,
    group::GroupElement as _,
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            aggregation::proof_share_round::ProofShare,
            language,
            language::{StatementSpaceGroupElement, WitnessSpaceGroupElement},
            Proof,
        },
    },
    PartyID,
};

pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    pub(super) language_public_parameters: language::PublicParameters<Language>,
    pub(super) protocol_context: ProtocolContext,
    pub(super) previous_round_party_ids: HashSet<PartyID>,
    pub(super) aggregated_statements: Vec<StatementSpaceGroupElement<Language>>,
    pub(super) aggregated_statement_mask: StatementSpaceGroupElement<Language>,
    pub(super) response: WitnessSpaceGroupElement<Language>,
}

impl<Language: schnorr::Language, ProtocolContext: Clone + Serialize>
    Party<Language, ProtocolContext>
{
    pub fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, ProofShare<Language>>,
    ) -> proofs::Result<(
        Proof<Language, ProtocolContext>,
        Vec<StatementSpaceGroupElement<Language>>,
    )> {
        // TODO: DRY-out!
        // First remove parties that didn't participate in the previous round, as they shouldn't be
        // allowed to join the session half-way, and we can self-heal this malicious behaviour
        // without needing to stop the session and report
        let proof_shares: HashMap<PartyID, ProofShare<Language>> = proof_shares
            .into_iter()
            .filter(|(party_id, _)| self.previous_round_party_ids.contains(party_id))
            .collect();
        let current_round_party_ids: HashSet<PartyID> = proof_shares.keys().map(|k| *k).collect();

        let unresponsive_parties: Vec<PartyID> = current_round_party_ids
            .symmetric_difference(&self.previous_round_party_ids)
            .cloned()
            .collect();

        if !unresponsive_parties.is_empty() {
            return Err(super::Error::UnresponsiveParties(unresponsive_parties))?;
        }

        let proof_shares: HashMap<PartyID, group::Result<WitnessSpaceGroupElement<Language>>> =
            proof_shares
                .into_iter()
                .map(|(party_id, proof_share)| {
                    (
                        party_id,
                        WitnessSpaceGroupElement::<Language>::new(
                            proof_share.0,
                            &self
                                .language_public_parameters
                                .as_ref()
                                .witness_space_public_parameters,
                        ),
                    )
                })
                .collect();

        let parties_sending_invalid_proof_shares: Vec<PartyID> = proof_shares
            .iter()
            .filter(|(_, proof_share)| proof_share.is_err())
            .map(|(party_id, _)| *party_id)
            .collect();

        if !parties_sending_invalid_proof_shares.is_empty() {
            return Err(super::Error::InvalidProofShare(
                parties_sending_invalid_proof_shares,
            ))?;
        }

        let proof_shares: HashMap<PartyID, WitnessSpaceGroupElement<Language>> = proof_shares
            .into_iter()
            .map(|(party_id, proof_share)| (party_id, proof_share.unwrap()))
            .collect();

        let response = proof_shares
            .values()
            .fold(self.response, |aggregated_reponse, proof_share| {
                aggregated_reponse + proof_share
            });

        let aggregated_proof = Proof::new(&self.aggregated_statement_mask, &response);
        if aggregated_proof
            .verify(
                &self.protocol_context,
                &self.language_public_parameters,
                self.aggregated_statements.clone(),
            )
            .is_err()
        {
            let proof_share_cheating_parties: Vec<PartyID> = proof_shares
                .into_iter()
                .map(|(party_id, proof_share)| {
                    (
                        party_id,
                        Proof::<Language, ProtocolContext>::new(
                            &self.aggregated_statement_mask,
                            &proof_share,
                        ),
                    )
                })
                .filter(|(_, proof)| {
                    proof
                        .verify(
                            &self.protocol_context,
                            &self.language_public_parameters,
                            self.aggregated_statements.clone(),
                        )
                        .is_err()
                })
                .map(|(party_id, _)| party_id)
                .collect();
        }

        Ok((aggregated_proof, self.aggregated_statements))
    }
}
