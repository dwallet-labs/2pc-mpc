// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::GroupElement as _,
    helpers::flat_map_results,
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            aggregation::{
                decommitment_round::Decommitment, proof_aggregation_round, ProofShareRoundParty,
            },
            language,
            language::{GroupsPublicParametersAccessors as _, WitnessSpaceValue},
            Proof,
        },
    },
    Commitment, PartyID,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProofShare<const REPETITIONS: usize, Language: schnorr::Language<REPETITIONS>>(
    #[serde(with = "crate::helpers::const_generic_array_serialization")]
    pub(super)  [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS],
);

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The language we are proving
    Language: language::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    pub(super) party_id: PartyID,
    pub(super) threshold: PartyID,
    pub(super) number_of_parties: PartyID,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) commitments: HashMap<PartyID, Commitment>,
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > ProofShareRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type Decommitment = Decommitment<REPETITIONS, Language>;
    type ProofShare = ProofShare<REPETITIONS, Language>;
    type ProofAggregationRoundParty =
        proof_aggregation_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Self::Decommitment>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self::ProofShare, Self::ProofAggregationRoundParty)> {
        let previous_round_party_ids: HashSet<PartyID> =
            self.commitments.keys().map(|k| *k).collect();
        // First remove parties that didn't participate in the previous round, as they shouldn't be
        // allowed to join the session half-way, and we can self-heal this malicious behaviour
        // without needing to stop the session and report
        let decommitments: HashMap<PartyID, Decommitment<REPETITIONS, Language>> = decommitments
            .into_iter()
            .filter(|(party_id, _)| *party_id != self.party_id)
            .filter(|(party_id, _)| previous_round_party_ids.contains(party_id))
            .collect();
        let current_round_party_ids: HashSet<PartyID> = decommitments.keys().map(|k| *k).collect();

        let number_of_parties = decommitments.len() + 1;

        let unresponsive_parties: Vec<PartyID> = current_round_party_ids
            .symmetric_difference(&previous_round_party_ids)
            .cloned()
            .collect();

        if !unresponsive_parties.is_empty() {
            return Err(super::Error::UnresponsiveParties(unresponsive_parties))?;
        }

        let reconstructed_commitments: proofs::Result<HashMap<PartyID, Commitment>> = decommitments
            .iter()
            .map(|(party_id, decommitment)| {
                Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
                    // TODO: insert the party id of the other party somehow, and maybe other
                    // things.
                    &self.protocol_context,
                    &self.language_public_parameters,
                    decommitment.statements.clone(),
                    &decommitment.statement_masks,
                )
                .map(|mut transcript| {
                    (
                        *party_id,
                        Commitment::commit_transcript(
                            &mut transcript,
                            &decommitment.commitment_randomness,
                        ),
                    )
                })
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

        let statement_masks: group::Result<
            Vec<[Language::StatementSpaceGroupElement; REPETITIONS]>,
        > = decommitments
            .values()
            .map(|decommitment| {
                flat_map_results(decommitment.statement_masks.map(|statement_mask| {
                    Language::StatementSpaceGroupElement::new(
                        statement_mask,
                        &self
                            .language_public_parameters
                            .statement_space_public_parameters(),
                    )
                }))
            })
            .collect();

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

        let aggregated_statement_masks = statement_masks?.into_iter().fold(
            Ok(self.statement_masks),
            |aggregated_statement_masks, statement_masks| {
                aggregated_statement_masks.and_then(|aggregated_statement_masks| {
                    aggregated_statement_masks
                        .into_iter()
                        .zip(statement_masks)
                        .map(|(aggregated_statement_mask, statement_mask)| {
                            aggregated_statement_mask + statement_mask
                        })
                        .collect::<Vec<_>>()
                        .try_into()
                        .map_err(|_| proofs::Error::InternalError)
                })
            },
        )?;

        let statements_vector: group::Result<Vec<Vec<Language::StatementSpaceGroupElement>>> =
            decommitments
                .into_values()
                .map(|decommitment| {
                    decommitment
                        .statements
                        .into_iter()
                        .map(|statement_value| {
                            Language::StatementSpaceGroupElement::new(
                                statement_value,
                                &self
                                    .language_public_parameters
                                    .statement_space_public_parameters(),
                            )
                        })
                        .collect()
                })
                .collect();

        let statements_vector = statements_vector?;

        let aggregated_statements: Vec<Language::StatementSpaceGroupElement> = (0
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

        let responses = Proof::<REPETITIONS, Language, ProtocolContext>::prove_inner(
            number_of_parties,
            &self.protocol_context,
            &self.language_public_parameters,
            self.witnesses,
            aggregated_statements.clone(),
            self.randomizers,
            aggregated_statement_masks.clone(),
        )?
        .responses;

        let proof_share = ProofShare(responses);

        let responses = flat_map_results(responses.map(|value| {
            Language::WitnessSpaceGroupElement::new(
                value,
                &self
                    .language_public_parameters
                    .witness_space_public_parameters(),
            )
        }))?;

        let proof_aggregation_round_party =
            proof_aggregation_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                threshold: self.threshold,
                number_of_parties: self.number_of_parties,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                previous_round_party_ids,
                aggregated_statements,
                aggregated_statement_masks,
                responses,
            };

        Ok((proof_share, proof_aggregation_round_party))
    }
}
