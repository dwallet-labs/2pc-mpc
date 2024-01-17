// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use serde::Serialize;

use crate::{
    group,
    group::GroupElement as _,
    helpers::FlatMapResults,
    proofs,
    proofs::schnorr::{
        aggregation::{proof_share_round::ProofShare, ProofAggregationRoundParty},
        language,
        language::GroupsPublicParametersAccessors as _,
        Proof,
    },
    PartyID,
};

pub type Output<const REPETITIONS: usize, Language, ProtocolContext> = (
    Proof<REPETITIONS, Language, ProtocolContext>,
    Vec<language::StatementSpaceGroupElement<REPETITIONS, Language>>,
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
    pub(crate) number_of_parties: PartyID,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) previous_round_party_ids: HashSet<PartyID>,
    pub(super) aggregated_statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) aggregated_statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) responses: [Language::WitnessSpaceGroupElement; REPETITIONS],
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > ProofAggregationRoundParty<Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type ProofShare = ProofShare<REPETITIONS, Language>;

    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<Output<REPETITIONS, Language, ProtocolContext>> {
        // TODO: DRY-out!
        // First remove parties that didn't participate in the previous round, as they shouldn't be
        // allowed to join the session half-way, and we can self-heal this malicious behaviour
        // without needing to stop the session and report
        let proof_shares: HashMap<PartyID, ProofShare<REPETITIONS, Language>> = proof_shares
            .into_iter()
            .filter(|(party_id, _)| *party_id != self.party_id)
            .filter(|(party_id, _)| self.previous_round_party_ids.contains(party_id))
            .collect();

        let number_of_parties = proof_shares.len() + 1;

        let current_round_party_ids: HashSet<PartyID> = proof_shares.keys().copied().collect();

        let unresponsive_parties: Vec<PartyID> = current_round_party_ids
            .symmetric_difference(&self.previous_round_party_ids)
            .cloned()
            .collect();

        if !unresponsive_parties.is_empty() {
            return Err(super::Error::UnresponsiveParties(unresponsive_parties))?;
        }

        let proof_shares: HashMap<
            PartyID,
            group::Result<[Language::WitnessSpaceGroupElement; REPETITIONS]>,
        > = proof_shares
            .into_iter()
            .map(|(party_id, proof_share)| {
                (
                    party_id,
                    proof_share
                        .0
                        .map(|value| {
                            Language::WitnessSpaceGroupElement::new(
                                value,
                                &self
                                    .language_public_parameters
                                    .witness_space_public_parameters(),
                            )
                        })
                        .flat_map_results(),
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

        let proof_shares: HashMap<PartyID, [Language::WitnessSpaceGroupElement; REPETITIONS]> =
            proof_shares
                .into_iter()
                .map(|(party_id, proof_share)| (party_id, proof_share.unwrap()))
                .collect();

        // TODO: helper function
        let response =
            proof_shares
                .values()
                .fold(Ok(self.responses), |aggregated_reponses, proof_share| {
                    aggregated_reponses.and_then(|aggregated_reponses| {
                        aggregated_reponses
                            .into_iter()
                            .zip(proof_share)
                            .map(|(aggregated_reponse, response)| aggregated_reponse + response)
                            .collect::<Vec<_>>()
                            .try_into()
                            .map_err(|_| proofs::Error::InternalError)
                    })
                });

        // TODO: this stage should be done seperately for enhanced proofs and the responses need to
        // be range-checked.
        let aggregated_proof = Proof::new(&self.aggregated_statement_masks, &response?);
        if aggregated_proof
            .verify(
                Some(number_of_parties),
                &self.protocol_context,
                &self.language_public_parameters,
                self.aggregated_statements.clone(),
            )
            .is_err()
        {
            // TODO: this should be their own statement mask, not the aggregated one
            // But the challenges should still remain the same - need to seperate the verify()
            // function, and take the challenge from the aggregated proof and pass it there
            let proof_share_cheating_parties: Vec<PartyID> = proof_shares
                .into_iter()
                .map(|(party_id, proof_share)| {
                    (
                        party_id,
                        Proof::<REPETITIONS, Language, ProtocolContext>::new(
                            &self.aggregated_statement_masks,
                            &proof_share,
                        ),
                    )
                })
                .filter(|(_, proof)| {
                    proof
                        .verify(
                            Some(number_of_parties),
                            &self.protocol_context,
                            &self.language_public_parameters,
                            self.aggregated_statements.clone(),
                        )
                        .is_err()
                })
                .map(|(party_id, _)| party_id)
                .collect();

            return Err(super::Error::ProofShareVerification(
                proof_share_cheating_parties,
            ))?;
        }

        Ok((aggregated_proof, self.aggregated_statements))
    }
}
