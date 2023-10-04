// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use serde::Serialize;

use crate::{
    proofs,
    proofs::{
        schnorr,
        schnorr::{language, language::StatementSpaceGroupElement},
    },
    PartyID,
};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_aggregation_round;
pub mod proof_share_round;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("parties {:?} participated in the previous round of the session but not in the current", .0)]
    UnresponsiveParties(Vec<PartyID>),

    #[error("parties {:?} maliciously attempted to bypass the commitment round by sending decommitment which does not match their commitment", .0)]
    WrongDecommitment(Vec<PartyID>),

    #[error("parties {:?} decommitted on a wrong number of statements", .0)]
    WrongNumberOfDecommittedStatements(Vec<PartyID>),

    #[error("parties {:?} sent an invalid proof share value", .0)]
    InvalidProofShare(Vec<PartyID>),

    #[error("parties {:?} sent a proof share that does not pass verification", .0)]
    ProofShareVerification(Vec<PartyID>),
}

pub type Result<T> = std::result::Result<T, Error>;

// TODO: do we actually want this struct?
pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    _language_choice: PhantomData<Language>,
    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<Language: schnorr::Language, ProtocolContext: Clone + Serialize>
    Party<Language, ProtocolContext>
{
    pub fn begin_session(
        party_id: PartyID,
        language_public_parameters: language::PublicParameters<Language>,
        protocol_context: ProtocolContext,
        witnesses: Vec<language::WitnessSpaceGroupElement<Language>>,
    ) -> proofs::Result<commitment_round::Party<Language, ProtocolContext>> {
        let statements: proofs::Result<Vec<StatementSpaceGroupElement<Language>>> = witnesses
            .iter()
            .map(|witness| Language::group_homomorphism(witness, &language_public_parameters))
            .collect();
        let statements = statements?;

        Ok(commitment_round::Party {
            party_id,
            language_public_parameters,
            protocol_context,
            witnesses,
            statements,
        })
    }
}

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::collections::HashMap;

    use rand_core::OsRng;

    use super::*;
    use crate::proofs::schnorr::{
        aggregation::{
            commitment_round::Commitment, decommitment_round::Decommitment,
            proof_share_round::ProofShare,
        },
        language::WitnessSpaceGroupElement,
        Language,
    };

    #[allow(dead_code)]
    pub(crate) fn aggregates<Lang: Language>(
        language_public_parameters: &Lang::PublicParameters,
        witnesses: Vec<Vec<WitnessSpaceGroupElement<Lang>>>,
    ) {
        let commitment_round_parties: HashMap<PartyID, commitment_round::Party<Lang, ()>> =
            witnesses
                .into_iter()
                .enumerate()
                .map(|(party_id, witnesses)| {
                    let party_id: u16 = party_id.try_into().unwrap();
                    (
                        party_id,
                        Party::begin_session(
                            party_id,
                            language_public_parameters.clone(),
                            (),
                            witnesses,
                        )
                        .unwrap(),
                    )
                })
                .collect();

        let commitments_and_decommitment_round_parties: HashMap<
            PartyID,
            (Commitment, decommitment_round::Party<Lang, ()>),
        > = commitment_round_parties
            .into_iter()
            .map(|(party_id, party)| {
                (
                    party_id,
                    party
                        .commit_statements_and_statement_mask(&mut OsRng)
                        .unwrap(),
                )
            })
            .collect();

        let commitments: HashMap<PartyID, Commitment> = commitments_and_decommitment_round_parties
            .iter()
            .map(|(party_id, (commitment, _))| (*party_id, *commitment))
            .collect();

        let decommitments_and_proof_share_round_parties: HashMap<
            PartyID,
            (Decommitment<Lang>, proof_share_round::Party<Lang, ()>),
        > = commitments_and_decommitment_round_parties
            .into_iter()
            .map(|(party_id, (_, party))| {
                (
                    party_id,
                    party.decommit_statements_and_statement_mask(commitments.clone()),
                )
            })
            .collect();

        let decommitments: HashMap<PartyID, Decommitment<Lang>> =
            decommitments_and_proof_share_round_parties
                .iter()
                .map(|(party_id, (decommitment, _))| (*party_id, decommitment.clone()))
                .collect();

        let proof_shares_and_proof_aggregation_round_parties: HashMap<
            PartyID,
            (ProofShare<Lang>, proof_aggregation_round::Party<Lang, ()>),
        > = decommitments_and_proof_share_round_parties
            .into_iter()
            .map(|(party_id, (_, party))| {
                (
                    party_id,
                    party.generate_proof_share(decommitments.clone()).unwrap(),
                )
            })
            .collect();

        let proof_shares: HashMap<PartyID, ProofShare<Lang>> =
            proof_shares_and_proof_aggregation_round_parties
                .iter()
                .map(|(party_id, (proof_share, _))| (*party_id, proof_share.clone())) // TODO: why can't copy
                .collect();

        let (_, (_, party)) = proof_shares_and_proof_aggregation_round_parties
            .into_iter()
            .next()
            .unwrap();

        let res = party.aggregate_proof_shares(proof_shares.clone());
        assert!(
            res.is_ok(),
            "valid proof aggregation sessions should yield verifiable aggregated proofs, instead got error: {:?}",
            res.err()
        );
    }
}
