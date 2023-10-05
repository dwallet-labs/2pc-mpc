// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::marker::PhantomData;

#[cfg(feature = "benchmarking")]
pub(crate) use benches::{benchmark, benchmark_enhanced};
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
        let mut witnesses = witnesses;

        let party_id = (witnesses.len() - 1).try_into().unwrap();
        let party = Party::begin_session(
            party_id,
            language_public_parameters.clone(),
            (),
            witnesses.pop().unwrap(),
        )
        .unwrap();

        let mut commitment_round_parties: HashMap<PartyID, commitment_round::Party<Lang, ()>> =
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

        let (commitment, decommitment_round_party) = party
            .commit_statements_and_statement_mask(&mut OsRng)
            .unwrap();

        let mut commitments: HashMap<PartyID, Commitment> =
            commitments_and_decommitment_round_parties
                .iter()
                .map(|(party_id, (commitment, _))| (*party_id, *commitment))
                .collect();

        commitments.insert(party_id, commitment);

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

        let (decommitment, proof_share_round_party) =
            decommitment_round_party.decommit_statements_and_statement_mask(commitments);

        let mut decommitments: HashMap<PartyID, Decommitment<Lang>> =
            decommitments_and_proof_share_round_parties
                .iter()
                .map(|(party_id, (decommitment, _))| (*party_id, decommitment.clone()))
                .collect();

        decommitments.insert(party_id, decommitment);

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

        let (proof_share, proof_aggregation_round_party) = proof_share_round_party
            .generate_proof_share(decommitments.clone())
            .unwrap();

        let mut proof_shares: HashMap<PartyID, ProofShare<Lang>> =
            proof_shares_and_proof_aggregation_round_parties
                .iter()
                .map(|(party_id, (proof_share, _))| (*party_id, proof_share.clone())) // TODO: why can't copy
                .collect();

        proof_shares.insert(party_id, proof_share);

        let res = proof_aggregation_round_party.aggregate_proof_shares(proof_shares.clone());
        assert!(
            res.is_ok(),
            "valid proof aggregation sessions should yield verifiable aggregated proofs, instead got error: {:?}",
            res.err()
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::{collections::HashMap, marker::PhantomData};

    use criterion::Criterion;
    use crypto_bigint::{Encoding, Uint};
    use rand_core::OsRng;

    use super::*;
    use crate::proofs::schnorr::{
        aggregation::{
            commitment_round::Commitment, decommitment_round::Decommitment,
            proof_share_round::ProofShare,
        },
        language::WitnessSpaceGroupElement,
        EnhancedLanguage, Language, Proof,
    };

    pub(crate) fn benchmark<Lang: Language>(
        language_public_parameters: Lang::PublicParameters,
        c: &mut Criterion,
    ) {
        for number_of_parties in [1, 10, 100, 1000] {
            for batch_size in [1, 10, 100, 1000] {
                let mut witnesses = language::tests::generate_witnesses_for_aggregation::<Lang>(
                    &language_public_parameters,
                    number_of_parties,
                    batch_size,
                );

                benchmark_internal::<Lang>(
                    language_public_parameters.clone(),
                    witnesses,
                    number_of_parties,
                    batch_size,
                    c,
                )
            }
        }
    }

    pub(crate) fn benchmark_enhanced<
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Lang: EnhancedLanguage<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
        >,
    >(
        language_public_parameters: Lang::PublicParameters,
        c: &mut Criterion,
    ) where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        Uint<WITNESS_MASK_LIMBS>: Encoding,
    {
        for number_of_parties in [1000] {
            for batch_size in [1] {
                // for number_of_parties in [1, 10, 100, 1000] {
                //     for batch_size in [1, 10, 100, 1000] {
                let mut witnesses = language::enhanced::tests::generate_witnesses_for_aggregation::<
                    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    NUM_RANGE_CLAIMS,
                    RANGE_CLAIM_LIMBS,
                    WITNESS_MASK_LIMBS,
                    Lang,
                >(
                    &language_public_parameters, number_of_parties, batch_size
                );

                benchmark_internal::<Lang>(
                    language_public_parameters.clone(),
                    witnesses,
                    number_of_parties,
                    batch_size,
                    c,
                )
            }
        }
    }

    fn benchmark_internal<Lang: Language>(
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Vec<WitnessSpaceGroupElement<Lang>>>,
        number_of_parties: usize,
        batch_size: usize,
        c: &mut Criterion,
    ) {
        let mut g = c.benchmark_group(format!(
            "{:?} aggregation for {number_of_parties} parties over {batch_size} statements",
            Lang::NAME
        ));

        g.sample_size(10);
        // TODO: DRY-out, have enhanced witnesses generate accordingly
        let mut witnesses = witnesses;
        let party_id = (witnesses.len() - 1).try_into().unwrap();
        let party_witnesses = witnesses.pop().unwrap();

        g.bench_function("compute statements", |bench| {
            bench.iter(|| {
                Party::<Lang, ()>::begin_session(
                    party_id,
                    language_public_parameters.clone(),
                    (),
                    party_witnesses.clone(),
                )
                .unwrap()
            })
        });

        let party = Party::<Lang, ()>::begin_session(
            party_id,
            language_public_parameters.clone(),
            (),
            party_witnesses,
        )
        .unwrap();

        let mut commitment_round_parties: HashMap<PartyID, commitment_round::Party<Lang, ()>> =
            witnesses
                .iter()
                .enumerate()
                .map(|(party_id, witnesses)| {
                    let party_id: u16 = party_id.try_into().unwrap();
                    (
                        party_id,
                        Party::<Lang, ()>::begin_session(
                            party_id,
                            language_public_parameters.clone(),
                            (),
                            witnesses.to_vec(),
                        )
                        .unwrap(),
                    )
                })
                .collect();

        g.bench_function(format!("commitment round"), |bench| {
            bench.iter(|| {
                party
                    .clone()
                    .commit_statements_and_statement_mask(&mut OsRng)
                    .unwrap()
            })
        });

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

        let (commitment, decommitment_round_party) = party
            .commit_statements_and_statement_mask(&mut OsRng)
            .unwrap();

        let mut commitments: HashMap<PartyID, Commitment> =
            commitments_and_decommitment_round_parties
                .iter()
                .map(|(party_id, (commitment, _))| (*party_id, *commitment))
                .collect();

        commitments.insert(party_id, commitment);

        g.bench_function(format!("decommitment round"), |bench| {
            bench.iter(|| {
                decommitment_round_party
                    .clone()
                    .decommit_statements_and_statement_mask(commitments.clone())
            })
        });

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

        let (decommitment, proof_share_round_party) =
            decommitment_round_party.decommit_statements_and_statement_mask(commitments);

        let mut decommitments: HashMap<PartyID, Decommitment<Lang>> =
            decommitments_and_proof_share_round_parties
                .iter()
                .map(|(party_id, (decommitment, _))| (*party_id, decommitment.clone()))
                .collect();

        decommitments.insert(party_id, decommitment);

        g.bench_function(format!("proof share round"), |bench| {
            bench.iter(|| {
                proof_share_round_party
                    .clone()
                    .generate_proof_share(decommitments.clone())
                // .unwrap()
            })
        });

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

        let (proof_share, proof_aggregation_round_party) = proof_share_round_party
            .generate_proof_share(decommitments.clone())
            .unwrap();

        let mut proof_shares: HashMap<PartyID, ProofShare<Lang>> =
            proof_shares_and_proof_aggregation_round_parties
                .iter()
                .map(|(party_id, (proof_share, _))| (*party_id, proof_share.clone())) // TODO: why can't copy
                .collect();

        proof_shares.insert(party_id, proof_share);

        g.bench_function(format!("proof aggregation round"), |bench| {
            bench.iter(|| {
                assert!(proof_aggregation_round_party
                    .clone()
                    .aggregate_proof_shares(proof_shares.clone())
                    .is_ok());
            })
        });

        g.finish();
    }
}
