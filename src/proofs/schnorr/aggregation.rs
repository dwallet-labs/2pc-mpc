#[cfg(feature = "benchmarking")]
pub(crate) use benches::{benchmark, benchmark_enhanced};
use serde::Serialize;

use crate::{proofs::schnorr::language, PartyID};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_aggregation_round;
pub mod proof_share_round;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("threshold not reached: received insufficient messages")]
    ThresholdNotReached,

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

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::collections::HashMap;

    use rand_core::OsRng;

    use super::*;
    use crate::{
        proofs::schnorr::{
            aggregation::{decommitment_round::Decommitment, proof_share_round::ProofShare},
            Language,
        },
        Commitment,
    };

    #[allow(dead_code)]
    pub(crate) fn aggregates<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        witnesses: Vec<Vec<Lang::WitnessSpaceGroupElement>>,
    ) {
        let number_of_parties = witnesses.len().try_into().unwrap();
        let mut witnesses = witnesses;

        let party_id = (witnesses.len() - 1).try_into().unwrap();
        let party = commitment_round::Party {
            party_id,
            threshold: number_of_parties,
            number_of_parties,
            language_public_parameters: language_public_parameters.clone(),
            protocol_context: (),
            witnesses: witnesses.pop().unwrap(),
        };

        let mut commitment_round_parties: HashMap<
            PartyID,
            commitment_round::Party<REPETITIONS, Lang, ()>,
        > = witnesses
            .into_iter()
            .enumerate()
            .map(|(party_id, witnesses)| {
                let party_id: u16 = party_id.try_into().unwrap();
                (
                    party_id,
                    commitment_round::Party {
                        party_id,
                        threshold: number_of_parties,
                        number_of_parties,
                        language_public_parameters: language_public_parameters.clone(),
                        protocol_context: (),
                        witnesses,
                    },
                )
            })
            .collect();

        let commitments_and_decommitment_round_parties: HashMap<
            PartyID,
            (Commitment, decommitment_round::Party<REPETITIONS, Lang, ()>),
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
            (
                Decommitment<REPETITIONS, Lang>,
                proof_share_round::Party<REPETITIONS, Lang, ()>,
            ),
        > = commitments_and_decommitment_round_parties
            .into_iter()
            .map(|(party_id, (_, party))| {
                (
                    party_id,
                    party
                        .decommit_statements_and_statement_mask(commitments.clone())
                        .unwrap(),
                )
            })
            .collect();

        let (decommitment, proof_share_round_party) = decommitment_round_party
            .decommit_statements_and_statement_mask(commitments)
            .unwrap();

        let mut decommitments: HashMap<PartyID, Decommitment<REPETITIONS, Lang>> =
            decommitments_and_proof_share_round_parties
                .iter()
                .map(|(party_id, (decommitment, _))| (*party_id, decommitment.clone()))
                .collect();

        decommitments.insert(party_id, decommitment);

        let proof_shares_and_proof_aggregation_round_parties: HashMap<
            PartyID,
            (
                ProofShare<REPETITIONS, Lang>,
                proof_aggregation_round::Party<REPETITIONS, Lang, ()>,
            ),
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

        let mut proof_shares: HashMap<PartyID, ProofShare<REPETITIONS, Lang>> =
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
    use std::{collections::HashMap, iter, marker::PhantomData};

    use criterion::Criterion;
    use crypto_bigint::{Encoding, Uint};
    use rand_core::OsRng;

    use super::*;
    use crate::{
        commitments,
        proofs::schnorr::{
            aggregation::{decommitment_round::Decommitment, proof_share_round::ProofShare},
            EnhancedLanguage, Language, Proof,
        },
        Commitment,
    };

    pub(crate) fn benchmark<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: Lang::PublicParameters,
        c: &mut Criterion,
    ) {
        for batch_size in [1, 10, 100, 1000] {
            let mut witnesses = language::tests::generate_witnesses::<REPETITIONS, Lang>(
                &language_public_parameters,
                batch_size,
            );

            benchmark_internal::<REPETITIONS, Lang>(
                language_public_parameters.clone(),
                witnesses,
                batch_size,
                c,
            )
        }
    }

    pub(crate) fn benchmark_enhanced<
        const REPETITIONS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Lang: EnhancedLanguage<
            REPETITIONS,
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
        for batch_size in [1, 10, 100, 1000] {
            let mut witnesses = language::enhanced::tests::generate_witnesses::<
                REPETITIONS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                Lang,
            >(&language_public_parameters, batch_size);

            benchmark_internal::<REPETITIONS, Lang>(
                language_public_parameters.clone(),
                witnesses,
                batch_size,
                c,
            )
        }
    }

    fn benchmark_internal<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
        batch_size: usize,
        c: &mut Criterion,
    ) {
        let mut g = c.benchmark_group(format!(
            "{:?} aggregation over {batch_size} statements",
            Lang::NAME
        ));

        g.sample_size(10);

        for number_of_parties in [1, 10, 100, 1000] {
            // TODO: DRY-out, have enhanced witnesses generate accordingly
            let party_id = (witnesses.len() - 1).try_into().unwrap();
            let party = commitment_round::Party {
                party_id,
                threshold: number_of_parties,
                number_of_parties,
                language_public_parameters: language_public_parameters.clone(),
                protocol_context: (),
                witnesses: witnesses.clone(),
            };

            g.bench_function(format!("commitment round"), |bench| {
                bench.iter(|| {
                    party
                        .clone()
                        .commit_statements_and_statement_mask(&mut OsRng)
                        .unwrap()
                })
            });

            let (commitment, decommitment_round_party) = party
                .commit_statements_and_statement_mask(&mut OsRng)
                .unwrap();
            let commitments: HashMap<PartyID, Commitment> =
                iter::repeat_with(|| commitment.clone())
                    .take(number_of_parties.into())
                    .enumerate()
                    .map(|(party_id, x)| (party_id.try_into().unwrap(), x))
                    .collect();

            g.bench_function(
                format!("decommitment round for {number_of_parties} parties"),
                |bench| {
                    bench.iter(|| {
                        decommitment_round_party
                            .clone()
                            .decommit_statements_and_statement_mask(commitments.clone())
                    })
                },
            );

            let (decommitment, proof_share_round_party) = decommitment_round_party
                .clone()
                .decommit_statements_and_statement_mask(commitments)
                .unwrap();

            let decommitments: HashMap<PartyID, Decommitment<REPETITIONS, Lang>> =
                iter::repeat_with(|| decommitment.clone())
                    .take(number_of_parties.into())
                    .enumerate()
                    .map(|(party_id, x)| (party_id.try_into().unwrap(), x))
                    .collect();

            g.bench_function(
                format!("proof share round for {number_of_parties} parties"),
                |bench| {
                    bench.iter(|| {
                        proof_share_round_party
                            .clone()
                            .generate_proof_share(decommitments.clone())
                            .unwrap()
                    })
                },
            );

            let (proof_share, proof_aggregation_round_party) = proof_share_round_party
                .clone()
                .generate_proof_share(decommitments.clone())
                .unwrap();

            let proof_shares: HashMap<PartyID, ProofShare<REPETITIONS, Lang>> =
                iter::repeat_with(|| proof_share.clone())
                    .take(number_of_parties.into())
                    .enumerate()
                    .map(|(party_id, x)| (party_id.try_into().unwrap(), x))
                    .collect();

            g.bench_function(
                format!("proof aggregation round for {number_of_parties} parties"),
                |bench| {
                    bench.iter(|| {
                        assert!(proof_aggregation_round_party
                            .clone()
                            .aggregate_proof_shares(proof_shares.clone())
                            .is_ok());
                    })
                },
            );
        }

        g.finish();
    }
}
