// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, Concat, Random, U256};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::decommitment_round;
use crate::{
    group::{GroupElement as _, Samplable},
    proofs,
    proofs::{
        schnorr,
        schnorr::{
            language,
            language::{StatementSpaceGroupElement, StatementSpaceValue, WitnessSpaceGroupElement},
            Proof,
        },
        TranscriptProtocol,
    },
    CommitmentSizedNumber, ComputationalSecuritySizedNumber,
};

pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    pub(super) language_public_parameters: language::PublicParameters<Language>,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<WitnessSpaceGroupElement<Language>>,
    pub(super) statements: Vec<StatementSpaceGroupElement<Language>>,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct Commitment(CommitmentSizedNumber);

impl Commitment {
    pub(super) fn commit_statements_and_statement_mask<
        Language: schnorr::Language,
        ProtocolContext: Clone + Serialize,
    >(
        protocol_context: &ProtocolContext,
        language_public_parameters: &language::PublicParameters<Language>,
        statements: Vec<StatementSpaceValue<Language>>,
        statement_mask: &StatementSpaceValue<Language>,
        commitment_randomness: &ComputationalSecuritySizedNumber,
    ) -> proofs::Result<Self> {
        let mut transcript = Proof::<Language, ProtocolContext>::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements,
            &statement_mask,
        )?;

        transcript.append_uint(
            b"schnorr proof aggregation commitment round commitment randomness",
            commitment_randomness,
        );

        // TODO: what size?
        Ok(Commitment(transcript.challenge(
            b"schnorr proof aggregation commitment round commitment",
        )))
    }
}

impl<Language: schnorr::Language, ProtocolContext: Clone + Serialize>
    Party<Language, ProtocolContext>
{
    pub fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Commitment,
        decommitment_round::Party<Language, ProtocolContext>,
    )> {
        let (randomizer, statement_mask) =
            Proof::<Language, ProtocolContext>::compute_statement_mask(
                &self.language_public_parameters,
                rng,
            )?;

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        let commitment =
            Commitment::commit_statements_and_statement_mask::<Language, ProtocolContext>(
                &self.protocol_context,
                &self.language_public_parameters,
                self.statements
                    .iter()
                    .map(|statement| statement.value())
                    .collect(),
                &statement_mask.value(),
                &commitment_randomness,
            )?;

        let decommitment_round_party = decommitment_round::Party::<Language, ProtocolContext> {
            language_public_parameters: self.language_public_parameters,
            protocol_context: self.protocol_context,
            witnesses: self.witnesses,
            statements: self.statements,
            randomizer,
            statement_mask,
            commitment_randomness,
        };

        Ok((commitment, decommitment_round_party))
    }
}
