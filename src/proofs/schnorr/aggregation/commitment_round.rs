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
    Commitment, CommitmentSizedNumber, ComputationalSecuritySizedNumber, PartyID,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    pub party_id: PartyID,
    pub language_public_parameters: language::PublicParameters<Language>,
    pub protocol_context: ProtocolContext,
    pub witnesses: Vec<WitnessSpaceGroupElement<Language>>,
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
        let statements: proofs::Result<Vec<StatementSpaceGroupElement<Language>>> = self
            .witnesses
            .iter()
            .map(|witness| Language::group_homomorphism(witness, &self.language_public_parameters))
            .collect();
        let statements = statements?;

        let (randomizer, statement_mask) =
            Proof::<Language, ProtocolContext>::sample_randomizer_and_statement_mask(
                &self.language_public_parameters,
                rng,
            )?;

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        let mut transcript = Proof::<Language, ProtocolContext>::setup_transcript(
            &self.protocol_context,
            &self.language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &statement_mask.value(),
        )?;

        // TODO: party id?

        let commitment = Commitment::commit_transcript(&mut transcript, &commitment_randomness);

        let decommitment_round_party = decommitment_round::Party::<Language, ProtocolContext> {
            party_id: self.party_id,
            language_public_parameters: self.language_public_parameters,
            protocol_context: self.protocol_context,
            witnesses: self.witnesses,
            statements,
            randomizer,
            statement_mask,
            commitment_randomness,
        };

        Ok((commitment, decommitment_round_party))
    }
}
