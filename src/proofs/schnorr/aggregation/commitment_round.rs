// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, Concat, Random, U256};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::decommitment_round;
use crate::{
    group,
    group::{GroupElement as _, Samplable},
    proofs,
    proofs::{
        schnorr,
        schnorr::{language, Proof},
        TranscriptProtocol,
    },
    Commitment, CommitmentSizedNumber, ComputationalSecuritySizedNumber, PartyID,
};

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
    pub party_id: PartyID,
    pub language_public_parameters: Language::PublicParameters,
    pub protocol_context: ProtocolContext,
    pub witnesses: Vec<Language::WitnessSpaceGroupElement>,
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > Party<REPETITIONS, Language, ProtocolContext>
{
    pub fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Commitment,
        decommitment_round::Party<REPETITIONS, Language, ProtocolContext>,
    )> {
        let statements: proofs::Result<Vec<Language::StatementSpaceGroupElement>> = self
            .witnesses
            .iter()
            .map(|witness| Language::group_homomorphism(witness, &self.language_public_parameters))
            .collect();
        let statements = statements?;

        let (randomizers, statement_masks) = Proof::<
            REPETITIONS,
            Language,
            ProtocolContext,
        >::sample_randomizers_and_statement_masks(
            &self.language_public_parameters, rng,
        )?;

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        // TODO: put them all into the transcript
        let mut transcript = Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
            &self.protocol_context,
            &self.language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
        )?;

        // TODO: party id?

        let commitment = Commitment::commit_transcript(&mut transcript, &commitment_randomness);

        let decommitment_round_party =
            decommitment_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                witnesses: self.witnesses,
                statements,
                randomizers,
                statement_masks,
                commitment_randomness,
            };

        Ok((commitment, decommitment_round_party))
    }
}
