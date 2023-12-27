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
        range, schnorr,
        schnorr::{
            aggregation::CommitmentRoundParty,
            enhanced,
            enhanced::{EnhancedLanguage, EnhancedPublicParameters},
            language,
            language::enhanced::EnhanceableLanguage,
            Proof,
        },
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
    pub(crate) party_id: PartyID,
    pub(crate) threshold: PartyID,
    pub(crate) number_of_parties: PartyID,
    pub(crate) language_public_parameters: Language::PublicParameters,
    pub(crate) protocol_context: ProtocolContext,
    pub(crate) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > CommitmentRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type Commitment = Commitment;

    type DecommitmentRoundParty = decommitment_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self::Commitment, Self::DecommitmentRoundParty)> {
        let statements: proofs::Result<Vec<Language::StatementSpaceGroupElement>> = self
            .witnesses
            .iter()
            .map(|witness| Language::group_homomorphism(witness, &self.language_public_parameters))
            .collect();
        let statements = statements?;

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        // TODO: put them all into the transcript
        let mut transcript = Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
            &self.protocol_context,
            &self.language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &self
                .statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
        )?;

        // TODO: party id?

        let commitment = Commitment::commit_transcript(&mut transcript, &commitment_randomness);

        let decommitment_round_party =
            decommitment_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                threshold: self.threshold,
                number_of_parties: self.number_of_parties,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                witnesses: self.witnesses,
                statements,
                randomizers: self.randomizers,
                statement_masks: self.statement_masks,
                commitment_randomness,
            };

        Ok((commitment, decommitment_round_party))
    }
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > Party<REPETITIONS, Language, ProtocolContext>
{
    pub fn new_session(
        party_id: PartyID,
        threshold: PartyID,
        number_of_parties: PartyID,
        language_public_parameters: Language::PublicParameters,
        protocol_context: ProtocolContext,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<Self> {
        let (randomizers, statement_masks) = Proof::<
            REPETITIONS,
            Language,
            ProtocolContext,
        >::sample_randomizers_and_statement_masks(
            &language_public_parameters, rng,
        )?;

        Ok(Self {
            party_id,
            threshold,
            number_of_parties,
            language_public_parameters,
            protocol_context,
            witnesses,
            randomizers,
            statement_masks,
        })
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: range::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >
{
    pub fn new_enhanced_session(
        party_id: PartyID,
        threshold: PartyID,
        number_of_parties: PartyID,
        language_public_parameters: EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        protocol_context: ProtocolContext,
        witnesses: Vec<
            enhanced::WitnessSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<Self> {
        let batch_size = witnesses.len();

        let (randomizers, statement_masks) = enhanced::Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >::sample_randomizers_and_statement_masks(
            number_of_parties.into(),
            batch_size,
            &language_public_parameters,
            rng,
        )?;

        Ok(Self {
            party_id,
            threshold,
            number_of_parties,
            language_public_parameters,
            protocol_context,
            witnesses,
            randomizers,
            statement_masks,
        })
    }
}
