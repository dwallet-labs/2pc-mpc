// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use core::iter;
use std::marker::PhantomData;

use bulletproofs::{
    range_proof_mpc::{dealer::Dealer, messages::BitCommitment, party},
    BulletproofGens, PedersenGens,
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint, U256, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    group::{ristretto, Samplable},
    proofs,
    proofs::{
        range,
        range::{
            bulletproofs::{decommitment_round, RANGE_CLAIM_BITS},
            RangeProof,
        },
        schnorr::{
            aggregation::{commitment_round, CommitmentRoundParty},
            enhanced,
            enhanced::{
                EnhanceableLanguage, EnhancedLanguage, EnhancedLanguageWitnessAccessors,
                EnhancedPublicParameters,
            },
            language,
        },
        transcript_protocol::TranscriptProtocol,
    },
    PartyID,
};

pub struct Party<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> {
    pub party_id: PartyID,
    pub threshold: PartyID,
    pub number_of_parties: PartyID,
    pub language_public_parameters: EnhancedPublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        super::RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
    // TODO: should I use the same protocol context for both bp & schnorr?
    pub protocol_context: ProtocolContext,
    pub witnesses: Vec<
        enhanced::WitnessSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            super::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
    >,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub(super) commitment: crate::Commitment,
    pub(super) bit_commitments: Vec<BitCommitment>,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    >
    CommitmentRoundParty<
        super::Output<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >,
    >
    for Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    type Commitment = Commitment;
    type DecommitmentRoundParty = decommitment_round::Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >;

    /// Due to a limitation in Bulletproofs, assumes both the number of parties and the number of
    /// witnesses are powers of 2. If one needs a non-power-of-two, pad to the
    /// `next_power_of_two` by creating additional parties with zero-valued witnesses and having
    /// every party emulate those locally.
    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self::Commitment, Self::DecommitmentRoundParty)> {
        let (commitment_messages, commitment_randomnesses): (Vec<_>, Vec<_>) = self
            .witnesses
            .clone()
            .into_iter()
            .map(|witness| {
                (
                    witness.range_proof_commitment_message().clone(),
                    witness.range_proof_commitment_randomness().clone(),
                )
            })
            .unzip();

        let batch_size = commitment_messages.len();

        let witnesses: Vec<_> = commitment_messages
            .into_iter()
            .flat_map(|witness| <[_; NUM_RANGE_CLAIMS]>::from(witness))
            .map(|witness: ristretto::Scalar| U256::from(witness))
            .collect();

        if witnesses
            .iter()
            .any(|witness| witness > &(&U64::MAX).into())
        {
            return Err(range::Error::OutOfRange)?;
        }

        let witnesses: Vec<u64> = witnesses
            .into_iter()
            .map(|witness| U64::from(&witness).into())
            .collect();

        let number_of_parties = self.number_of_parties;
        let number_of_witnesses = witnesses.len();

        if !number_of_witnesses.is_power_of_two() || !number_of_parties.is_power_of_two() {
            return Err(proofs::Error::InvalidParameters);
        }

        let number_of_parties = number_of_parties
            .checked_mul(
                number_of_witnesses
                    .try_into()
                    .map_err(|_| proofs::Error::InternalError)?,
            )
            .ok_or(proofs::Error::InternalError)?;

        let commitments_randomness: Vec<_> = commitment_randomnesses
            .into_iter()
            .flat_map(|multicommitment_randomness| {
                <[_; NUM_RANGE_CLAIMS]>::from(multicommitment_randomness)
            })
            .map(|randomness| randomness.0)
            .collect();

        let bulletproofs_generators = BulletproofGens::new(
            range::bulletproofs::RANGE_CLAIM_BITS,
            number_of_parties.into(),
        );

        let commitment_generators = PedersenGens::default();

        let transcript = enhanced::Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            range::bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >::setup_range_proof(
            &self.protocol_context, &super::PublicParameters::default()
        )?;

        let dealer_awaiting_bit_commitments = Dealer::new(
            bulletproofs_generators.clone(),
            commitment_generators.clone(),
            transcript,
            RANGE_CLAIM_BITS,
            number_of_parties.into(),
        )
        .map_err(bulletproofs::ProofError::from)
        .map_err(range::bulletproofs::Error::from)
        .map_err(range::Error::from)?;

        let parties: Vec<_> = witnesses
            .into_iter()
            .zip(commitments_randomness.into_iter())
            .map(|(witness, commitment_randomness)| {
                party::Party::new(
                    bulletproofs_generators.clone(),
                    commitment_generators.clone(),
                    witness,
                    commitment_randomness,
                    RANGE_CLAIM_BITS,
                )
                .map_err(bulletproofs::ProofError::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(range::bulletproofs::Error::from)
            .map_err(range::Error::from)?;

        let (parties_awaiting_bit_challenge, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(i, party)| {
                usize::from(self.party_id)
                    .checked_sub(1)
                    .and_then(|position| position.checked_mul(NUM_RANGE_CLAIMS))
                    .and_then(|position| position.checked_mul(batch_size))
                    .and_then(|position| position.checked_add(i))
                    .ok_or(proofs::Error::InternalError)
                    .and_then(|position| {
                        party
                            .assign_position_with_rng(position, rng)
                            .map_err(bulletproofs::ProofError::from)
                            .map_err(range::bulletproofs::Error::from)
                            .map_err(range::Error::from)
                            .map_err(proofs::Error::from)
                    })
            })
            .collect::<Result<Vec<(_, _)>, _>>()?
            .into_iter()
            .unzip();

        let commitment_round_party = commitment_round::Party::new_enhanced_session(
            self.party_id,
            self.threshold,
            self.number_of_parties,
            self.language_public_parameters,
            self.protocol_context,
            self.witnesses,
            rng,
        )?;

        let (commitment, decommitment_round_party) =
            commitment_round_party.commit_statements_and_statement_mask(rng)?;

        let decommitment_round_party = decommitment_round::Party {
            decommitment_round_party,
            dealer_awaiting_bit_commitments,
            parties_awaiting_bit_challenge,
        };

        let message = Commitment {
            commitment,
            bit_commitments,
        };

        Ok((message, decommitment_round_party))
    }
}
