// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
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
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, ristretto, Samplable},
    proofs,
    proofs::{
        range,
        range::{
            bulletproofs::{decommitment_round, RANGE_CLAIM_BITS},
            RangeProof,
        },
        schnorr::{
            aggregation::{commitment_round, CommitmentRoundParty},
            enhanced::{EnhanceableLanguage, EnhancedLanguage, EnhancedLanguageWitnessAccessors},
            language,
        },
        transcript_protocol::TranscriptProtocol,
    },
};

pub struct Party<
    'a,
    'b,
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
    pub commitment_round_party: commitment_round::Party<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            super::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >,

    pub bulletproofs_generators: &'b BulletproofGens,
    pub commitment_generators: &'b PedersenGens,
    pub transcript: &'a mut Transcript,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Commitment {
    pub(super) commitment: crate::Commitment,
    pub(super) bit_commitments: Vec<BitCommitment>,
}

impl<
        'a,
        'b,
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
        'a,
        'b,
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    type Commitment = Commitment;
    type DecommitmentRoundParty = decommitment_round::Party<
        'a,
        'b,
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
            .commitment_round_party
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

        let witnesses: Vec<_> = commitment_messages
            .into_iter()
            .map(|witness| <[_; NUM_RANGE_CLAIMS]>::from(witness))
            .flatten()
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

        let number_of_parties = self.commitment_round_party.number_of_parties;
        let number_of_witnesses = self.commitment_round_party.witnesses.len();

        if !number_of_witnesses.is_power_of_two() || !number_of_parties.is_power_of_two() {
            return Err(proofs::Error::InvalidParameters);
        }

        let number_of_parties = number_of_parties
            .checked_mul(
                number_of_witnesses
                    .try_into()
                    .map_err(|_| proofs::Error::Conversion)?,
            )
            .ok_or(proofs::Error::InvalidParameters)?;

        let commitments_randomness: Vec<_> = commitment_randomnesses
            .into_iter()
            .flat_map(|multicommitment_randomness| {
                <[_; NUM_RANGE_CLAIMS]>::from(multicommitment_randomness)
            })
            .map(|randomness| randomness.0)
            .collect();

        let dealer_awaiting_bit_commitments = Dealer::new(
            self.bulletproofs_generators,
            self.commitment_generators,
            self.transcript,
            RANGE_CLAIM_BITS,
            number_of_parties.into(),
        )
        .map_err(bulletproofs::ProofError::from)
        .map_err(range::Error::from)?;

        let parties: Vec<_> = witnesses
            .into_iter()
            .zip(commitments_randomness.into_iter())
            .map(|(witness, commitment_randomness)| {
                party::Party::new(
                    &self.bulletproofs_generators,
                    &self.commitment_generators,
                    witness,
                    commitment_randomness,
                    RANGE_CLAIM_BITS,
                )
                .map_err(bulletproofs::ProofError::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(range::Error::from)?;

        let (parties_awaiting_bit_challenge, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(i, party)| {
                party
                    .assign_position_with_rng(
                        usize::from(self.commitment_round_party.party_id) + i,
                        rng,
                    )
                    .map_err(bulletproofs::ProofError::from)
            })
            .collect::<Result<Vec<(_, _)>, _>>()
            .map_err(range::Error::from)?
            .into_iter()
            .unzip();

        let (commitment, decommitment_round_party) = self
            .commitment_round_party
            .commit_statements_and_statement_mask(rng)?;

        let decommitment_and_polycommitment_round_party = decommitment_round::Party {
            decommitment_round_party,
            dealer_awaiting_bit_commitments,
            parties_awaiting_bit_challenge,
        };

        let message = Commitment {
            commitment,
            bit_commitments,
        };

        Ok((message, decommitment_and_polycommitment_round_party))
    }
}
