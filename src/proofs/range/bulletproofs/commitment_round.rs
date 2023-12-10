// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use core::iter;

use bulletproofs::{
    range_proof_mpc::{dealer::Dealer, messages::BitCommitment, party},
    BulletproofGens, PedersenGens,
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, ristretto},
    proofs,
    proofs::{
        range::{
            bulletproofs::{
                decommitment_and_poly_commitment_round, RANGE_CLAIM_BITS, RANGE_CLAIM_LIMBS,
                SCALAR_LIMBS,
            },
            RangeProof,
        },
        schnorr::{
            aggregation::commitment_round, language,
            language::enhanced::EnhancedLanguageWitnessAccessors, EnhancedLanguage,
        },
        transcript_protocol::TranscriptProtocol,
    },
    Commitment,
};

pub struct Party<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const WITNESS_MASK_LIMBS: usize,
    Language: EnhancedLanguage<
        REPETITIONS,
        { SCALAR_LIMBS },
        NUM_RANGE_CLAIMS,
        { RANGE_CLAIM_LIMBS },
        WITNESS_MASK_LIMBS,
        RangeProof = super::RangeProof,
    >,
    ProtocolContext: Clone,
> where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    pub commitment_round_party: commitment_round::Party<REPETITIONS, Language, ProtocolContext>,
    pub bulletproofs_generators: BulletproofGens,
    pub commitment_generators: PedersenGens,
    pub transcript: Transcript,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pub(super) commitment: Commitment,
    pub(super) bit_commitments: Vec<BitCommitment>,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Language: EnhancedLanguage<
            REPETITIONS,
            { SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            { RANGE_CLAIM_LIMBS },
            WITNESS_MASK_LIMBS,
            RangeProof = super::RangeProof,
        >,
        ProtocolContext: Clone + Serialize,
    > Party<REPETITIONS, NUM_RANGE_CLAIMS, WITNESS_MASK_LIMBS, Language, ProtocolContext>
where
    Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    // TODO: new function, remove pub.

    /// Due to a limitation in Bulletproofs, assumes both the number of parties and the number of
    /// witnesses are powers of 2. If one needs a non-power-of-two, pad to the
    /// `next_power_of_two` by creating additional parties with zero-valued witnesses and having
    /// every party emulate those locally.
    pub fn commit_statements(
        mut self,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(
        Message,
        decommitment_and_poly_commitment_round::Party<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            WITNESS_MASK_LIMBS,
            Language,
            ProtocolContext,
        >,
    )> {
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

        let (constrained_witnesses, commitments_randomness): (
            Vec<[u64; NUM_RANGE_CLAIMS]>,
            Vec<
                language::enhanced::RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
                    REPETITIONS,
                    { SCALAR_LIMBS },
                    NUM_RANGE_CLAIMS,
                    { RANGE_CLAIM_LIMBS },
                    WITNESS_MASK_LIMBS,
                    Language,
                >,
            >,
        ) = self
            .commitment_round_party
            .witnesses
            .clone()
            .into_iter()
            .map(|witness| {
                let constrained_witness: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>;
                    NUM_RANGE_CLAIMS] = (*witness.constrained_witness()).into();

                let constrained_witness: [u64; NUM_RANGE_CLAIMS] =
                    constrained_witness.map(|witness_part| {
                        let witness_part_value: Uint<WITNESS_MASK_LIMBS> = witness_part.into();

                        let witness_part_value: U64 = (&witness_part_value).into();

                        witness_part_value.to_limbs()[0].0
                    });

                (
                    constrained_witness,
                    witness.range_proof_commitment_randomness().clone(),
                )
            })
            .unzip();

        // TODO: DRY

        let constrained_witnesses: Vec<_> =
            constrained_witnesses.into_iter().flat_map(|x| x).collect();

        let commitments_randomness: Vec<curve25519_dalek::scalar::Scalar> = commitments_randomness
            .into_iter()
            .flat_map(|multicommitment_randomness| {
                <[ristretto::Scalar; NUM_RANGE_CLAIMS]>::from(multicommitment_randomness)
            })
            .map(|randomness| randomness.0)
            .collect();

        let dealer_awaiting_bit_commitments = Dealer::new(
            &self.bulletproofs_generators,
            &self.commitment_generators,
            &mut self.transcript,
            RANGE_CLAIM_BITS,
            number_of_parties.into(),
        )
        .map_err(bulletproofs::ProofError::from)?;

        let parties: Vec<_> = constrained_witnesses
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
            .collect::<Result<Vec<_>, _>>()?;

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
            .collect::<Result<Vec<(_, _)>, _>>()?
            .into_iter()
            .unzip();

        let (commitment, decommitment_round_party) = self
            .commitment_round_party
            .commit_statements_and_statement_mask(rng)?;

        let decommitment_and_polycommitment_round_party =
            decommitment_and_poly_commitment_round::Party {
                decommitment_round_party,
                dealer_awaiting_bit_commitments,
                parties_awaiting_bit_challenge,
            };

        let message = Message {
            commitment,
            bit_commitments,
        };

        Ok((message, decommitment_and_polycommitment_round_party))
    }
}
