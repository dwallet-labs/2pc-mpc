// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group::Samplable,
    proofs,
    proofs::{schnorr, schnorr::knowledge_of_decommitment},
    StatisticalSecuritySizedNumber,
};

// TODO: should this be dependent on some variables?
const REPETITIONS: usize = 128;

pub type WitnessSpaceGroupElement<const MESSAGE_SPACE_SCALAR_LIMBS: usize, CommitmentScheme> =
    schnorr::language::WitnessSpaceGroupElement<
        REPETITIONS,
        knowledge_of_decommitment::Language<
            REPETITIONS,
            MESSAGE_SPACE_SCALAR_LIMBS,
            CommitmentScheme,
        >,
    >;

/// Lightningproofs Range Proof.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RangeProof<
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> where
    CommitmentScheme::MessageSpaceGroupElement: Samplable,
    CommitmentScheme::RandomnessSpaceGroupElement: Samplable,
{
    schnorr_proof: schnorr::Proof<
        REPETITIONS,
        knowledge_of_decommitment::Language<
            REPETITIONS,
            MESSAGE_SPACE_SCALAR_LIMBS,
            CommitmentScheme,
        >,
        ProtocolContext,
    >,
}

impl<
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    > RangeProof<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme, ProtocolContext>
where
    CommitmentScheme::MessageSpaceGroupElement: Samplable,
    CommitmentScheme::RandomnessSpaceGroupElement: Samplable,
{
    pub fn prove(
        witnesses: Vec<WitnessSpaceGroupElement<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>>,
        protocol_context: &ProtocolContext,
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        // TODO: because this is a bit-soundness, number of parties has no implications on params
        // right?
        todo!()
    }

    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
        commitments: Vec<CommitmentScheme::CommitmentSpaceGroupElement>,
    ) -> proofs::Result<()> {
        // TODO: because this is a bit-soundness, number of parties has no implications on params
        // right?
        // TODO: call schnorr verify and do range check
        todo!()
    }
}

// TODO: do we even want this???
pub fn range_claim_bits<const MESSAGE_SPACE_SCALAR_LIMBS: usize>() -> usize {
    // TODO: formula, and maybe return `Result` and check conditions.
    Uint::<MESSAGE_SPACE_SCALAR_LIMBS>::BITS - StatisticalSecuritySizedNumber::BITS
}
