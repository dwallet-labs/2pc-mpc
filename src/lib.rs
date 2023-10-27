// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub use ahe::{AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey};
#[cfg(feature = "benchmarking")]
use criterion::criterion_group;
use crypto_bigint::{Concat, U128, U64};
use merlin::Transcript;
use proofs::transcript_protocol::TranscriptProtocol as _;
use serde::{Deserialize, Serialize};

pub mod ahe;
pub mod commitments;
mod dkg;
pub mod group;
pub(crate) mod helpers;
pub mod proofs;
mod traits;

/// Represents an unsigned integer sized based on the computation security parameter, denoted as
/// $\kappa$.
pub type ComputationalSecuritySizedNumber = U128;

// TODO: what value should this be
pub const COMPUTATIONAL_SECURITY_PARAMETERS: usize = 112;

/// Represents an unsigned integer sized based on the statistical security parameter, denoted as
/// $s$. Configured for 64-bit statistical security using U64.
pub type StatisticalSecuritySizedNumber = U64;

/// Represents an unsigned integer sized based on the commitment size that matches security
/// parameter, which is double in size, as collisions can be found in the root of the space.
pub type CommitmentSizedNumber = <ComputationalSecuritySizedNumber as Concat>::Output;

#[derive(PartialEq, Serialize, Deserialize, Clone, Copy)]
pub struct Commitment(CommitmentSizedNumber);

impl Commitment {
    pub fn commit_transcript(
        transcript: &mut Transcript,
        commitment_randomness: &ComputationalSecuritySizedNumber,
    ) -> Self {
        transcript.append_uint(
            b"schnorr proof aggregation commitment round commitment randomness",
            commitment_randomness,
        );

        Commitment(transcript.challenge(b"schnorr proof aggregation commitment round commitment"))
    }
}

/// A unique identifier of a party in a MPC protocol.
pub type PartyID = u16;

#[cfg(feature = "benchmarking")]
criterion_group!(
    benches,
    proofs::transcript_protocol::benchmark,
    proofs::schnorr::knowledge_of_discrete_log::benchmark,
    proofs::schnorr::knowledge_of_decommitment::benchmark,
    proofs::schnorr::commitment_of_discrete_log::benchmark,
    proofs::schnorr::discrete_log_ratio_of_commited_values::benchmark,
    proofs::schnorr::encryption_of_discrete_log::benchmark,
    proofs::schnorr::encryption_of_tuple::benchmark,
    proofs::schnorr::committed_linear_evaluation::benchmark,
);
