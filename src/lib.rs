// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub use ahe::{AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey};
#[cfg(feature = "benchmarking")]
use criterion::criterion_group;
use crypto_bigint::{Concat, U128, U64};

pub mod ahe;
pub mod commitments;
pub mod group;
pub(crate) mod helpers;
pub mod proofs;
mod traits;

/// Represents an unsigned integer sized based on the computation security parameter, denoted as
/// $\kappa$. Configured for 128-bit computational security using U128.
pub type ComputationalSecuritySizedNumber = U128;

/// Represents an unsigned integer sized based on the statistical security parameter, denoted as
/// $s$. Configured for 64-bit statistical security using U64.
pub type StatisticalSecuritySizedNumber = U64;

/// Represents an unsigned integer sized based on the commitment size that matches security
/// parameter, which is double in size, as collisions can be found in the root of the space.
pub type CommitmentSizedNumber = <ComputationalSecuritySizedNumber as Concat>::Output;

/// A unique identifier of a party in a MPC protocol.
pub type PartyID = u16;

#[cfg(feature = "benchmarking")]
criterion_group!(
    benches,
    proofs::schnorr::knowledge_of_discrete_log::benchmark,
    proofs::schnorr::knowledge_of_decommitment::benchmark,
    proofs::schnorr::commitment_of_discrete_log::benchmark,
    proofs::schnorr::discrete_log_ratio_of_commited_values::benchmark,
    proofs::schnorr::encryption_of_discrete_log::benchmark,
    proofs::schnorr::committed_linear_evaluation::benchmark,
);
