// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod ahe;
pub mod commitments;
pub mod group;
pub(crate) mod helpers;
pub mod proofs;
mod traits;

pub use ahe::{AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey};
use crypto_bigint::{U128, U64};

/// Represents an unsigned integer sized based on the computation security parameter, denoted as
/// $\kappa$. Configured for 128-bit computational security using U128.
pub type ComputationalSecuritySizedNumber = U128;

/// Represents an unsigned integer sized based on the statistical security parameter, denoted as
/// $s$. Configured for 64-bit statistical security using U64.
pub type StatisticalSecuritySizedNumber = U64;
