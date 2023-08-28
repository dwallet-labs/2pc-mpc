// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod group;
pub mod proofs;
mod traits;

use crypto_bigint::U128;

/// Represents an unsigned integer sized based on the computation security parameter, denoted as $\kappa$.
/// Configured for 128-bit security using U128.
pub type ComputationalSecuritySizedNumber = U128;
