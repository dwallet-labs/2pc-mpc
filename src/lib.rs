// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0
mod group;
pub mod proofs;
mod traits;

/// A type alias for an unsigned integer of the size of the computation security parameter $\kappa$.
/// Set to a U128 for 128-bit security.
pub type ComputationalSecuritySizedNumber = U128;
use crypto_bigint::U128;
