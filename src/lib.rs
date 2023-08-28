// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0
pub mod group;
pub mod proofs;
mod traits;

use crypto_bigint::U128;

/// A type alias for an unsigned integer of the size of the computation security parameter $\kappa$.
/// Set to a U128 for 128-bit security.
pub type ComputationalSecuritySizedNumber = U128;
