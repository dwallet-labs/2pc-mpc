// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crate::group::secp256k1;

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party {
    pub(super) secret_key_share: secp256k1::Scalar,
}
