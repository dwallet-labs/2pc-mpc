// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use serde::{Deserialize, Serialize};

pub mod commitment_round;
pub mod proof_verification_round;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presign<GroupElementValue, ScalarValue, CiphertextValue> {
    pub(crate) nonce_share: ScalarValue,
    pub(crate) decentralized_party_nonce_public_share: GroupElementValue,
    pub(crate) encrypted_mask: CiphertextValue,
    pub(crate) encrypted_masked_key_share: CiphertextValue,
    pub(crate) commitment_randomness: ScalarValue,
}
