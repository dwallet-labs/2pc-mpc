// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use serde::{Deserialize, Serialize};

pub mod commitment_round;
pub mod proof_verification_round;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presign<GroupElementValue, ScalarValue, CiphertextValue> {
    pub(crate) nonce_share: ScalarValue, // $k_A$
    pub(crate) decentralized_party_nonce_public_share: GroupElementValue, // $R_B$
    pub(crate) encrypted_mask: CiphertextValue, // $\ct_1$
    pub(crate) encrypted_masked_key_share: CiphertextValue, // $\ct_2$
    pub(crate) commitment_randomness: ScalarValue, // $ρ_1$
}
