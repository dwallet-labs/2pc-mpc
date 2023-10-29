// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crate::{proofs::schnorr::aggregation, Commitment};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party {
    commitment_to_centralized_party_secret_key_share: Commitment,
    encryption_of_secret_share_decommitment_round_party: aggregation::decommitment_round::Party<
        super::EncryptionOfSecretKeyShareLanguage,
        PhantomData<()>,
    >,
}
