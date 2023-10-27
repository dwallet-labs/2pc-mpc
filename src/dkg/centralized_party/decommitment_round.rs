// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    dkg::centralized_party::decommitment_round,
    group,
    group::{secp256k1, GroupElement as _, Samplable},
    proofs::schnorr::{knowledge_of_discrete_log, language::GroupsPublicParameters, Proof},
    Commitment, ComputationalSecuritySizedNumber,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party {
    pub(super) secret_key_share: secp256k1::Scalar,
    pub(super) public_key_share: secp256k1::GroupElement,
    pub(super) proof: Proof<
        knowledge_of_discrete_log::Language<secp256k1::Scalar, secp256k1::GroupElement>,
        PhantomData<()>,
    >,
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    proof: Proof<
        knowledge_of_discrete_log::Language<secp256k1::Scalar, secp256k1::GroupElement>,
        PhantomData<()>,
    >,
    public_key_share: group::Value<secp256k1::GroupElement>,
}
