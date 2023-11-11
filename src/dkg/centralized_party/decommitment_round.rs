// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::{
    group::PrimeGroupElement, proofs::schnorr::knowledge_of_discrete_log,
    ComputationalSecuritySizedNumber,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub(super) secret_key_share: GroupElement::Scalar,
    pub(super) public_key_share: GroupElement,
    pub(super) proof:
        knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

// #[derive(Serialize, Deserialize, Clone)]
// pub struct Message {
//     proof: Proof<
//         knowledge_of_discrete_log::Language<secp256k1::Scalar, secp256k1::GroupElement>,
//         PhantomData<()>,
//     >,
//     public_key_share: group::Value<secp256k1::GroupElement>,
// }
