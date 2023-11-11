// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Clone)]
pub struct Message<GroupElementValue, DLProof> {
    proof: DLProof,
    public_key_share: GroupElementValue,
}

impl<
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    > Party<SCALAR_LIMBS, GroupElement, ProtocolContext>
{
}
