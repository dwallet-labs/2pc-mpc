// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use serde::{Deserialize, Serialize};

pub mod signature_homomorphic_evaluation_round;
mod signature_verification_round;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicNonceEncryptedPartialSignatureAndProof<
    GroupElementValue,
    RangeProofCommitmentValue,
    CiphertextValue,
    ComDLProof,
    ComRatioProof,
    DComEvalProof,
> {
    pub public_nonce: GroupElementValue,
    pub(super) public_nonce_proof: ComDLProof,
    pub(super) nonce_share_by_key_share_commitment: GroupElementValue,
    pub(super) nonce_share_by_key_share_proof: ComRatioProof,
    pub(super) first_coefficient_commitment: GroupElementValue,
    pub(super) second_coefficient_commitment: GroupElementValue,
    pub(super) encrypted_partial_signature: CiphertextValue,
    pub(super) encrypted_partial_signature_range_proof_commitment: RangeProofCommitmentValue,
    pub(super) encrypted_partial_signature_proof: DComEvalProof,
}
