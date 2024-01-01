// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    ahe, group,
    group::{GroupElement as _, PrimeGroupElement, Samplable},
    proofs,
    proofs::{
        range, schnorr,
        schnorr::{
            encryption_of_discrete_log, encryption_of_tuple,
            encryption_of_tuple::StatementAccessors as _,
            enhanced,
            enhanced::{EnhanceableLanguage, EnhancedLanguageStatementAccessors},
            language::encryption_of_discrete_log::StatementAccessors as _,
        },
    },
    AdditivelyHomomorphicEncryptionKey,
};

pub mod encrypted_masked_key_share_and_public_nonce_shares_round;
pub mod encrypted_masked_nonces_round;

// TODO: name this?
#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Output<
    GroupElementValue,
    RangeProofCommitmentValue,
    CiphertextValue,
    EncDHProof,
    EncDLProof,
> {
    // TODO: make sure the vectors are of the same length?
    pub(super) encrypted_masks: Vec<CiphertextValue>,
    pub(super) encrypted_masked_key_shares: Vec<CiphertextValue>,
    pub(super) key_share_masking_range_proof_commitments: Vec<RangeProofCommitmentValue>,
    pub(super) masks_and_encrypted_masked_key_share_proof: EncDHProof,
    pub(super) nonce_public_shares: Vec<GroupElementValue>,
    pub(super) nonce_sharing_range_proof_commitments: Vec<RangeProofCommitmentValue>,
    pub(super) encrypted_nonce_shares_and_public_shares_proof: EncDLProof,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >
    Output<
        GroupElement::Value,
        range::CommitmentSchemeCommitmentSpaceValue<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RangeProof,
        >,
        ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        encryption_of_tuple::EnhancedProof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            UnboundedEncDHWitness,
            RangeProof,
            ProtocolContext,
        >,
        encryption_of_discrete_log::EnhancedProof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            UnboundedEncDLWitness,
            RangeProof,
            ProtocolContext,
        >,
    >
where
    // TODO: I'd love to solve this huge restriction, which seems completely useless to me and is
    // required because Rust.
    encryption_of_discrete_log::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: schnorr::Language<
            { encryption_of_discrete_log::REPETITIONS },
            WitnessSpaceGroupElement = encryption_of_discrete_log::WitnessSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            StatementSpaceGroupElement = encryption_of_discrete_log::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
            PublicParameters = encryption_of_discrete_log::PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        > + EnhanceableLanguage<
            { encryption_of_discrete_log::REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDLWitness,
        >,
    encryption_of_tuple::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: schnorr::Language<
            { encryption_of_tuple::REPETITIONS },
            WitnessSpaceGroupElement = encryption_of_tuple::WitnessSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            StatementSpaceGroupElement = encryption_of_tuple::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                EncryptionKey,
            >,
            PublicParameters = encryption_of_tuple::PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        > + EnhanceableLanguage<
            { encryption_of_tuple::REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDHWitness,
        >,
{
    pub fn new(
        masks_and_encrypted_masked_key_share: Vec<
            enhanced::StatementSpaceGroupElement<
                { encryption_of_tuple::REPETITIONS },
                RANGE_CLAIMS_PER_SCALAR,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedEncDHWitness,
                encryption_of_tuple::Language<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
            >,
        >,
        masks_and_encrypted_masked_key_share_proof: encryption_of_tuple::EnhancedProof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            UnboundedEncDHWitness,
            RangeProof,
            ProtocolContext,
        >,
        encrypted_nonce_shares_and_public_shares: Vec<
            enhanced::StatementSpaceGroupElement<
                { encryption_of_tuple::REPETITIONS },
                RANGE_CLAIMS_PER_SCALAR,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedEncDLWitness,
                encryption_of_discrete_log::Language<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
            >,
        >,
        encrypted_nonce_shares_and_public_shares_proof: encryption_of_discrete_log::EnhancedProof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            UnboundedEncDLWitness,
            RangeProof,
            ProtocolContext,
        >,
    ) -> Self {
        let encrypted_masks: Vec<_> = masks_and_encrypted_masked_key_share
            .iter()
            .map(|mask_and_encrypted_masked_key_share| {
                mask_and_encrypted_masked_key_share
                    .language_statement()
                    .encryption_of_multiplicand()
                    .value()
            })
            .collect();

        let encrypted_masked_key_shares: Vec<_> = masks_and_encrypted_masked_key_share
            .iter()
            .map(|mask_and_encrypted_masked_key_share| {
                mask_and_encrypted_masked_key_share
                    .language_statement()
                    .encryption_of_product()
                    .value()
            })
            .collect();

        let key_share_masking_range_proof_commitments: Vec<_> =
            masks_and_encrypted_masked_key_share
                .iter()
                .map(|mask_and_encrypted_masked_key_share| {
                    mask_and_encrypted_masked_key_share
                        .range_proof_commitment()
                        .value()
                })
                .collect();

        let nonce_public_shares: Vec<_> = encrypted_nonce_shares_and_public_shares
            .iter()
            .map(|nonce_share_encryption_and_public_share| {
                nonce_share_encryption_and_public_share
                    .language_statement()
                    .base_by_discrete_log()
                    .value()
            })
            .collect();

        let nonce_sharing_range_proof_commitments: Vec<_> =
            encrypted_nonce_shares_and_public_shares
                .iter()
                .map(|nonce_share_encryption_and_public_share| {
                    nonce_share_encryption_and_public_share
                        .range_proof_commitment()
                        .value()
                })
                .collect();

        Self {
            encrypted_masks,
            encrypted_masked_key_shares,
            key_share_masking_range_proof_commitments,
            masks_and_encrypted_masked_key_share_proof,
            nonce_public_shares,
            nonce_sharing_range_proof_commitments,
            encrypted_nonce_shares_and_public_shares_proof,
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Presign<GroupElementValue, CiphertextValue> {
    pub(crate) nonce_public_share: GroupElementValue,
    pub(crate) encrypted_mask: CiphertextValue,
    pub(crate) encrypted_masked_key_share: CiphertextValue,
    pub(crate) encrypted_masked_nonce: CiphertextValue,
}

impl<GroupElementValue, CiphertextValue> Presign<GroupElementValue, CiphertextValue> {
    pub fn new<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        mask_and_encrypted_masked_key_share: encryption_of_tuple::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            EncryptionKey,
        >,
        encrypted_nonce_share_and_public_share:
        encryption_of_discrete_log::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >,
        encrypted_masked_nonce: encryption_of_tuple::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            EncryptionKey,
        >,
    ) -> Self
    where
        GroupElement: group::GroupElement<Value = GroupElementValue>,
        EncryptionKey::CiphertextSpaceGroupElement: group::GroupElement<Value = CiphertextValue>,
    {
        let encrypted_mask = mask_and_encrypted_masked_key_share
            .encryption_of_multiplicand()
            .value();

        let encrypted_masked_key_share = mask_and_encrypted_masked_key_share
            .encryption_of_product()
            .value();

        let nonce_public_share = encrypted_nonce_share_and_public_share
            .base_by_discrete_log()
            .value();

        let encrypted_masked_nonce = encrypted_masked_nonce.encryption_of_product().value();

        // TODO: I don't need to match encryption of the nonce E(k) from both the previous round
        // aggregation and the current one right?

        Presign {
            nonce_public_share,
            encrypted_mask,
            encrypted_masked_key_share,
            encrypted_masked_nonce,
        }
    }
}
