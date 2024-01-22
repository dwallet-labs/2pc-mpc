// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::{Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    homomorphic_encryption, group,
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
    pub(super) encrypted_nonces: Vec<CiphertextValue>,
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
        homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
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
    encryption_of_discrete_log::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: schnorr::Language<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDHWitness,
        >,
{
    pub fn new(
        masks_and_encrypted_masked_key_share: Vec<
            enhanced::StatementSpaceGroupElement<
                { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
                { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
        // TODO: check sizes match?

        let encrypted_masks: Vec<_> = masks_and_encrypted_masked_key_share
            .iter()
            .map(|mask_and_encrypted_masked_key_share| {
                mask_and_encrypted_masked_key_share
                    .language_statement()
                    .encrypted_multiplicand()
                    .value()
            })
            .collect();

        let encrypted_masked_key_shares: Vec<_> = masks_and_encrypted_masked_key_share
            .iter()
            .map(|mask_and_encrypted_masked_key_share| {
                mask_and_encrypted_masked_key_share
                    .language_statement()
                    .encrypted_product()
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

        let encrypted_nonces: Vec<_> = encrypted_nonce_shares_and_public_shares
            .iter()
            .map(|nonce_share_encryption_and_public_share| {
                nonce_share_encryption_and_public_share
                    .language_statement()
                    .encrypted_discrete_log()
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
            encrypted_nonces,
            nonce_public_shares,
            nonce_sharing_range_proof_commitments,
            encrypted_nonce_shares_and_public_shares_proof,
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Presign<GroupElementValue, CiphertextValue> {
    pub(crate) centralized_party_nonce_share_commitment: GroupElementValue,
    pub(crate) nonce_public_share: GroupElementValue,
    pub(crate) encrypted_mask: CiphertextValue,
    pub(crate) encrypted_masked_key_share: CiphertextValue,
    pub(crate) encrypted_masked_nonce_share: CiphertextValue,
}

impl<GroupElementValue, CiphertextValue> Presign<GroupElementValue, CiphertextValue> {
    pub fn new<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        centralized_party_nonce_share_commitment: GroupElement,
        mask_and_encrypted_masked_key_share: encryption_of_tuple::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            EncryptionKey,
        >,
        encrypted_nonce_share_and_public_share: encryption_of_discrete_log::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >,
        encrypted_masked_nonce_share: encryption_of_tuple::StatementSpaceGroupElement<
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
            .encrypted_multiplicand()
            .value();

        let encrypted_masked_key_share = mask_and_encrypted_masked_key_share
            .encrypted_product()
            .value();

        let nonce_public_share = encrypted_nonce_share_and_public_share
            .base_by_discrete_log()
            .value();

        let encrypted_masked_nonce_share = encrypted_masked_nonce_share.encrypted_product().value();

        // TODO: I don't need to match encrypted nonce E(k) from both the previous round
        // aggregation and the current one right?

        Presign {
            centralized_party_nonce_share_commitment: centralized_party_nonce_share_commitment
                .value(),
            nonce_public_share,
            encrypted_mask,
            encrypted_masked_key_share,
            encrypted_masked_nonce_share,
        }
    }
}
