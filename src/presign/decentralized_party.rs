// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use commitment::Pedersen;
use crypto_bigint::{Encoding, Uint};
use enhanced_maurer::{
    encryption_of_discrete_log, encryption_of_discrete_log::StatementAccessors as _,
    encryption_of_tuple, encryption_of_tuple::StatementAccessors as _,
    language::EnhancedLanguageStatementAccessors, EnhanceableLanguage,
};
use group::{GroupElement as _, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use maurer::{knowledge_of_decommitment, SOUND_PROOFS_REPETITIONS};
use proof::{range, AggregatableRangeProof};
use serde::{Deserialize, Serialize};

use crate::{
    presign::centralized_party::commitment_round::SignatureNonceSharesCommitmentsAndBatchedProof,
    Error, Result,
};

pub mod encrypted_masked_key_share_and_public_nonce_shares_round;
pub mod encrypted_masked_nonces_round;

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Output<
    GroupElementValue,
    RangeProofCommitmentValue,
    CiphertextValue,
    EncDHProof,
    EncDLProof,
> {
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
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
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
        encryption_of_tuple::Proof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDHWitness,
            ProtocolContext,
        >,
        encryption_of_discrete_log::Proof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            ProtocolContext,
        >,
    >
where
    encryption_of_discrete_log::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: maurer::Language<
            SOUND_PROOFS_REPETITIONS,
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
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDLWitness,
        >,
    encryption_of_tuple::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: maurer::Language<
            SOUND_PROOFS_REPETITIONS,
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
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDHWitness,
        >,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
{
    pub fn new(
        masks_and_encrypted_masked_key_share: Vec<
            enhanced_maurer::StatementSpaceGroupElement<
                SOUND_PROOFS_REPETITIONS,
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
        masks_and_encrypted_masked_key_share_proof: encryption_of_tuple::Proof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDHWitness,
            ProtocolContext,
        >,
        encrypted_nonce_shares_and_public_shares: Vec<
            enhanced_maurer::StatementSpaceGroupElement<
                SOUND_PROOFS_REPETITIONS,
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
        encrypted_nonce_shares_and_public_shares_proof: encryption_of_discrete_log::Proof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            ProtocolContext,
        >,
    ) -> Result<Self> {
        if masks_and_encrypted_masked_key_share.len()
            != encrypted_nonce_shares_and_public_shares.len()
        {
            return Err(Error::InvalidParameters);
        }

        // = ct_1
        // = AHE.Enc(γ)
        let encrypted_masks: Vec<_> = masks_and_encrypted_masked_key_share
            .iter()
            .map(|mask_and_encrypted_masked_key_share| {
                mask_and_encrypted_masked_key_share
                    .language_statement()
                    .encrypted_multiplicand()
                    .value()
            })
            .collect();

        // = ct_2
        // = AHE.Enc(γ) * ct_key
        // = AHE.Enc(γ * x_B)
        let encrypted_masked_key_shares: Vec<_> = masks_and_encrypted_masked_key_share
            .iter()
            .map(|mask_and_encrypted_masked_key_share| {
                mask_and_encrypted_masked_key_share
                    .language_statement()
                    .encrypted_product()
                    .value()
            })
            .collect();

        // commitments for range proof on γ
        let key_share_masking_range_proof_commitments: Vec<_> =
            masks_and_encrypted_masked_key_share
                .iter()
                .map(|mask_and_encrypted_masked_key_share| {
                    mask_and_encrypted_masked_key_share
                        .range_proof_commitment()
                        .value()
                })
                .collect();

        // = ct_3
        // = AHE.Enc(k)
        let encrypted_nonces: Vec<_> = encrypted_nonce_shares_and_public_shares
            .iter()
            .map(|nonce_share_encryption_and_public_share| {
                nonce_share_encryption_and_public_share
                    .language_statement()
                    .encrypted_discrete_log()
                    .value()
            })
            .collect();

        // = R_B
        let nonce_public_shares: Vec<_> = encrypted_nonce_shares_and_public_shares
            .iter()
            .map(|nonce_share_encryption_and_public_share| {
                nonce_share_encryption_and_public_share
                    .language_statement()
                    .base_by_discrete_log()
                    .value()
            })
            .collect();

        // commitments to the range proof of k
        let nonce_sharing_range_proof_commitments: Vec<_> =
            encrypted_nonce_shares_and_public_shares
                .iter()
                .map(|nonce_share_encryption_and_public_share| {
                    nonce_share_encryption_and_public_share
                        .range_proof_commitment()
                        .value()
                })
                .collect();

        Ok(Self {
            encrypted_masks,
            encrypted_masked_key_shares,
            key_share_masking_range_proof_commitments,
            masks_and_encrypted_masked_key_share_proof,
            encrypted_nonces,
            nonce_public_shares,
            nonce_sharing_range_proof_commitments,
            encrypted_nonce_shares_and_public_shares_proof,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presign<GroupElementValue, CiphertextValue> {
    pub(crate) centralized_party_nonce_share_commitment: GroupElementValue, // K_A
    pub(crate) nonce_public_share: GroupElementValue,                       // R_B
    pub(crate) encrypted_mask: CiphertextValue,                             // \ct_1
    pub(crate) encrypted_masked_key_share: CiphertextValue,                 // \ct_2
    pub(crate) encrypted_masked_nonce_share: CiphertextValue,               // \ct_4
}

impl<
        GroupElementValue: Clone,
        CiphertextValue: Clone + PartialEq + Serialize + for<'a> Deserialize<'a>,
    > Presign<GroupElementValue, CiphertextValue>
{
    pub fn new<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        parties: HashSet<PartyID>,
        centralized_party_nonce_share_commitment: GroupElement,
        mask_and_encrypted_masked_key_share: encryption_of_tuple::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            EncryptionKey,
        >,
        individual_encrypted_nonce_share_and_public_share: HashMap<
            PartyID,
            group::Value<
                encryption_of_discrete_log::StatementSpaceGroupElement<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
            >,
        >,
        encrypted_nonce_share_and_public_share: encryption_of_discrete_log::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >,
        individual_encrypted_masked_nonce_share: HashMap<
            PartyID,
            group::Value<
                encryption_of_tuple::StatementSpaceGroupElement<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    EncryptionKey,
                >,
            >,
        >,
        encrypted_masked_nonce_share: encryption_of_tuple::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            EncryptionKey,
        >,
    ) -> Result<Self>
    where
        GroupElement:
            group::GroupElement<Value = GroupElementValue> + PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey::CiphertextSpaceGroupElement: group::GroupElement<Value = CiphertextValue>,
    {
        // = ct_1
        let encrypted_mask = mask_and_encrypted_masked_key_share
            .encrypted_multiplicand()
            .value();

        // = ct_2
        let encrypted_masked_key_share = mask_and_encrypted_masked_key_share
            .encrypted_product()
            .value();

        // = R_B
        let nonce_public_share = encrypted_nonce_share_and_public_share
            .base_by_discrete_log()
            .value();

        if encrypted_nonce_share_and_public_share.encrypted_discrete_log()
            != encrypted_masked_nonce_share.encrypted_multiplicand()
        {
            let mut malicious_parties: Vec<_> = parties
                .into_iter()
                .map(|party_id| {
                    individual_encrypted_nonce_share_and_public_share
                        .get(&party_id)
                        .map(|x| {
                            let (encrypted_discrete_log, _) = x.into();

                            encrypted_discrete_log.clone()
                        })
                        .zip(
                            individual_encrypted_masked_nonce_share
                                .get(&party_id)
                                .map(|x| {
                                    let value: [_; 2] = x.clone().into();

                                    value[0].clone()
                                }),
                        )
                        .map(
                            |(
                                first_round_encrypted_mask_share,
                                second_round_encrypted_mask_share,
                            )| {
                                (
                                    party_id,
                                    (
                                        first_round_encrypted_mask_share,
                                        second_round_encrypted_mask_share,
                                    ),
                                )
                            },
                        )
                        .ok_or(Error::InvalidParameters)
                })
                .collect::<Result<HashMap<_, _>>>()?
                .into_iter()
                .filter(
                    |(_, (first_round_encrypted_mask_share, second_round_encrypted_mask_share))| {
                        first_round_encrypted_mask_share != second_round_encrypted_mask_share
                    },
                )
                .map(|(party_id, _)| party_id)
                .collect();

            if malicious_parties.is_empty() {
                return Err(Error::InvalidParameters);
            }

            malicious_parties.sort();

            return Err(Error::MismatchingEncrypedMasks(malicious_parties));
        }

        let encrypted_masked_nonce_share = encrypted_masked_nonce_share.encrypted_product().value();

        Ok(Presign {
            centralized_party_nonce_share_commitment: centralized_party_nonce_share_commitment
                .value(),                   // = K_A
            nonce_public_share,             // = R_B            
            encrypted_mask,                 // = ct_1 = AHE.Enc(γ)
            encrypted_masked_key_share,     // = ct_2 = AHE.Enc(γ * x_B)
            encrypted_masked_nonce_share,   // = ct_4 = AHE.Enc(k * γ * x_B)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_batch<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >(
        parties: HashSet<PartyID>,
        centralized_party_nonce_shares_commitments_and_batched_proof:
            SignatureNonceSharesCommitmentsAndBatchedProof<SCALAR_LIMBS, GroupElement::Value, maurer::Proof<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_decommitment::Language<
                SOUND_PROOFS_REPETITIONS,
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >,
        ProtocolContext,
        >,>,
        masks_and_encrypted_masked_key_share: Vec<
            encryption_of_tuple::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                EncryptionKey,
            >,
        >,
        individual_encrypted_nonce_shares_and_public_shares: HashMap<
            PartyID,
            Vec<
                group::Value<
                    encryption_of_discrete_log::StatementSpaceGroupElement<
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        SCALAR_LIMBS,
                        GroupElement,
                        EncryptionKey,
                    >,
                >,
            >,
        >,
        encrypted_nonce_shares_and_public_shares: Vec<
            encryption_of_discrete_log::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >,
        individual_encrypted_masked_nonce_shares: HashMap<
            PartyID,
            Vec<
                group::Value<
                    encryption_of_tuple::StatementSpaceGroupElement<
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        SCALAR_LIMBS,
                        EncryptionKey,
                    >,
                >,
            >,
        >,
        encrypted_masked_nonce_shares: Vec<
            encryption_of_tuple::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                EncryptionKey,
            >,
        >,
        group_public_parameters: &GroupElement::PublicParameters,
    ) -> Result<Vec<Self>>
    where
        GroupElement:
            group::GroupElement<Value = GroupElementValue> + PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey::CiphertextSpaceGroupElement: group::GroupElement<Value = CiphertextValue>,
    {
        let batch_size = centralized_party_nonce_shares_commitments_and_batched_proof
            .commitments
            .len();

        if individual_encrypted_nonce_shares_and_public_shares
            .iter()
            .any(|(_, v)| v.len() != batch_size)
            || individual_encrypted_masked_nonce_shares
                .iter()
                .any(|(_, v)| v.len() != batch_size)
            || masks_and_encrypted_masked_key_share.len() != batch_size
            || encrypted_nonce_shares_and_public_shares.len() != batch_size
            || encrypted_masked_nonce_shares.len() != batch_size
        {
            return Err(Error::InvalidParameters);
        }

        let centralized_party_nonce_shares_commitments =
            centralized_party_nonce_shares_commitments_and_batched_proof
                .commitments
                .into_iter()
                .map(|value| GroupElement::new(value, group_public_parameters))
                .collect::<group::Result<Vec<_>>>()?;

        // safe to access vector indices as we've checked the lengths.
        (0..batch_size).map(|i|
            Self::new::<
                SCALAR_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >(
                parties.clone(),
                centralized_party_nonce_shares_commitments[i].clone(),
                masks_and_encrypted_masked_key_share[i].clone(),
                individual_encrypted_nonce_shares_and_public_shares.iter().map(|(party_id, statements)| (*party_id, statements[i].clone())).collect(),
                encrypted_nonce_shares_and_public_shares[i].clone(),
                individual_encrypted_masked_nonce_shares.iter().map(|(party_id, statements)| (*party_id, statements[i].clone())).collect(),
                encrypted_masked_nonce_shares[i].clone(),
            )
        ).collect()
    }
}
