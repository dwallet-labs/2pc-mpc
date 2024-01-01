// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::rand_core::CryptoRngCore;
use serde::Serialize;

use crate::{
    ahe,
    ahe::GroupsPublicParametersAccessors as _,
    commitments::GroupsPublicParametersAccessors as _,
    group,
    group::{GroupElement as _, GroupElement, PrimeGroupElement, Samplable},
    presign::decentralized_party,
    proofs,
    proofs::{
        range,
        range::PublicParametersAccessors,
        schnorr,
        schnorr::{
            encryption_of_discrete_log, encryption_of_tuple,
            enhanced::{EnhanceableLanguage, EnhancedPublicParameters},
        },
    },
    AdditivelyHomomorphicEncryptionKey,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    UnboundedEncDHWitness: group::GroupElement + Samplable,
    RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    // TODO: should we get this like that? is it the same for both the centralized & decentralized
    // party (and all their parties?)
    pub(super) protocol_context: ProtocolContext,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(super) unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    pub(super) unbounded_encdh_witness_public_parameters: UnboundedEncDHWitness::PublicParameters,
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub(super) signature_nonce_shares_and_commitment_randomnesses:
        Vec<(GroupElement::Scalar, GroupElement::Scalar)>,
    pub(super) encrypted_decentralized_party_secret_key_share:
        EncryptionKey::CiphertextSpaceGroupElement,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
        RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        UnboundedEncDLWitness,
        UnboundedEncDHWitness,
        RangeProof,
        ProtocolContext,
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
    pub fn verify_presign_output(
        self,
        presign_output: decentralized_party::Output<
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
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<()> {
        let encrypted_masks = presign_output
            .encrypted_masks
            .into_iter()
            .map(|encrypted_mask| {
                EncryptionKey::CiphertextSpaceGroupElement::new(
                    encrypted_mask,
                    &self
                        .encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let encrypted_masked_key_shares = presign_output
            .encrypted_masked_key_shares
            .into_iter()
            .map(|encrypted_masked_key_share| {
                EncryptionKey::CiphertextSpaceGroupElement::new(
                    encrypted_masked_key_share,
                    &self
                        .encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let key_share_masking_range_proof_commitments = presign_output
            .key_share_masking_range_proof_commitments
            .into_iter()
            .map(|key_share_masking_range_proof_commitment| {
                range::CommitmentSchemeCommitmentSpaceGroupElement::<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    RangeProof,
                >::new(
                    key_share_masking_range_proof_commitment,
                    &self
                        .range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .commitment_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let statements = encrypted_masks
            .into_iter()
            .zip(encrypted_masked_key_shares.into_iter())
            .zip(key_share_masking_range_proof_commitments.into_iter())
            .map(
                |(
                    (encrypted_mask, encrypted_masked_key_share),
                    key_share_masking_range_proof_commitment,
                )| {
                    (
                        key_share_masking_range_proof_commitment,
                        [encrypted_mask, encrypted_masked_key_share].into(),
                    )
                        .into()
                },
            )
            .collect();

        let language_public_parameters =
            encryption_of_tuple::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.encryption_scheme_public_parameters.clone(),
                self.encrypted_decentralized_party_secret_key_share.value(),
            );

        let language_public_parameters = EnhancedPublicParameters::<
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
        >::new::<
            RangeProof,
            UnboundedEncDHWitness,
            encryption_of_tuple::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >(
            self.unbounded_encdh_witness_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            language_public_parameters,
        );

        presign_output
            .masks_and_encrypted_masked_key_share_proof
            .verify(
                // TODO: there actually are `n` parties, but we don't know how many, so what to do
                // here?
                None,
                &self.protocol_context,
                &language_public_parameters,
                statements,
                rng,
            )?;

        // TODO: output anything here?
        todo!();
    }
}
