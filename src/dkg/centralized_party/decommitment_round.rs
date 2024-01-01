// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    ahe::GroupsPublicParametersAccessors as _,
    commitments::GroupsPublicParametersAccessors as _,
    dkg::decentralized_party,
    group,
    group::{direct_product, GroupElement as _, PrimeGroupElement, Samplable},
    proofs,
    proofs::{
        range,
        range::PublicParametersAccessors,
        schnorr,
        schnorr::{
            encryption_of_discrete_log, enhanced,
            enhanced::{EnhanceableLanguage, EnhancedPublicParameters},
            knowledge_of_discrete_log, language,
        },
    },
    AdditivelyHomomorphicEncryptionKey, ComputationalSecuritySizedNumber,
};

#[derive(Clone)]
pub struct Output<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> {
    pub secret_key_share: GroupElement::Scalar,
    pub public_key_share: GroupElement,
    pub public_key: GroupElement,
    pub encrypted_decentralized_party_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub decentralized_party_public_key_share: GroupElement,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKeyShareDecommitmentAndProof<GroupElementValue, DLProof> {
    pub(in crate::dkg) proof: DLProof,
    pub(in crate::dkg) public_key_share: GroupElementValue,
    pub(in crate::dkg) commitment_randomness: ComputationalSecuritySizedNumber,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(super) unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    // TODO: should we get this like that? is it the same for both the centralized & decentralized
    // party (and all their parties?)
    pub(super) protocol_context: ProtocolContext,
    pub(super) secret_key_share: GroupElement::Scalar,
    pub(super) public_key_share: GroupElement,
    pub(super) knowledge_of_discrete_log_proof:
        knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
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
{
    pub fn decommit_proof_public_key_share(
        self,
        decentralized_party_secret_key_share_encryption_and_proof: decentralized_party::SecretKeyShareEncryptionAndProof<
            GroupElement::Value,
            range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RangeProof,
            >,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
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
    ) -> crate::Result<(
        PublicKeyShareDecommitmentAndProof<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        >,
        Output<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>,
    )> {
        let encrypted_decentralized_party_secret_key_share =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                decentralized_party_secret_key_share_encryption_and_proof
                    .encrypted_secret_key_share,
                &self
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        let decentralized_party_public_key_share = GroupElement::new(
            decentralized_party_secret_key_share_encryption_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        let range_proof_commitment = range::CommitmentSchemeCommitmentSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RangeProof,
        >::new(
            decentralized_party_secret_key_share_encryption_and_proof.range_proof_commitment,
            &self
                .range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .commitment_space_public_parameters(),
        )?;

        let statement = (
            range_proof_commitment,
            (
                encrypted_decentralized_party_secret_key_share.clone(),
                decentralized_party_public_key_share.clone(),
            )
                .into(),
        )
            .into();

        let encryption_of_discrete_log_language_public_parameters =
            encryption_of_discrete_log::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                self.encryption_scheme_public_parameters,
            );

        let encryption_of_discrete_log_enhanced_language_public_parameters =
            enhanced::PublicParameters::new::<
                RangeProof,
                UnboundedEncDLWitness,
                encryption_of_discrete_log::Language<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
            >(
                self.unbounded_encdl_witness_public_parameters,
                self.range_proof_public_parameters.clone(),
                encryption_of_discrete_log_language_public_parameters,
            );

        decentralized_party_secret_key_share_encryption_and_proof
            .encryption_of_secret_key_share_proof
            .verify(
                // TODO: there actually are `n` parties, but we don't know how many, so what to do
                // here?
                None,
                &self.protocol_context,
                &encryption_of_discrete_log_enhanced_language_public_parameters,
                vec![statement],
                rng,
            )?;

        let public_key_share_decommitment_proof = PublicKeyShareDecommitmentAndProof::<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        > {
            proof: self.knowledge_of_discrete_log_proof,
            public_key_share: self.public_key_share.value(),
            commitment_randomness: self.commitment_randomness,
        };

        let public_key = self.public_key_share.clone() + &decentralized_party_public_key_share;

        let output = Output {
            secret_key_share: self.secret_key_share,
            public_key_share: self.public_key_share,
            public_key,
            encrypted_decentralized_party_secret_key_share,
            decentralized_party_public_key_share,
        };

        Ok((public_key_share_decommitment_proof, output))
    }
}
