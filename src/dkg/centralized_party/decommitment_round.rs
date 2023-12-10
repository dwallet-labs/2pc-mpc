// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    ahe::GroupsPublicParametersAccessors as _,
    commitments::GroupsPublicParametersAccessors as _,
    dkg::{
        decentralized_party,
        decentralized_party::proof_aggregation_round::SecretKeyShareEncryptionAndProof,
    },
    group,
    group::{GroupElement as _, PrimeGroupElement},
    proofs,
    proofs::{
        range,
        range::CommitmentPublicParametersAccessor as _,
        schnorr::{encryption_of_discrete_log, knowledge_of_discrete_log, language::enhanced},
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
    pub encryption_of_decentralized_party_secret_key_share:
        EncryptionKey::CiphertextSpaceGroupElement,
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
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: proofs::RangeProof<RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_LIMBS>,
    ProtocolContext: Clone + Serialize,
> where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    group::ScalarValue<SCALAR_LIMBS, GroupElement>: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
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
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIM_LIMBS,
        >,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    group::ScalarValue<SCALAR_LIMBS, GroupElement>: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    pub fn decommit_proof_public_key_share(
        self,
        decentralized_party_secret_key_share_encryption_and_proof: decentralized_party::SecretKeyShareEncryptionAndProof<
            range::CommitmentSchemeCommitmentSpaceValue<
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                RangeProof,
            >,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            encryption_of_discrete_log::Proof<
                SCALAR_LIMBS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
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
        let range_proof_commitment = range::CommitmentSchemeCommitmentSpaceGroupElement::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >::new(
            decentralized_party_secret_key_share_encryption_and_proof.range_proof_commitment,
            &self
                .range_proof_public_parameters
                .commitment_public_parameters()
                .commitment_space_public_parameters(),
        )?;

        let encryption_of_decentralized_party_secret_key_share =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                decentralized_party_secret_key_share_encryption_and_proof
                    .encryption_of_secret_key_share,
                &self
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        let decentralized_party_public_key_share = GroupElement::new(
            decentralized_party_secret_key_share_encryption_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        let statement = (
            range_proof_commitment,
            (
                encryption_of_decentralized_party_secret_key_share.clone(),
                decentralized_party_public_key_share.clone(),
            )
                .into(),
        )
            .into();

        let encryption_of_discrete_log_language_public_parameters =
            encryption_of_discrete_log::LanguagePublicParameters::<
                SCALAR_LIMBS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
            >::new::<
                SCALAR_LIMBS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIM_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
            >(
                self.scalar_group_public_parameters,
                self.group_public_parameters,
                self.range_proof_public_parameters.clone(),
                self.encryption_scheme_public_parameters,
            );

        decentralized_party_secret_key_share_encryption_and_proof
            .encryption_of_secret_key_share_proof
            .verify(
                // TODO: there actually are `n` parties, but we don't know how many, so what to do
                // here?
                None,
                &self.protocol_context,
                &encryption_of_discrete_log_language_public_parameters,
                &self.range_proof_public_parameters,
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
            encryption_of_decentralized_party_secret_key_share,
            decentralized_party_public_key_share,
        };

        Ok((public_key_share_decommitment_proof, output))
    }
}
