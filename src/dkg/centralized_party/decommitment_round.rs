// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{
    dkg::decentralized_party,
    group,
    group::{GroupElement as _, PrimeGroupElement},
    proofs,
    proofs::{
        range,
        schnorr::{encryption_of_discrete_log, knowledge_of_discrete_log, language::enhanced},
    },
    AdditivelyHomomorphicEncryptionKey, ComputationalSecuritySizedNumber,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKeyShareDecommitmentAndProof<GroupElementValue, DLProof> {
    proof: DLProof,
    public_key_share: GroupElementValue,
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
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
    >,
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
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters,
    // TODO: should we get this like that? is it the same for both the centralized & decentralized
    // party (and all their parties?)
    pub(super) protocol_context: ProtocolContext,
    pub(super) encryption_of_discrete_log_language_public_parameters:
        encryption_of_discrete_log::LanguagePublicParameters<
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
        >,
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
            RANGE_CLAIMS_PER_SCALAR,
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
    ) -> crate::Result<
        PublicKeyShareDecommitmentAndProof<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        >,
    > {
        let range_proof_commitment = range::CommitmentSchemeCommitmentSpaceGroupElement::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            RangeProof,
        >::new(
            decentralized_party_secret_key_share_encryption_and_proof.range_proof_commitment,
            &self
                .range_proof_public_parameters
                .as_ref()
                .as_ref()
                .commitment_space_public_parameters,
        )?;

        let encryption_of_decentralized_party_secret_key_share =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                decentralized_party_secret_key_share_encryption_and_proof
                    .encryption_of_secret_key_share,
                &self
                    .encryption_scheme_public_parameters
                    .as_ref()
                    .ciphertext_space_public_parameters,
            )?;

        let decentralized_party_public_key_share = GroupElement::new(
            decentralized_party_secret_key_share_encryption_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        // TODO: have some verify function where you input those seperately
        let statement = (
            range_proof_commitment,
            (
                encryption_of_decentralized_party_secret_key_share,
                decentralized_party_public_key_share,
            )
                .into(),
        )
            .into();

        decentralized_party_secret_key_share_encryption_and_proof
            .encryption_of_secret_key_share_proof
            .verify(
                0,
                &self.protocol_context,
                &self.encryption_of_discrete_log_language_public_parameters,
                vec![statement],
            )?;

        let public_key_share_decommitment_proof = PublicKeyShareDecommitmentAndProof::<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        > {
            proof: self.knowledge_of_discrete_log_proof,
            public_key_share: self.public_key_share.value(),
        };

        Ok(public_key_share_decommitment_proof)
    }
}
