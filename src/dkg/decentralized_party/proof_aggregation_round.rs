// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crypto_bigint::{Encoding, Uint};
use serde::{Deserialize, Serialize};

use super::proof_share_round;
use crate::{
    dkg::decentralized_party::decommitment_proof_verification_round,
    group,
    group::{GroupElement as _, PrimeGroupElement},
    proofs,
    proofs::schnorr::{
        aggregation::decommitment_round::Decommitment,
        encryption_of_discrete_log, language,
        language::{enhanced, enhanced::EnhancedLanguageStatementAccessors as _},
    },
    AdditivelyHomomorphicEncryptionKey, Commitment, PartyID,
};

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct SecretKeyShareEncryptionAndProof<
    RangeProofCommitmentValue,
    GroupElementValue,
    CiphertextValue,
    EncDLProof,
> {
    pub(in crate::dkg) public_key_share: GroupElementValue,
    pub(in crate::dkg) range_proof_commitment: RangeProofCommitmentValue,
    pub(in crate::dkg) encryption_of_secret_key_share: CiphertextValue,
    pub(in crate::dkg) encryption_of_secret_key_share_proof: EncDLProof,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub(super) party_id: PartyID,
    pub(super) threshold: PartyID,
    pub(super) number_of_parties: PartyID,
    pub(super) protocol_context: ProtocolContext,
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub(super) commitment_to_centralized_party_secret_key_share: Commitment,
    pub(super) encryption_of_secret_share_proof_aggregation_round_party:
        encryption_of_discrete_log::ProofAggregationProofAggregationRoundParty<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
            ProtocolContext,
        >,
    pub(super) share_of_decentralized_party_secret_key_share: GroupElement::Scalar,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
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
        RangeProof,
        ProtocolContext,
    >
{
    pub fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<
            PartyID,
            encryption_of_discrete_log::ProofShare<
                SCALAR_LIMBS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
            >,
        >,
    ) -> crate::Result<(
        SecretKeyShareEncryptionAndProof<
            range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RangeProof,
            >,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            encryption_of_discrete_log::EnhancedProof<
                SCALAR_LIMBS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
                ProtocolContext,
            >,
        >,
        decommitment_proof_verification_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            ProtocolContext,
        >,
    )> {
        let (encryption_of_secret_key_share_proof, statements) = self
            .encryption_of_secret_share_proof_aggregation_round_party
            .aggregate_proof_shares(proof_shares)?;

        let statement = statements.first().ok_or(crate::Error::APIMismatch)?;

        let decentralized_party_secret_key_share_encryption_and_proof =
            SecretKeyShareEncryptionAndProof {
                public_key_share: (&statement.generator_by_discrete_log()).value(),
                range_proof_commitment: (statement.range_proof_commitment()).value(),
                encryption_of_secret_key_share: (&statement.encryption_of_discrete_log()).value(),
                encryption_of_secret_key_share_proof,
            };

        let centralized_party_decommitment_proof_verification_round_party =
            decommitment_proof_verification_round::Party::<
                SCALAR_LIMBS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
                ProtocolContext,
            > {
                party_id: self.party_id,
                threshold: self.threshold,
                number_of_parties: self.number_of_parties,
                protocol_context: self.protocol_context,
                group_public_parameters: self.group_public_parameters,
                scalar_group_public_parameters: self.scalar_group_public_parameters,
                commitment_to_centralized_party_secret_key_share: self
                    .commitment_to_centralized_party_secret_key_share,
                share_of_decentralized_party_secret_key_share: self
                    .share_of_decentralized_party_secret_key_share,
                public_key_share: statement.generator_by_discrete_log().clone(),
                encryption_of_secret_key_share: statement.encryption_of_discrete_log().clone(),
            };

        Ok((
            decentralized_party_secret_key_share_encryption_and_proof,
            centralized_party_decommitment_proof_verification_round_party,
        ))
    }
}
