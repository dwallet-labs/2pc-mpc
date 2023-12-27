// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe, commitments,
    commitments::GroupsPublicParametersAccessors as _,
    dkg::decentralized_party::decommitment_round,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, GroupElement as _,
        PrimeGroupElement, Samplable,
    },
    presign::decentralized_party::{
        nonce_masking_commitment_round, nonce_sharing_and_key_share_masking_decommitment_round,
    },
    proofs,
    proofs::schnorr::{
        encryption_of_discrete_log, encryption_of_tuple,
        knowledge_of_decommitment::LanguageCommitmentScheme,
        language::{enhanced, enhanced::ConstrainedWitnessGroupElement},
    },
    AdditivelyHomomorphicEncryptionKey, Commitment, PartyID,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_LIMBS>,
    CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, 1, GroupElement::Scalar, GroupElement>,
    ProtocolContext: Clone + Serialize,
> where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    group::ScalarValue<SCALAR_LIMBS, GroupElement>: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    pub(super) party_id: PartyID,
    pub(super) threshold: PartyID,
    pub(super) number_of_parties: PartyID,
    // TODO: should we get this like that?
    pub(super) protocol_context: ProtocolContext,
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(super) commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub(super) public_key_share: GroupElement,
    pub(super) public_key: GroupElement,
    pub(super) encryption_of_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub(super) centralized_party_public_key_share: GroupElement,
    pub(super) shares_of_signature_nonce_shares_witnesses:
        Vec<ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
    pub(super) shares_of_signature_nonce_shares_encryption_randomness:
        Vec<EncryptionKey::RandomnessSpaceGroupElement>,
    pub(super) nonce_sharing_proof_share_round_party:
        encryption_of_discrete_log::ProofAggregationProofShareRoundParty<
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
    pub(super) key_share_masking_proof_share_round_party:
        encryption_of_tuple::ProofAggregationProofShareRoundParty<
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
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_LIMBS>,
        CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, 1, GroupElement::Scalar, GroupElement>,
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
        CommitmentScheme,
        ProtocolContext,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    group::ScalarValue<SCALAR_LIMBS, GroupElement>: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    pub fn prove_nonce_sharing_and_secret_key_share_masking(
        self,
        nonce_sharing_decommitments: HashMap<
            PartyID,
            encryption_of_discrete_log::Decommitment<
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
        key_share_masking_decommitments: HashMap<
            PartyID,
            encryption_of_tuple::Decommitment<
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
        (
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
            encryption_of_tuple::ProofShare<
                SCALAR_LIMBS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
            >,
        ),
        nonce_masking_commitment_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            CommitmentScheme,
            ProtocolContext,
        >,
    )> {
        let (nonce_sharing_proof_share, nonce_sharing_proof_aggregation_round_party) = self
            .nonce_sharing_proof_share_round_party
            .generate_proof_share(nonce_sharing_decommitments)?;

        let (key_share_masking_proof_share, key_share_masking_proof_aggregation_round_party) = self
            .key_share_masking_proof_share_round_party
            .generate_proof_share(key_share_masking_decommitments)?;

        let party = nonce_masking_commitment_round::Party::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            CommitmentScheme,
            ProtocolContext,
        > {
            party_id: self.party_id,
            threshold: self.threshold,
            number_of_parties: self.number_of_parties,
            protocol_context: self.protocol_context,
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            commitment_scheme_public_parameters: self.commitment_scheme_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            public_key_share: self.public_key_share,
            public_key: self.public_key,
            encryption_of_secret_key_share: self.encryption_of_secret_key_share,
            centralized_party_public_key_share: self.centralized_party_public_key_share,
            shares_of_signature_nonce_shares_witnesses: self
                .shares_of_signature_nonce_shares_witnesses,
            shares_of_signature_nonce_shares_encryption_randomness: self
                .shares_of_signature_nonce_shares_encryption_randomness,
            nonce_sharing_proof_aggregation_round_party,
            key_share_masking_proof_aggregation_round_party,
        };

        Ok((
            (nonce_sharing_proof_share, key_share_masking_proof_share),
            party,
        ))
    }
}
