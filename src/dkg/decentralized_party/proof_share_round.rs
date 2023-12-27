// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use super::proof_share_round;
use crate::{
    dkg::decentralized_party::proof_aggregation_round,
    group,
    group::PrimeGroupElement,
    proofs,
    proofs::schnorr::{
        aggregation::decommitment_round::Decommitment, encryption_of_discrete_log,
        language::enhanced,
    },
    AdditivelyHomomorphicEncryptionKey, Commitment, PartyID,
};

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
    pub(super) encryption_of_secret_share_proof_share_round_party:
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
    pub fn generate_proof_share(
        self,
        decommitments: HashMap<
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
    ) -> crate::Result<(
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
        proof_aggregation_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            ProtocolContext,
        >,
    )> {
        let (proof_share, encryption_of_secret_share_proof_aggregation_round_party) = self
            .encryption_of_secret_share_proof_share_round_party
            .generate_proof_share(decommitments)?;

        let proof_aggregation_round_party = proof_aggregation_round::Party::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            ProtocolContext,
        > {
            party_id: self.party_id,
            threshold: self.threshold,
            number_of_parties: self.number_of_parties,
            protocol_context: self.protocol_context,
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            commitment_to_centralized_party_secret_key_share: self
                .commitment_to_centralized_party_secret_key_share,
            encryption_of_secret_share_proof_aggregation_round_party,
            share_of_decentralized_party_secret_key_share: self
                .share_of_decentralized_party_secret_key_share,
        };

        Ok((proof_share, proof_aggregation_round_party))
    }
}
