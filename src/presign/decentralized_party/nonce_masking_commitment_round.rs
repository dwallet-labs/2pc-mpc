// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use core::array;
use std::collections::HashMap;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe,
    ahe::GroupsPublicParametersAccessors,
    commitments,
    commitments::GroupsPublicParametersAccessors as _,
    dkg::decentralized_party::decommitment_round,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, GroupElement as _,
        PrimeGroupElement, Samplable,
    },
    presign::decentralized_party::{
        nonce_masking_decommitment_round, nonce_sharing_and_key_share_masking_decommitment_round,
    },
    proofs,
    proofs::{
        range,
        range::CommitmentPublicParametersAccessor as _,
        schnorr::{
            encryption_of_discrete_log, encryption_of_tuple,
            knowledge_of_decommitment::LanguageCommitmentScheme,
            language::{
                enhanced,
                enhanced::{ConstrainedWitnessGroupElement, EnhancedLanguageStatementAccessors},
            },
        },
    },
    AdditivelyHomomorphicEncryptionKey, Commitment, PartyID,
};

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
    CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
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
    pub(super) nonce_sharing_proof_aggregation_round_party:
        encryption_of_discrete_log::ProofAggregationProofAggregationRoundParty<
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
    pub(super) key_share_masking_proof_aggregation_round_party:
        encryption_of_tuple::ProofAggregationProofAggregationRoundParty<
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
        CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
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
        CommitmentScheme,
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
    pub fn commit_nonce_masking(
        self,
        nonce_sharing_proof_shares: HashMap<
            PartyID,
            encryption_of_discrete_log::ProofShare<
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
        >,
        key_share_masking_proof_shares: HashMap<
            PartyID,
            encryption_of_tuple::ProofShare<
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
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        Commitment,
        nonce_masking_decommitment_round::Party<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            CommitmentScheme,
            ProtocolContext,
        >,
    )> {
        let batch_size = nonce_sharing_proof_shares.len();

        let (nonce_sharing_proof, statements) = self
            .nonce_sharing_proof_aggregation_round_party
            .aggregate_proof_shares(nonce_sharing_proof_shares)?;

        // TODO: range proofs@!@!!@#! or, also, in aggregation, or seperately.

        // TODO: plurals all the code
        // TODO: in DKG also, don't use fully qualified names for locally owned variables, only for
        // foreign ones. TODO: name of R
        let (_, nonce_public_shares): (Vec<_>, Vec<_>) = statements
            .into_iter()
            .map(|statement| statement.remaining_statement().clone().into())
            .unzip();

        let (key_share_masking_proof, statements) = self
            .key_share_masking_proof_aggregation_round_party
            .aggregate_proof_shares(key_share_masking_proof_shares)?;

        let (masks_encryptions, masked_key_share_encryptions): (Vec<_>, Vec<_>) = statements
            .into_iter()
            .map(|statement| {
                let as_array: &[_; 2] = statement.remaining_statement().into();
                (as_array[0].clone(), as_array[1].clone())
            })
            .unzip();

        // TODO: we're not sampling new encryption randomness here for the encryption of the nonce
        // share, this is intended, just making sure.

        let masked_nonce_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                rng,
                &self
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                batch_size,
            )?;

        let nonce_masking_commitment_randomness = commitments::RandomnessSpaceGroupElement::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof::CommitmentScheme<RANGE_CLAIMS_PER_SCALAR>,
        >::sample_batch(
            rng,
            &self
                .range_proof_public_parameters
                .commitment_public_parameters()
                .randomness_space_public_parameters(),
            batch_size,
        )?;

        // TODO: maybe make this a named function in Accessors?
        let witnesses = self
            .shares_of_signature_nonce_shares_witnesses
            .into_iter()
            .zip(
                nonce_masking_commitment_randomness.clone().into_iter().zip(
                    self.shares_of_signature_nonce_shares_encryption_randomness
                        .into_iter()
                        .zip(masked_nonce_encryption_randomness.clone().into_iter()),
                ),
            )
            .map(
                |(
                    nonce,
                    (
                        commitment_randomness,
                        (nonces_encryption_randomness, masked_nonces_encryption_randomness),
                    ),
                )| {
                    (
                        nonce,
                        commitment_randomness,
                        [
                            nonces_encryption_randomness,
                            masked_nonces_encryption_randomness,
                        ]
                        .into(),
                    )
                        .into()
                },
            )
            .collect();

        let language_public_parameters = encryption_of_tuple::LanguagePublicParameters::<
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
            self.scalar_group_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            self.encryption_scheme_public_parameters.clone(),
            // TODO: actually, this needs to be a vector of ciphtertexts, for previous rounds they
            // are all the same, but here they are different
            todo!(),
        );

        let nonce_masking_commitment_round_party =
            encryption_of_tuple::ProofAggregationCommitmentRoundParty::<
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
            > {
                party_id: self.party_id,
                threshold: self.threshold,
                number_of_parties: self.number_of_parties,
                language_public_parameters,
                protocol_context: self.protocol_context.clone(),
                witnesses,
            };

        let (nonce_masking_commitment, nonce_masking_decommitment_round_party) =
            nonce_masking_commitment_round_party.commit_statements_and_statement_mask(rng)?;

        let party = nonce_masking_decommitment_round::Party::<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
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
            nonce_public_shares,
            masks_encryptions,
            masked_key_share_encryptions,
            nonce_sharing_proof,
            key_share_masking_proof,
            nonce_masking_decommitment_round_party,
        };

        Ok((nonce_masking_commitment, party))
    }
}
