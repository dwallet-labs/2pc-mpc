// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

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
    presign::{
        centralized_party::commitment_round::SignatureNonceSharesCommitmentsAndBatchedProof,
        decentralized_party::nonce_sharing_and_key_share_masking_decommitment_round,
    },
    proofs,
    proofs::schnorr::{
        encryption_of_discrete_log, encryption_of_tuple, knowledge_of_decommitment,
        knowledge_of_decommitment::LanguageCommitmentScheme,
        language::{enhanced, enhanced::DecomposableWitness},
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
    pub party_id: PartyID,
    pub threshold: PartyID,
    pub number_of_parties: PartyID,
    // TODO: should we get this like that?
    pub protocol_context: ProtocolContext,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub public_key_share: GroupElement,
    pub public_key: GroupElement,
    pub encryption_of_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub centralized_party_public_key_share: GroupElement,
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
    pub fn commit_nonce_sharing_and_secret_key_share_masking(
        self,
        centralized_party_nonce_shares_commitments_and_batched_proof: SignatureNonceSharesCommitmentsAndBatchedProof<
            SCALAR_LIMBS,
            GroupElement,
            CommitmentScheme,
            ProtocolContext,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        (Commitment, Commitment),
        nonce_sharing_and_key_share_masking_decommitment_round::Party<
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
        let batch_size = centralized_party_nonce_shares_commitments_and_batched_proof
            .commitments
            .len();

        // TODO: flip order of proofs to fit paper
        let language_public_parameters = knowledge_of_decommitment::PublicParameters::new::<
            { knowledge_of_decommitment::ZERO_KNOWLEDGE_REPETITIONS },
            SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            CommitmentScheme,
        >(
            self.scalar_group_public_parameters.clone(),
            self.group_public_parameters.clone(),
            self.commitment_scheme_public_parameters.clone(),
        );

        centralized_party_nonce_shares_commitments_and_batched_proof
            .proof
            .verify(
                None,
                &self.protocol_context,
                &language_public_parameters,
                centralized_party_nonce_shares_commitments_and_batched_proof.commitments,
            )?;

        let shares_of_signature_nonce_shares = GroupElement::Scalar::sample_batch(
            rng,
            &self.scalar_group_public_parameters,
            batch_size,
        )?;

        let shares_of_signature_nonce_shares_witnesses: Vec<_> = shares_of_signature_nonce_shares
            .clone()
            .into_iter()
            .map(|share_of_decentralized_party_signature_nonce_share| {
                share_of_decentralized_party_signature_nonce_share
                    .decompose_into_constrained_witness(RangeProof::RANGE_CLAIM_BITS)
            })
            .collect();

        let shares_of_signature_nonce_shares_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                rng,
                &self
                    .encryption_scheme_public_parameters
                    .as_ref()
                    .randomness_space_public_parameters,
                batch_size,
            )?;

        let nonce_sharing_commitment_randomness = commitments::RandomnessSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof::CommitmentScheme<RANGE_CLAIMS_PER_SCALAR>,
        >::sample_batch(
            rng,
            &self
                .range_proof_public_parameters
                .commitment_public_parameters()
                .randomness_space_public_parameters(),
            batch_size,
        )?;

        let witnesses: Vec<_> = shares_of_signature_nonce_shares_witnesses
            .clone()
            .into_iter()
            .zip(
                nonce_sharing_commitment_randomness.clone().into_iter().zip(
                    shares_of_signature_nonce_shares_encryption_randomness
                        .clone()
                        .into_iter(),
                ),
            )
            .map(
                |(nonce_share, (commitment_randomness, encryption_randomness))| {
                    (nonce_share, commitment_randomness, encryption_randomness).into()
                },
            )
            .collect();

        let language_public_parameters = encryption_of_discrete_log::LanguagePublicParameters::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >::new::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >(
            self.scalar_group_public_parameters.clone(),
            self.group_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            self.encryption_scheme_public_parameters.clone(),
        );

        let nonce_sharing_commitment_round_party =
            encryption_of_discrete_log::ProofAggregationCommitmentRoundParty::<
                SCALAR_LIMBS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
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

        let (nonce_sharing_commitment, nonce_sharing_decommitment_round_party) =
            nonce_sharing_commitment_round_party.commit_statements_and_statement_mask(rng)?;

        let masks_shares = GroupElement::Scalar::sample_batch(
            rng,
            &self.scalar_group_public_parameters,
            batch_size,
        )?;

        let mask_shares_witnesses: Vec<_> = masks_shares
            .clone()
            .into_iter()
            .map(|share_of_decentralized_party_signature_nonce_share| {
                share_of_decentralized_party_signature_nonce_share
                    .decompose_into_constrained_witness(RangeProof::RANGE_CLAIM_BITS)
            })
            .collect();

        let masks_encryption_randomness = EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
            rng,
            &self
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            batch_size,
        )?;

        let masked_key_share_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                rng,
                &self
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                batch_size,
            )?;

        let key_share_masking_commitment_randomness = commitments::RandomnessSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
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
        let witnesses = mask_shares_witnesses
            .clone()
            .into_iter()
            .zip(
                key_share_masking_commitment_randomness
                    .clone()
                    .into_iter()
                    .zip(
                        masks_encryption_randomness
                            .clone()
                            .into_iter()
                            .zip(masked_key_share_encryption_randomness.clone().into_iter()),
                    ),
            )
            .map(
                |(
                    mask,
                    (
                        commitment_randomness,
                        (
                            masks_encryption_randomness,
                            masked_secret_key_share_encryption_randomness,
                        ),
                    ),
                )| {
                    (
                        mask,
                        commitment_randomness,
                        [
                            masks_encryption_randomness,
                            masked_secret_key_share_encryption_randomness,
                        ]
                        .into(),
                    )
                        .into()
                },
            )
            .collect();

        let language_public_parameters = encryption_of_tuple::LanguagePublicParameters::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >::new::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >(
            self.scalar_group_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            self.encryption_scheme_public_parameters.clone(),
            self.encryption_of_secret_key_share.value(),
        );

        let key_share_masking_commitment_round_party =
            encryption_of_tuple::ProofAggregationCommitmentRoundParty::<
                SCALAR_LIMBS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
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

        let (key_share_masking_commitment, key_share_masking_decommitment_round_party) =
            key_share_masking_commitment_round_party.commit_statements_and_statement_mask(rng)?;

        let party = nonce_sharing_and_key_share_masking_decommitment_round::Party::<
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
            shares_of_signature_nonce_shares_witnesses,
            shares_of_signature_nonce_shares_encryption_randomness,
            nonce_sharing_decommitment_round_party,
            key_share_masking_decommitment_round_party,
        };

        Ok((
            (nonce_sharing_commitment, key_share_masking_commitment),
            party,
        ))
    }
}
