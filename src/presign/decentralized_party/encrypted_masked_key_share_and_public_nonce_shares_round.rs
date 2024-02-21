// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use std::collections::HashSet;

use commitment::{pedersen, Pedersen};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use enhanced_maurer::{
    encryption_of_discrete_log, encryption_of_tuple, language::composed_witness_upper_bound,
    EnhanceableLanguage, EnhancedLanguage, EnhancedPublicParameters,
};
use group::{GroupElement, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{knowledge_of_decommitment, SOUND_PROOFS_REPETITIONS};
use proof::AggregatableRangeProof;
use serde::Serialize;

use crate::{
    dkg,
    presign::{
        centralized_party::commitment_round::SignatureNonceSharesCommitmentsAndBatchedProof,
        decentralized_party::encrypted_masked_nonces_round,
    },
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    UnboundedEncDHWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
    pub(in crate::presign) party_id: PartyID,
    pub(in crate::presign) parties: HashSet<PartyID>,
    pub(in crate::presign) protocol_context: ProtocolContext,
    pub(in crate::presign) scalar_group_public_parameters:
        group::PublicParameters<GroupElement::Scalar>,
    pub(in crate::presign) group_public_parameters: GroupElement::PublicParameters,
    pub(in crate::presign) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(in crate::presign) unbounded_encdl_witness_public_parameters:
        UnboundedEncDLWitness::PublicParameters,
    pub(in crate::presign) unbounded_encdh_witness_public_parameters:
        UnboundedEncDHWitness::PublicParameters,
    pub(in crate::presign) range_proof_public_parameters:
        RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub(in crate::presign) encrypted_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
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
        UnboundedEncDLWitness,
        UnboundedEncDHWitness,
        ProtocolContext,
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
    pub fn sample_mask_and_nonce_shares_and_initialize_proof_aggregation(
        self,
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
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        (
            enhanced_maurer::aggregation::commitment_round::Party<
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
                ProtocolContext,
            >,
            enhanced_maurer::aggregation::commitment_round::Party<
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
                ProtocolContext,
            >,
        ),
        encrypted_masked_nonces_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDHWitness,
            ProtocolContext,
        >,
    )> {
        let batch_size = centralized_party_nonce_shares_commitments_and_batched_proof
            .commitments
            .len();

        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
            )?;

        let language_public_parameters = knowledge_of_decommitment::PublicParameters::new::<
            SOUND_PROOFS_REPETITIONS,
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >(commitment_scheme_public_parameters.clone());

        let centralized_party_nonce_shares_commitments =
            centralized_party_nonce_shares_commitments_and_batched_proof
                .commitments
                .into_iter()
                .map(|value| GroupElement::new(value, &self.group_public_parameters))
                .collect::<group::Result<Vec<_>>>()?;

        centralized_party_nonce_shares_commitments_and_batched_proof
            .proof
            .verify(
                &self.protocol_context,
                &language_public_parameters,
                centralized_party_nonce_shares_commitments.clone(),
            )?;

        let masks_shares = GroupElement::Scalar::sample_batch(
            &self.scalar_group_public_parameters,
            batch_size,
            rng,
        )?;

        let mask_shares_witnesses = masks_shares
            .clone()
            .into_iter()
            .map(|share_of_decentralized_party_signature_nonce_share| {
                let share_of_decentralized_party_signature_nonce_share_value: Uint<SCALAR_LIMBS> =
                    share_of_decentralized_party_signature_nonce_share.into();

                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
                        &share_of_decentralized_party_signature_nonce_share_value,
                    )
                    .into(),
                    self.encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let masks_encryption_randomness = EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
            self.encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            batch_size,
            rng,
        )?;

        let masked_key_share_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                self.encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                batch_size,
                rng,
            )?;

        let encrypted_secret_key_share_upper_bound = composed_witness_upper_bound::<
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >()?;

        let language_public_parameters = encryption_of_tuple::PublicParameters::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >::new::<SCALAR_LIMBS, GroupElement, EncryptionKey>(
            self.scalar_group_public_parameters.clone(),
            self.encryption_scheme_public_parameters.clone(),
            self.encrypted_secret_key_share.value(),
            encrypted_secret_key_share_upper_bound,
        );

        let language_public_parameters = EnhancedPublicParameters::<
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
        )?;

        let witnesses = mask_shares_witnesses
            .clone()
            .into_iter()
            .zip(
                masks_encryption_randomness
                    .clone()
                    .into_iter()
                    .zip(masked_key_share_encryption_randomness),
            )
            .map(
                |(
                    mask_share,
                    (
                        mask_share_encryption_randomness,
                        masked_secret_key_share_encryption_randomness,
                    ),
                )| {
                    (
                        mask_share,
                        mask_share_encryption_randomness,
                        masked_secret_key_share_encryption_randomness,
                    )
                        .into()
                },
            )
            .collect();

        let witnesses = EnhancedLanguage::<
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
        >::generate_witnesses(witnesses, &language_public_parameters, rng)?;

        let key_share_masking_commitment_round_party =
            enhanced_maurer::aggregation::commitment_round::Party::<
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
                ProtocolContext,
            >::new_session(
                self.party_id,
                self.parties.clone(),
                language_public_parameters,
                self.protocol_context.clone(),
                witnesses,
                rng,
            )?;

        let shares_of_signature_nonce_shares_witnesses = masks_shares
            .clone()
            .into_iter()
            .map(|share_of_signature_nonce_share| {
                let share_of_signature_nonce_share_value: Uint<SCALAR_LIMBS> =
                    share_of_signature_nonce_share.into();

                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
                        &share_of_signature_nonce_share_value,
                    )
                    .into(),
                    self.encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let shares_of_signature_nonce_shares_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                &self
                    .encryption_scheme_public_parameters
                    .as_ref()
                    .randomness_space_public_parameters,
                batch_size,
                rng,
            )?;

        let language_public_parameters =
            encryption_of_discrete_log::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                self.encryption_scheme_public_parameters.clone(),
                GroupElement::generator_value_from_public_parameters(&self.group_public_parameters),
            );

        let language_public_parameters = EnhancedPublicParameters::<
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
        >::new::<
            RangeProof,
            UnboundedEncDLWitness,
            encryption_of_discrete_log::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >(
            self.unbounded_encdl_witness_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            language_public_parameters,
        )?;

        let witnesses: Vec<_> = shares_of_signature_nonce_shares_witnesses
            .clone()
            .into_iter()
            .zip(shares_of_signature_nonce_shares_encryption_randomness.clone())
            .map(|(nonce_share, encryption_randomness)| (nonce_share, encryption_randomness).into())
            .collect();

        let witnesses = EnhancedLanguage::<
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
        >::generate_witnesses(witnesses, &language_public_parameters, rng)?;

        let nonce_sharing_commitment_round_party =
            enhanced_maurer::aggregation::commitment_round::Party::<
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
                ProtocolContext,
            >::new_session(
                self.party_id,
                self.parties.clone(),
                language_public_parameters,
                self.protocol_context.clone(),
                witnesses,
                rng,
            )?;

        let party = encrypted_masked_nonces_round::Party {
            party_id: self.party_id,
            parties: self.parties,
            protocol_context: self.protocol_context,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            unbounded_encdh_witness_public_parameters: self
                .unbounded_encdh_witness_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            shares_of_signature_nonce_shares_witnesses,
            shares_of_signature_nonce_shares_encryption_randomness,
        };

        Ok((
            (
                key_share_masking_commitment_round_party,
                nonce_sharing_commitment_round_party,
            ),
            party,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        party_id: PartyID,
        parties: HashSet<PartyID>,
        protocol_context: ProtocolContext,
        scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        group_public_parameters: GroupElement::PublicParameters,
        encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
        unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
        unbounded_encdh_witness_public_parameters: UnboundedEncDHWitness::PublicParameters,
        range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    ) -> crate::Result<Self> {
        let encrypted_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            dkg_output.encrypted_secret_key_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        Ok(Self {
            party_id,
            parties,
            protocol_context,
            scalar_group_public_parameters,
            group_public_parameters,
            encryption_scheme_public_parameters,
            unbounded_encdl_witness_public_parameters,
            unbounded_encdh_witness_public_parameters,
            range_proof_public_parameters,
            encrypted_secret_key_share,
        })
    }
}
