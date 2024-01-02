// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe,
    ahe::GroupsPublicParametersAccessors,
    commitments,
    commitments::{GroupsPublicParametersAccessors as _, Pedersen},
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, GroupElement as _,
        PrimeGroupElement, Samplable,
    },
    presign::{
        centralized_party::commitment_round::SignatureNonceSharesCommitmentsAndBatchedProof,
        decentralized_party::encrypted_masked_nonces_round,
    },
    proofs,
    proofs::{
        range, schnorr,
        schnorr::{
            encryption_of_discrete_log, encryption_of_tuple,
            enhanced::{EnhanceableLanguage, EnhancedLanguage, EnhancedPublicParameters},
            knowledge_of_decommitment,
        },
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
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    UnboundedEncDHWitness: group::GroupElement + Samplable,
    RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub party_id: PartyID,
    pub threshold: PartyID,
    pub number_of_parties: PartyID,
    // TODO: should we get this like that?
    pub protocol_context: ProtocolContext,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub commitment_scheme_public_parameters: commitments::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    pub unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    pub unbounded_encdh_witness_public_parameters: UnboundedEncDHWitness::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    // TODO: why do we need all the following? think we can delete them.
    pub public_key_share: GroupElement,
    pub public_key: GroupElement,
    pub encrypted_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub centralized_party_public_key_share: GroupElement,
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
    pub fn sample_mask_and_nonce_shares_and_initialize_proof_aggregation(
        self,
        centralized_party_nonce_shares_commitments_and_batched_proof: SignatureNonceSharesCommitmentsAndBatchedProof<
            SCALAR_LIMBS,
            GroupElement,
            ProtocolContext,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        (
            range::CommitmentRoundParty<
                { encryption_of_tuple::REPETITIONS },
                RANGE_CLAIMS_PER_SCALAR,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                UnboundedEncDHWitness,
                RangeProof,
                encryption_of_tuple::Language<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
                ProtocolContext,
            >,
            range::CommitmentRoundParty<
                { encryption_of_discrete_log::REPETITIONS },
                RANGE_CLAIMS_PER_SCALAR,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                UnboundedEncDLWitness,
                RangeProof,
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
            UnboundedEncDHWitness,
            RangeProof,
            ProtocolContext,
        >,
    )> {
        let batch_size = centralized_party_nonce_shares_commitments_and_batched_proof
            .commitments
            .len();

        let language_public_parameters = knowledge_of_decommitment::PublicParameters::new::<
            { knowledge_of_decommitment::ZERO_KNOWLEDGE_REPETITIONS },
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >(self.commitment_scheme_public_parameters.clone());

        centralized_party_nonce_shares_commitments_and_batched_proof
            .proof
            .verify(
                None,
                &self.protocol_context,
                &language_public_parameters,
                centralized_party_nonce_shares_commitments_and_batched_proof.commitments,
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
            &self
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            batch_size,
            rng,
        )?;

        let masked_key_share_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                &self
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                batch_size,
                rng,
            )?;

        let language_public_parameters =
            encryption_of_tuple::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.encryption_scheme_public_parameters.clone(),
                self.encrypted_secret_key_share.value(),
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

        // TODO: maybe make this a named function in Accessors?
        let witnesses = mask_shares_witnesses
            .clone()
            .into_iter()
            .zip(
                masks_encryption_randomness
                    .clone()
                    .into_iter()
                    .zip(masked_key_share_encryption_randomness.clone().into_iter()),
            )
            .map(
                |(
                    mask,
                    (masks_encryption_randomness, masked_secret_key_share_encryption_randomness),
                )| {
                    (
                        mask,
                        masks_encryption_randomness,
                        masked_secret_key_share_encryption_randomness,
                    )
                        .into()
                },
            )
            .collect();

        let witnesses = EnhancedLanguage::<
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
        >::generate_witnesses(witnesses, &language_public_parameters, rng)?;

        let key_share_masking_commitment_round_party = RangeProof::new_enhanced_session::<
            { encryption_of_tuple::REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            UnboundedEncDHWitness,
            encryption_of_tuple::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
            ProtocolContext,
        >(
            self.party_id,
            self.threshold,
            self.number_of_parties,
            language_public_parameters,
            self.protocol_context.clone(),
            witnesses,
        );

        let shares_of_signature_nonce_shares = GroupElement::Scalar::sample_batch(
            &self.scalar_group_public_parameters,
            batch_size,
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
            );

        let language_public_parameters = EnhancedPublicParameters::<
            { encryption_of_discrete_log::REPETITIONS },
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
        );

        let witnesses: Vec<_> = shares_of_signature_nonce_shares_witnesses
            .clone()
            .into_iter()
            .zip(
                shares_of_signature_nonce_shares_encryption_randomness
                    .clone()
                    .into_iter(),
            )
            .map(|(nonce_share, encryption_randomness)| (nonce_share, encryption_randomness).into())
            .collect();

        let witnesses = EnhancedLanguage::<
            { encryption_of_discrete_log::REPETITIONS },
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

        // TODO: name?
        let nonce_sharing_commitment_round_party = RangeProof::new_enhanced_session::<
            { encryption_of_discrete_log::REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            UnboundedEncDLWitness,
            encryption_of_discrete_log::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
            ProtocolContext,
        >(
            self.party_id,
            self.threshold,
            self.number_of_parties,
            language_public_parameters,
            self.protocol_context.clone(),
            witnesses,
        );

        let party = encrypted_masked_nonces_round::Party {
            party_id: self.party_id,
            threshold: self.threshold,
            number_of_parties: self.number_of_parties,
            protocol_context: self.protocol_context,
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            commitment_scheme_public_parameters: self.commitment_scheme_public_parameters,
            unbounded_encdh_witness_public_parameters: self
                .unbounded_encdh_witness_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            public_key_share: self.public_key_share,
            public_key: self.public_key,
            encrypted_secret_key_share: self.encrypted_secret_key_share,
            centralized_party_public_key_share: self.centralized_party_public_key_share,
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
}
