// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use commitment::{pedersen, GroupsPublicParametersAccessors as _, Pedersen};
use crypto_bigint::{rand_core::CryptoRngCore, CheckedMul, Encoding, Uint};
use enhanced_maurer::{
    committed_linear_evaluation, language::composed_witness_upper_bound, EnhanceableLanguage,
    EnhancedPublicParameters,
};
use group::{AffineXCoordinate, GroupElement, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use maurer::{
    committment_of_discrete_log, discrete_log_ratio_of_committed_values, SOUND_PROOFS_REPETITIONS,
};
use proof::{range::PublicParametersAccessors, AggregatableRangeProof};
use serde::Serialize;

use crate::{
    dkg, presign,
    sign::{
        centralized_party::PublicNonceEncryptedPartialSignatureAndProof,
        decentralized_party::signature_threhsold_decryption_round, DIMENSION,
    },
    Error,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const NUM_RANGE_CLAIMS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedDComEvalWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
    pub(in crate::sign) threshold: PartyID,
    pub(in crate::sign) decryption_key_share: DecryptionKeyShare,
    pub(in crate::sign) decryption_key_share_public_parameters:
        DecryptionKeyShare::PublicParameters,
    pub(in crate::sign) protocol_context: ProtocolContext,
    pub(in crate::sign) scalar_group_public_parameters:
        group::PublicParameters<GroupElement::Scalar>,
    pub(in crate::sign) group_public_parameters: GroupElement::PublicParameters,
    pub(in crate::sign) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(in crate::sign) unbounded_dcom_eval_witness_public_parameters:
        UnboundedDComEvalWitness::PublicParameters,
    pub(in crate::sign) range_proof_public_parameters:
        RangeProof::PublicParameters<NUM_RANGE_CLAIMS>,
    pub(in crate::sign) public_key: GroupElement,
    pub(in crate::sign) nonce_public_share: GroupElement,
    pub(in crate::sign) encrypted_mask: EncryptionKey::CiphertextSpaceGroupElement,
    pub(in crate::sign) encrypted_masked_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub(in crate::sign) encrypted_masked_nonce_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub(in crate::sign) centralized_party_public_key_share: GroupElement,
    pub(in crate::sign) centralized_party_nonce_share_commitment: GroupElement,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        DecryptionKeyShare,
        RangeProof,
        UnboundedDComEvalWitness,
        ProtocolContext,
    >
where
    committed_linear_evaluation::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >: maurer::Language<
            SOUND_PROOFS_REPETITIONS,
            WitnessSpaceGroupElement = committed_linear_evaluation::WitnessSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                DIMENSION,
                GroupElement,
                EncryptionKey,
            >,
            StatementSpaceGroupElement = committed_linear_evaluation::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                DIMENSION,
                GroupElement,
                EncryptionKey,
            >,
            PublicParameters = committed_linear_evaluation::PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                DIMENSION,
                GroupElement,
                EncryptionKey,
            >,
        > + EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedDComEvalWitness,
        >,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Error: From<DecryptionKeyShare::Error>,
{
    pub fn partially_decrypt_encrypted_signature_parts(
        self,
        message: GroupElement::Scalar,
        public_nonce_encrypted_partial_signature_and_proof: PublicNonceEncryptedPartialSignatureAndProof<
            GroupElement::Value,
            proof::range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >,
            homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
            maurer::Proof<
                SOUND_PROOFS_REPETITIONS,
                committment_of_discrete_log::Language<
                    SCALAR_LIMBS,
                    GroupElement::Scalar,
                    GroupElement,
                    Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
                >,
                ProtocolContext,
            >,
            maurer::Proof<
                SOUND_PROOFS_REPETITIONS,
                discrete_log_ratio_of_committed_values::Language<
                    SCALAR_LIMBS,
                    GroupElement::Scalar,
                    GroupElement,
                >,
                ProtocolContext,
            >,
            committed_linear_evaluation::Proof<
                NUM_RANGE_CLAIMS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                DIMENSION,
                GroupElement,
                EncryptionKey,
                RangeProof,
                UnboundedDComEvalWitness,
                ProtocolContext,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        (
            DecryptionKeyShare::DecryptionShare,
            DecryptionKeyShare::DecryptionShare,
        ),
        signature_threhsold_decryption_round::Party<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            DecryptionKeyShare,
        >,
    )> {
        // TODO: hash the message here

        let public_nonce = GroupElement::new(
            public_nonce_encrypted_partial_signature_and_proof.public_nonce,
            &self.group_public_parameters,
        )?; // $R$

        let nonce_x_coordinate = public_nonce.x(); // $r$

        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
            )?;

        let language_public_parameters = committment_of_discrete_log::PublicParameters::new::<
            SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >(
            self.scalar_group_public_parameters.clone(),
            self.group_public_parameters.clone(),
            commitment_scheme_public_parameters.clone(),
            public_nonce_encrypted_partial_signature_and_proof.public_nonce,
        );

        public_nonce_encrypted_partial_signature_and_proof
            .public_nonce_proof
            .verify(
                &self.protocol_context,
                &language_public_parameters,
                vec![[
                    self.centralized_party_nonce_share_commitment.clone(),
                    self.nonce_public_share,
                ]
                .into()],
            )?;

        let language_public_parameters =
            discrete_log_ratio_of_committed_values::PublicParameters::new::<
                SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
            >(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                commitment_scheme_public_parameters.clone(),
                self.centralized_party_public_key_share,
            );

        let nonce_share_by_key_share_commitment = GroupElement::new(
            public_nonce_encrypted_partial_signature_and_proof.nonce_share_by_key_share_commitment,
            &self.group_public_parameters,
        )?;

        public_nonce_encrypted_partial_signature_and_proof
            .nonce_share_by_key_share_proof
            .verify(
                &self.protocol_context,
                &language_public_parameters,
                vec![[
                    self.centralized_party_nonce_share_commitment.clone(),
                    nonce_share_by_key_share_commitment.clone(),
                ]
                .into()],
            )?;

        let encrypted_mask_upper_bound = composed_witness_upper_bound::<
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >()?;

        let encrypted_masked_key_share_upper_bound: Option<_> = composed_witness_upper_bound::<
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >()?
        .checked_mul(&encrypted_mask_upper_bound)
        .into();

        let ciphertexts_and_upper_bounds = [
            (self.encrypted_mask, encrypted_mask_upper_bound),
            (
                self.encrypted_masked_key_share,
                encrypted_masked_key_share_upper_bound.ok_or(Error::InvalidPublicParameters)?,
            ),
        ]
        .map(|(ct, upper_bound)| (ct.value(), upper_bound));

        let commitment_scheme_public_parameters = commitment_scheme_public_parameters.into();

        let language_public_parameters = committed_linear_evaluation::PublicParameters::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            DIMENSION,
            GroupElement,
            EncryptionKey,
        >::new::<SCALAR_LIMBS, GroupElement, EncryptionKey>(
            self.scalar_group_public_parameters.clone(),
            self.group_public_parameters.clone(),
            self.encryption_scheme_public_parameters.clone(),
            commitment_scheme_public_parameters,
            ciphertexts_and_upper_bounds,
        );

        let language_public_parameters = EnhancedPublicParameters::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedDComEvalWitness,
            committed_linear_evaluation::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                DIMENSION,
                GroupElement,
                EncryptionKey,
            >,
        >::new::<
            RangeProof,
            UnboundedDComEvalWitness,
            committed_linear_evaluation::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                DIMENSION,
                GroupElement,
                EncryptionKey,
            >,
        >(
            self.unbounded_dcom_eval_witness_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            language_public_parameters,
        )?;

        let encrypted_partial_signature = EncryptionKey::CiphertextSpaceGroupElement::new(
            public_nonce_encrypted_partial_signature_and_proof.encrypted_partial_signature,
            self.encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )?;

        let range_proof_commitment = proof::range::CommitmentSchemeCommitmentSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::new(
            public_nonce_encrypted_partial_signature_and_proof
                .encrypted_partial_signature_range_proof_commitment,
            self.range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .commitment_space_public_parameters(),
        )?;

        public_nonce_encrypted_partial_signature_and_proof
            .encrypted_partial_signature_proof
            .verify(
                &self.protocol_context,
                &language_public_parameters,
                vec![(
                    range_proof_commitment,
                    (
                        encrypted_partial_signature.clone(),
                        [
                            ((nonce_x_coordinate * nonce_share_by_key_share_commitment)
                                + (message * &self.centralized_party_nonce_share_commitment)),
                            (nonce_x_coordinate * &self.centralized_party_nonce_share_commitment),
                        ]
                        .into(),
                    )
                        .into(),
                )
                    .into()],
                rng,
            )?;

        // TODO: what am I suppose to do here in the case of failure in decryption?
        let partial_signature_decryption_share = Option::from(
            self.decryption_key_share
                .generate_decryption_share_semi_honest(
                    &encrypted_partial_signature,
                    &self.decryption_key_share_public_parameters,
                ),
        )
        .ok_or(Error::InternalError)?;

        let masked_nonce_decryption_share = Option::from(
            self.decryption_key_share
                .generate_decryption_share_semi_honest(
                    &self.encrypted_masked_nonce_share,
                    &self.decryption_key_share_public_parameters,
                ),
        )
        .ok_or(Error::InternalError)?;

        let signature_threhsold_decryption_round_party =
            signature_threhsold_decryption_round::Party {
                threshold: self.threshold,
                decryption_key_share_public_parameters: self.decryption_key_share_public_parameters,
                scalar_group_public_parameters: self.scalar_group_public_parameters,
                message,
                public_key: self.public_key,
                nonce_x_coordinate,
            };

        Ok((
            (
                partial_signature_decryption_share,
                masked_nonce_decryption_share,
            ),
            signature_threhsold_decryption_round_party,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        threshold: PartyID,
        decryption_key_share: DecryptionKeyShare,
        decryption_key_share_public_parameters: DecryptionKeyShare::PublicParameters,
        protocol_context: ProtocolContext,
        scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        group_public_parameters: GroupElement::PublicParameters,
        encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
        unbounded_dcom_eval_witness_public_parameters: UnboundedDComEvalWitness::PublicParameters,
        range_proof_public_parameters: RangeProof::PublicParameters<NUM_RANGE_CLAIMS>,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: presign::decentralized_party::Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    ) -> crate::Result<Self> {
        let public_key = GroupElement::new(dkg_output.public_key, &group_public_parameters)?;

        let centralized_party_public_key_share = GroupElement::new(
            dkg_output.centralized_party_public_key_share,
            &group_public_parameters,
        )?;

        let centralized_party_nonce_share_commitment = GroupElement::new(
            presign.centralized_party_nonce_share_commitment,
            &group_public_parameters,
        )?;

        let nonce_public_share =
            GroupElement::new(presign.nonce_public_share, &group_public_parameters)?;

        let encrypted_mask = EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encrypted_mask,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        let encrypted_masked_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encrypted_masked_key_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        let encrypted_masked_nonce_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encrypted_masked_nonce_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        Ok(Self {
            threshold,
            decryption_key_share,
            decryption_key_share_public_parameters,
            protocol_context,
            scalar_group_public_parameters,
            group_public_parameters,
            encryption_scheme_public_parameters,
            unbounded_dcom_eval_witness_public_parameters,
            range_proof_public_parameters,
            public_key,
            nonce_public_share,
            encrypted_mask,
            encrypted_masked_key_share,
            encrypted_masked_nonce_share,
            centralized_party_public_key_share,
            centralized_party_nonce_share_commitment,
        })
    }
}
