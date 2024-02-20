// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use commitment::{pedersen, GroupsPublicParametersAccessors as _, Pedersen};
use crypto_bigint::{rand_core::CryptoRngCore, CheckedMul, Encoding, NonZero, Uint};
use enhanced_maurer::{
    committed_linear_evaluation, language::composed_witness_upper_bound, EnhanceableLanguage,
    EnhancedPublicParameters,
};
use group::{
    AffineXCoordinate, GroupElement, Invert, KnownOrderGroupElement, PartyID, PrimeGroupElement,
    Reduce, Samplable,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use maurer::{
    committment_of_discrete_log, discrete_log_ratio_of_committed_values, SOUND_PROOFS_REPETITIONS,
};
use proof::{range::PublicParametersAccessors, AggregatableRangeProof};
use serde::Serialize;
use std::collections::HashMap;
use std::ops::Neg;

use super::DIMENSION;
use crate::{
    dkg, presign, sign::centralized_party::PublicNonceEncryptedPartialSignatureAndProof, Error,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const NUM_RANGE_CLAIMS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedDComEvalWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
    pub(super) decryption_key_share: DecryptionKeyShare,
    pub(super) decryption_key_share_public_parameters: DecryptionKeyShare::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(super) unbounded_dcom_eval_witness_public_parameters:
        UnboundedDComEvalWitness::PublicParameters,
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters<NUM_RANGE_CLAIMS>,
    pub(super) nonce_public_share: GroupElement,
    pub(super) encrypted_mask: EncryptionKey::CiphertextSpaceGroupElement,
    pub(super) encrypted_masked_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub(super) encrypted_masked_nonce_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub(super) centralized_party_public_key_share: GroupElement,
    pub(super) centralized_party_nonce_share_commitment: GroupElement,
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
        DecryptionKeyShare::DecryptionShare,
        DecryptionKeyShare::DecryptionShare,
    )> {
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

        Ok((
            partial_signature_decryption_share,
            masked_nonce_decryption_share,
        ))
    }

    // TODO: seperate to struct?
    pub fn decrypt_signature(
        lagrange_coefficients: HashMap<PartyID, DecryptionKeyShare::LagrangeCoefficient>,
        decryption_key_share_public_parameters: &DecryptionKeyShare::PublicParameters,
        scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        partial_signature_decryption_shares: HashMap<PartyID, DecryptionKeyShare::DecryptionShare>,
        masked_nonce_decryption_shares: HashMap<PartyID, DecryptionKeyShare::DecryptionShare>,
    ) -> crate::Result<GroupElement::Scalar> {
        let partial_signature: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            DecryptionKeyShare::combine_decryption_shares_semi_honest(
                partial_signature_decryption_shares,
                lagrange_coefficients.clone(),
                decryption_key_share_public_parameters,
            )?
            .into();

        let group_order =
            GroupElement::Scalar::order_from_public_parameters(&scalar_group_public_parameters);

        let group_order =
            Option::<_>::from(NonZero::new(group_order)).ok_or(Error::InternalError)?;

        let partial_signature = GroupElement::Scalar::new(
            partial_signature.reduce(&group_order).into(),
            &scalar_group_public_parameters,
        )?;

        let masked_nonce: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            DecryptionKeyShare::combine_decryption_shares_semi_honest(
                masked_nonce_decryption_shares,
                lagrange_coefficients,
                decryption_key_share_public_parameters,
            )?
            .into();

        let masked_nonce = GroupElement::Scalar::new(
            masked_nonce.reduce(&group_order).into(),
            &scalar_group_public_parameters,
        )?;

        let inverted_masked_nonce = masked_nonce.invert();

        if inverted_masked_nonce.is_none().into() {
            // TODO: in this case I should report invalid signature, and everyone should send their proven decrypted share.
            todo!();
        }

        // TODO: what is meant by this OUtput Ua if ...

        // TODO: add logic where the decryption fails?
        // TODO: add logic where the decryption succeeds but the signature is invalid; as honest
        // verifier I should wish to see proofs for everyone. As malicious verifier, other honest
        // verifiers should request to see proofs, and if all pass, blame me for wrong decryption.

        // TODO: get r too, verify the sig, don't output if fails? or have it externally?

        // TODO: have the signature verification party for both decentralized & centralized party?
        // if so, should I put the malicious detection logic in this party?

        // TODO: what about malleability?

        let signature_s = inverted_masked_nonce.unwrap() * partial_signature;
        let negated_signature_s = signature_s.neg();

        // Attend to malleability.
        let signature_s = if negated_signature_s.value() < signature_s.value() {
            negated_signature_s
        } else {
            signature_s
        };

        // TODO: verify signature

        Ok(signature_s)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
            decryption_key_share,
            decryption_key_share_public_parameters,
            protocol_context,
            scalar_group_public_parameters,
            group_public_parameters,
            encryption_scheme_public_parameters,
            unbounded_dcom_eval_witness_public_parameters,
            range_proof_public_parameters,
            nonce_public_share,
            encrypted_mask,
            encrypted_masked_key_share,
            encrypted_masked_nonce_share,
            centralized_party_public_key_share,
            centralized_party_nonce_share_commitment,
        })
    }

    // TODO: add verify signature function for advancing the party for all lazy parties.
}
