// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use commitment::Pedersen;
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use enhanced_maurer::{committed_linear_evaluation, EnhanceableLanguage};
use group::{GroupElement, PrimeGroupElement, Samplable};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use maurer::{
    committment_of_discrete_log, discrete_log_ratio_of_committed_values, SOUND_PROOFS_REPETITIONS,
};
use proof::AggregatableRangeProof;
use serde::Serialize;

use crate::{
    presign,
    sign::{
        centralized_party::PublicNonceEncryptedPartialSignatureAndProof,
        decentralized_party::identifiable_abort::signature_partial_decryption_verification_round,
        DIMENSION,
    },
    Error,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
> {
    pub(in crate::sign) decryption_key_share: DecryptionKeyShare,
    pub(in crate::sign) decryption_key_share_public_parameters:
        DecryptionKeyShare::PublicParameters,
    pub(in crate::sign) encrypted_partial_signature: EncryptionKey::CiphertextSpaceGroupElement,
    pub(in crate::sign) encrypted_masked_nonce_share: EncryptionKey::CiphertextSpaceGroupElement,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    > Party<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey, DecryptionKeyShare>
where
    Error: From<DecryptionKeyShare::Error>,
{
    pub fn prove_correct_signature_partial_decryption(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        DecryptionKeyShare::PartialDecryptionProof,
        signature_partial_decryption_verification_round::Party<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            DecryptionKeyShare,
        >,
    )> {
        let (_, proof) = Option::from(self.decryption_key_share.generate_decryption_shares(
            vec![
                self.encrypted_partial_signature.clone(),
                self.encrypted_masked_nonce_share.clone(),
            ],
            &self.decryption_key_share_public_parameters,
            rng,
        ))
        .ok_or(Error::InternalError)?;

        let signature_partial_decryption_verification_round_party =
            signature_partial_decryption_verification_round::Party {
                decryption_key_share_public_parameters: self.decryption_key_share_public_parameters,
                encrypted_partial_signature: self.encrypted_partial_signature,
                encrypted_masked_nonce_share: self.encrypted_masked_nonce_share,
            };

        Ok((proof, signature_partial_decryption_verification_round_party))
    }

    pub fn new<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
        ProtocolContext: Clone + Serialize,
    >(
        decryption_key_share: DecryptionKeyShare,
        decryption_key_share_public_parameters: DecryptionKeyShare::PublicParameters,
        presign: presign::decentralized_party::Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
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
            >>,
    ) -> crate::Result<Self> where
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
    {
        let encrypted_partial_signature = EncryptionKey::CiphertextSpaceGroupElement::new(
            public_nonce_encrypted_partial_signature_and_proof.encrypted_partial_signature,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        let encrypted_masked_nonce_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encrypted_masked_nonce_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        Ok(Self {
            decryption_key_share,
            decryption_key_share_public_parameters,
            encrypted_partial_signature,
            encrypted_masked_nonce_share,
        })
    }
}

// TODO: should we put the protocol context there [in IA]
