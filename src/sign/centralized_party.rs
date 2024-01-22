// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::{rand_core::CryptoRngCore, Random, Uint};
use serde::{Deserialize, Serialize};

use super::DIMENSION;
use crate::{
    homomorphic_encryption,
    homomorphic_encryption::GroupsPublicParametersAccessors,
    commitment,
    commitment::{pedersen, MultiPedersen, Pedersen},
    group,
    group::{self_product, AffineXCoordinate, GroupElement, Invert, PrimeGroupElement, Samplable},
    helpers::FlatMapResults,
    proofs,
    proofs::{
        range, schnorr,
        schnorr::{
            committed_linear_evaluation, committment_of_discrete_log,
            discrete_log_ratio_of_committed_values, enhanced,
            enhanced::{
                EnhanceableLanguage, EnhancedLanguage, EnhancedLanguageStatementAccessors as _,
            },
            language::{
                committed_linear_evaluation::StatementAccessors as _,
                discrete_log_ratio_of_committed_values::StatementAccessors as _,
            },
        },
    },
    sign::centralized_party::schnorr::enhanced::EnhancedPublicParameters,
    AdditivelyHomomorphicEncryptionKey, StatisticalSecuritySizedNumber,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicNonceEncryptedPartialSignatureAndProof<
    GroupElementValue,
    RangeProofCommitmentValue,
    CiphertextValue,
    DComDLProof,
    DComRatioProof,
    DComEvalProof,
> {
    pub(super) public_nonce: GroupElementValue,
    pub(super) public_nonce_proof: DComDLProof,
    pub(super) nonce_share_by_key_share_commitment: GroupElementValue,
    pub(super) nonce_share_by_key_share_proof: DComRatioProof,
    pub(super) first_coefficient_commitment: GroupElementValue,
    pub(super) second_coefficient_commitment: GroupElementValue,
    pub(super) encrypted_partial_signature: CiphertextValue,
    pub(super) encrypted_partial_signature_range_proof_commitment: RangeProofCommitmentValue,
    pub(super) encrypted_partial_signature_proof: DComEvalProof,
}

// TODO: consistent order of generics with other protocols.
#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    UnboundedDComEvalWitness: group::GroupElement + Samplable,
    RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub protocol_context: ProtocolContext,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub unbounded_dcom_eval_witness_public_parameters: UnboundedDComEvalWitness::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters<NUM_RANGE_CLAIMS>,
    pub secret_key_share: GroupElement::Scalar,
    pub public_key_share: GroupElement,
    pub nonce_share_commitment_randomness: GroupElement::Scalar,
    pub nonce_share: GroupElement::Scalar,
    pub decentralized_party_nonce_public_share: GroupElement,
    pub encrypted_mask: EncryptionKey::CiphertextSpaceGroupElement,
    pub encrypted_masked_key_share: EncryptionKey::CiphertextSpaceGroupElement,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
        RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        GroupElement,
        EncryptionKey,
        UnboundedDComEvalWitness,
        RangeProof,
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
    >: schnorr::Language<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedDComEvalWitness,
        >,
{
    pub fn evaluate_encrypted_partial_signature(
        self,
        message: GroupElement::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<
        PublicNonceEncryptedPartialSignatureAndProof<
            GroupElement::Value,
            range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >,
            homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
            schnorr::Proof<
                { schnorr::proof::SOUND_PROOFS_REPETITIONS },
                committment_of_discrete_log::Language<
                    SCALAR_LIMBS,
                    GroupElement::Scalar,
                    GroupElement,
                    Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
                >,
                ProtocolContext,
            >,
            schnorr::Proof<
                { schnorr::proof::SOUND_PROOFS_REPETITIONS },
                discrete_log_ratio_of_committed_values::Language<
                    SCALAR_LIMBS,
                    GroupElement::Scalar,
                    GroupElement,
                >,
                ProtocolContext,
            >,
            committed_linear_evaluation::EnhancedProof<
                NUM_RANGE_CLAIMS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                DIMENSION,
                GroupElement,
                EncryptionKey,
                UnboundedDComEvalWitness,
                RangeProof,
                ProtocolContext,
            >,
        >,
    > {
        let inverted_nonce_share = self.nonce_share.invert();

        if inverted_nonce_share.is_none().into() {
            // TODO: should we do rejection sampling to ensure this never happens, or are we ok with
            // just saying this is negligible?
            return Err(crate::Error::InternalError);
        }

        let inverted_nonce_share = inverted_nonce_share.unwrap();

        // TODO: name
        let public_nonce = inverted_nonce_share * self.decentralized_party_nonce_public_share; // $R$

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
            public_nonce.value(),
        );

        let (public_nonce_proof, _) = schnorr::Proof::<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
            committment_of_discrete_log::Language<
                SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
            >,
            ProtocolContext,
        >::prove(
            &self.protocol_context,
            &language_public_parameters,
            vec![[self.nonce_share, self.nonce_share_commitment_randomness].into()],
            rng,
        )?;

        let nonce_share_by_key_share_commitment_randomness =
            GroupElement::Scalar::sample(&self.scalar_group_public_parameters, rng)?;

        let language_public_parameters =
            discrete_log_ratio_of_committed_values::PublicParameters::new::<
                SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
            >(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                commitment_scheme_public_parameters.clone(),
                self.public_key_share,
            );

        let (nonce_share_by_key_share_proof, statement) = schnorr::Proof::<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
            discrete_log_ratio_of_committed_values::Language<
                SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
            >,
            ProtocolContext,
        >::prove(
            &self.protocol_context,
            &language_public_parameters,
            vec![[
                self.nonce_share,
                self.nonce_share_commitment_randomness,
                nonce_share_by_key_share_commitment_randomness,
            ]
            .into()],
            rng,
        )?;

        let statement = statement.first().ok_or(crate::Error::InternalError)?;

        let nonce_share_by_key_share_commitment =
            statement.altered_base_committment_of_discrete_log().clone();

        let nonce_x_coordinate = public_nonce.x(); // $r$

        let first_coefficient = (nonce_x_coordinate * self.nonce_share * self.secret_key_share)
            + (message * self.nonce_share); // $a1$

        let first_coefficient_commitment_randomness = (nonce_x_coordinate
            * nonce_share_by_key_share_commitment_randomness)
            + (message * self.nonce_share_commitment_randomness);

        let second_coefficient = nonce_x_coordinate * self.nonce_share; // $a2$

        let second_coefficient_commitment_randomness =
            nonce_x_coordinate * self.nonce_share_commitment_randomness;

        let partial_signature_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample(
                &self
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                rng,
            )?;

        let ciphertexts =
            [self.encrypted_mask, self.encrypted_masked_key_share].map(|ct| ct.value());

        // TODO: 1 is for l as DIMENSION = 2; perhaps compute this through log.
        // Uint::<SCALAR_LIMBS>::BITS is an upper bound.
        // This is correct?
        let sampling_bit_size: usize =
            Uint::<SCALAR_LIMBS>::BITS + 1 + StatisticalSecuritySizedNumber::BITS;

        // TODO: verify
        let mask = Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::MAX
            >> (Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::BITS - sampling_bit_size);

        let mask = EncryptionKey::PlaintextSpaceGroupElement::new(
            (Uint::<{ PLAINTEXT_SPACE_SCALAR_LIMBS }>::random(rng) & mask).into(),
            self.encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;

        let coefficients: [Uint<SCALAR_LIMBS>; DIMENSION] =
            [first_coefficient, second_coefficient].map(|coefficient| coefficient.into());

        let coefficients: self_product::GroupElement<DIMENSION, _> = coefficients
            .map(|coefficient| {
                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&coefficient).into(),
                    self.encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .flat_map_results()?
            .into();

        let commitment_randomness: self_product::GroupElement<DIMENSION, _> = [
            first_coefficient_commitment_randomness,
            second_coefficient_commitment_randomness,
        ]
        .into();

        let witness = (
            coefficients,
            commitment_randomness,
            mask,
            partial_signature_encryption_randomness,
        )
            .into();

        let commitment_scheme_public_parameters = commitment_scheme_public_parameters.into();

        let language_public_parameters =
            committed_linear_evaluation::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                DIMENSION,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                self.encryption_scheme_public_parameters.clone(),
                commitment_scheme_public_parameters,
                ciphertexts,
            );

        let language_public_parameters = EnhancedPublicParameters::<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
        );

        let witness = EnhancedLanguage::<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
        >::generate_witness(witness, &language_public_parameters, rng)?;

        let (encrypted_partial_signature_proof, statement) = enhanced::Proof::<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
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
            ProtocolContext,
        >::prove(
            &self.protocol_context,
            &language_public_parameters,
            vec![witness],
            rng,
        )?;

        let statement = statement.first().ok_or(crate::Error::InternalError)?;

        let encrypted_partial_signature_range_proof_commitment = statement.range_proof_commitment();
        let encrypted_partial_signature = statement.language_statement().ciphertext();
        let coefficient_commitments: &[_; DIMENSION] =
            statement.language_statement().commitments().into();

        Ok(PublicNonceEncryptedPartialSignatureAndProof {
            public_nonce: public_nonce.value(),
            public_nonce_proof,
            nonce_share_by_key_share_commitment: nonce_share_by_key_share_commitment.value(),
            nonce_share_by_key_share_proof,
            first_coefficient_commitment: coefficient_commitments[0].value(),
            second_coefficient_commitment: coefficient_commitments[1].value(),
            encrypted_partial_signature: encrypted_partial_signature.value(),
            encrypted_partial_signature_range_proof_commitment:
                encrypted_partial_signature_range_proof_commitment.value(),
            encrypted_partial_signature_proof,
        })
    }
}
