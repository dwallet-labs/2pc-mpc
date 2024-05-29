// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use commitment::{pedersen, Pedersen};
use crypto_bigint::{rand_core::CryptoRngCore, CheckedMul, Encoding, Uint};
use enhanced_maurer::{
    committed_linear_evaluation,
    committed_linear_evaluation::StatementAccessors as _,
    language::{composed_witness_upper_bound, EnhancedLanguageStatementAccessors},
    EnhanceableLanguage, EnhancedLanguage, EnhancedPublicParameters,
};
use group::{
    helpers::FlatMapResults, self_product, AffineXCoordinate, GroupElement as _, Invert,
    PrimeGroupElement, Samplable,
};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{
    committment_of_discrete_log, discrete_log_ratio_of_committed_values,
    discrete_log_ratio_of_committed_values::StatementAccessors as _, SOUND_PROOFS_REPETITIONS,
};
use proof::AggregatableRangeProof;
use serde::Serialize;

use crate::{
    dkg, presign,
    sign::{
        centralized_party::{
            signature_verification_round, PublicNonceEncryptedPartialSignatureAndProof,
        },
        DIMENSION,
    },
    Error, ProtocolPublicParameters,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedDComEvalWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
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
    pub(in crate::sign) secret_key_share: GroupElement::Scalar,
    pub(in crate::sign) public_key_share: GroupElement,
    pub(in crate::sign) nonce_share_commitment_randomness: GroupElement::Scalar,
    pub(in crate::sign) nonce_share: GroupElement::Scalar,
    pub(in crate::sign) decentralized_party_nonce_public_share: GroupElement,
    pub(in crate::sign) encrypted_mask: EncryptionKey::CiphertextSpaceGroupElement,
    pub(in crate::sign) encrypted_masked_key_share: EncryptionKey::CiphertextSpaceGroupElement,
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
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
{
    /// This function implements Protocol 6, step 1 of the
    /// 2PC-MPC: Emulating Two Party ECDSA in Large-Scale MPC paper.
    /// src: https://eprint.iacr.org/2024/253
    ///
    /// Evaluate the encrypted partial signature.
    /// Note: `message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    pub fn evaluate_encrypted_partial_signature_prehash(
        self,
        message: GroupElement::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        PublicNonceEncryptedPartialSignatureAndProof<
            GroupElement::Value,
            proof::range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
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
        signature_verification_round::Party<SCALAR_LIMBS, GroupElement>,
    )> {
        // = (k_A)^{-1}
        let inverted_nonce_share = self.nonce_share.invert();
        if inverted_nonce_share.is_none().into() {
            // This has negligible probability of failing.
            return Err(crate::Error::InternalError);
        }
        let inverted_nonce_share = inverted_nonce_share.unwrap();

        // = R
        let public_nonce = inverted_nonce_share * self.decentralized_party_nonce_public_share;

        // Generate DComDL public parameters
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

        // === Generate DComDL proof ===
        // Protocol 6, step 1e, dash 1
        let (public_nonce_proof, _) = maurer::Proof::<
            SOUND_PROOFS_REPETITIONS,
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
            vec![[self.nonce_share, self.nonce_share_commitment_randomness].into()], // = [k_A, ρ_1]
            rng,
        )?;

        // === Sample ρ_2 ===
        // Protocol 6, step 1b
        let nonce_share_by_key_share_commitment_randomness =
            GroupElement::Scalar::sample(&self.scalar_group_public_parameters, rng)?;

        // Generate DComRatio public parameters
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

        // === Generate DComRatio proof ===
        // Protocol 6, step 1e, dash 2
        let (nonce_share_by_key_share_proof, statement) = maurer::Proof::<
            SOUND_PROOFS_REPETITIONS,
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

        // = U_A
        let nonce_share_by_key_share_commitment =
            statement.altered_base_committment_of_discrete_log().clone();

        // = r
        let nonce_x_coordinate = public_nonce.x();

        // = a_1
        let first_coefficient = (nonce_x_coordinate * self.nonce_share * self.secret_key_share)
            + (message * self.nonce_share);

        // = r * ρ_2 + m * ρ_1
        let first_coefficient_commitment_randomness = (nonce_x_coordinate
            * nonce_share_by_key_share_commitment_randomness)
            + (message * self.nonce_share_commitment_randomness);

        // = a_2
        let second_coefficient = nonce_x_coordinate * self.nonce_share;

        // = r * ρ_1
        let second_coefficient_commitment_randomness =
            nonce_x_coordinate * self.nonce_share_commitment_randomness;

        // === Sample η ===
        // Protocol 6, step 1d
        let partial_signature_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample(
                self.encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                rng,
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
        ];

        // === Sample ω ===
        // Required for secure evaluation of the DComEval function.
        // See `homomorphic-encryption::AdditivelyHomomorphicEncryptionKey::securely_evaluate_linear_combination_with_randomness`
        let mask = EncryptionKey::sample_mask_for_secure_function_evaluation(
            &ciphertexts_and_upper_bounds,
            &self.encryption_scheme_public_parameters,
            rng,
        )?;

        // = A (see DComEval language definition, Section 5.2)
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

        // = ρ (see DComEval language definition, Section 5.2)
        let commitment_randomness: self_product::GroupElement<DIMENSION, _> = [
            first_coefficient_commitment_randomness,
            second_coefficient_commitment_randomness,
        ]
        .into();

        // = (A, ρ, ω, η)
        let witness = (
            coefficients,
            commitment_randomness,
            mask,
            partial_signature_encryption_randomness,
        )
            .into();

        // Generate DComEval language parameters
        let ciphertexts_and_upper_bounds =
            ciphertexts_and_upper_bounds.map(|(ct, upper_bound)| (ct.value(), upper_bound));
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

        // === Compute ct_A ===
        // Protocol 6, step 1e, dash 3
        let witness = EnhancedLanguage::<
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
        >::generate_witness(witness, &language_public_parameters, rng)?;
        let (encrypted_partial_signature_proof, statement) = enhanced_maurer::Proof::<
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
            ProtocolContext,
        >::prove(
            &self.protocol_context,
            &language_public_parameters,
            vec![witness],
            rng,
        )?;
        let statement = statement.first().ok_or(crate::Error::InternalError)?;

        let encrypted_partial_signature_range_proof_commitment = statement.range_proof_commitment();
        let encrypted_partial_signature = statement.language_statement().evaluated_ciphertext(); // = ct_A
        let coefficient_commitments: &[_; DIMENSION] =
            statement.language_statement().commitments().into();

        let public_nonce_encrypted_partial_signature_and_proof =
            PublicNonceEncryptedPartialSignatureAndProof {
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
            };

        let signature_verification_round_party = signature_verification_round::Party {
            public_key: self.public_key,
            message,
        };

        Ok((
            public_nonce_encrypted_partial_signature_and_proof,
            signature_verification_round_party,
        ))
    }

    pub fn new<
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
    >(
        protocol_context: ProtocolContext,
        protocol_public_parameters: ProtocolPublicParameters<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            UnboundedEncDHWitness,
            UnboundedDComEvalWitness,
        >,
        dkg_output: dkg::centralized_party::Output<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: presign::centralized_party::Presign<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    ) -> crate::Result<Self> {
        let scalar_group_public_parameters =
            protocol_public_parameters.scalar_group_public_parameters;
        let group_public_parameters = protocol_public_parameters.group_public_parameters;
        let encryption_scheme_public_parameters =
            protocol_public_parameters.encryption_scheme_public_parameters;

        let public_key = GroupElement::new(dkg_output.public_key, &group_public_parameters)?;

        let secret_key_share = GroupElement::Scalar::new(
            dkg_output.secret_key_share,
            &scalar_group_public_parameters,
        )?;

        let public_key_share =
            GroupElement::new(dkg_output.public_key_share, &group_public_parameters)?;

        let nonce_share_commitment_randomness = GroupElement::Scalar::new(
            presign.commitment_randomness,
            &scalar_group_public_parameters,
        )?;

        let nonce_share =
            GroupElement::Scalar::new(presign.nonce_share, &scalar_group_public_parameters)?;

        let decentralized_party_nonce_public_share = GroupElement::new(
            presign.decentralized_party_nonce_public_share,
            &group_public_parameters,
        )?;

        let encrypted_mask = EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encrypted_mask,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        let encrypted_masked_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encrypted_masked_key_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        Ok(Self {
            protocol_context,
            scalar_group_public_parameters,
            group_public_parameters,
            encryption_scheme_public_parameters,
            unbounded_dcom_eval_witness_public_parameters: protocol_public_parameters
                .unbounded_dcom_eval_witness_public_parameters,
            range_proof_public_parameters: protocol_public_parameters
                .range_proof_dcom_eval_public_parameters,
            public_key,
            secret_key_share,
            public_key_share,
            nonce_share_commitment_randomness,
            nonce_share,
            decentralized_party_nonce_public_share,
            encrypted_mask,
            encrypted_masked_key_share,
        })
    }
}
