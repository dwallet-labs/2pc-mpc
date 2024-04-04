// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use group::{PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use proof::{range, AggregatableRangeProof};
use serde::Serialize;

pub mod dkg;
pub mod presign;
pub mod sign;

/// 2PC-MPC error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("commitment error")]
    Commitment(#[from] commitment::Error),
    #[error("homomorphic encryption error")]
    HomomorphicEncryption(#[from] homomorphic_encryption::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("maurer error")]
    Maurer(#[from] maurer::Error),
    #[error("enhanced maurer error")]
    EnhancedMaurer(#[from] enhanced_maurer::Error),
    #[error("tiresias error")]
    Tiresias(#[from] tiresias::Error),
    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),
    #[error("parties {:?} sent mismatching encrypted masks in the first and second proof aggregation protocols in the presign protocol", .0)]
    MismatchingEncrypedMasks(Vec<PartyID>),
    #[error("parties {:?} did not send partial decryption proofs in the signing identifiable abort protocol", .0)]
    UnresponsiveParties(Vec<PartyID>),
    #[error("not enough parties to initiate the session")]
    ThresholdNotReached,
    #[error("the other party maliciously attempted to bypass the commitment round by sending decommitment which does not match its commitment")]
    WrongDecommitment,
    #[error("the designated decrypting party behaved maliciously by not sending the honest decrypted values")]
    MaliciousDesignatedDecryptingParty(PartyID),
    #[error("signature failed to verify")]
    SignatureVerification,
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

/// 2PC-MPC result.
pub type Result<T> = std::result::Result<T, Error>;

pub const CENTRALIZED_PARTY_ID: PartyID = 1;
pub const DECENTRALIZED_PARTY_ID: PartyID = 2;

#[derive(Serialize, Clone, PartialEq)]
pub struct ProtocolPublicParameters<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const NUM_RANGE_CLAIMS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    UnboundedEncDHWitness: group::GroupElement + Samplable,
    UnboundedDComEvalWitness: group::GroupElement + Samplable,
> {
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub group_public_parameters: group::PublicParameters<GroupElement>,
    pub encryption_scheme_public_parameters:
        homomorphic_encryption::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    pub unbounded_encdl_witness_public_parameters: group::PublicParameters<UnboundedEncDLWitness>,
    pub unbounded_encdh_witness_public_parameters: group::PublicParameters<UnboundedEncDHWitness>,
    pub unbounded_dcom_eval_witness_public_parameters:
        group::PublicParameters<UnboundedDComEvalWitness>,
    pub range_proof_enc_dl_public_parameters: range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RangeProof,
    >,
    pub range_proof_dcom_eval_public_parameters: range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >,
}

#[cfg(feature = "paillier")]
pub mod paillier {
    use group::self_product;

    pub const PLAINTEXT_SPACE_SCALAR_LIMBS: usize = tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS;
    pub type EncryptionKey = tiresias::EncryptionKey;
    pub type DecryptionKeyShare = tiresias::DecryptionKeyShare;

    pub type UnboundedEncDLWitness = tiresias::RandomnessSpaceGroupElement;
    pub type UnboundedEncDHWitness =
        self_product::GroupElement<2, tiresias::RandomnessSpaceGroupElement>;

    pub type PlaintextSpaceGroupElement = tiresias::PlaintextSpaceGroupElement;
    pub type RandomnessSpaceGroupElement = tiresias::RandomnessSpaceGroupElement;
    pub type CiphertextSpaceGroupElement = tiresias::CiphertextSpaceGroupElement;
}

#[cfg(feature = "bulletproofs")]
pub mod bulletproofs {
    use group::ristretto;
    use proof::range::bulletproofs;

    pub const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize = ristretto::SCALAR_LIMBS;
    pub type RangeProof = bulletproofs::RangeProof;
}

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use group::secp256k1;

    pub const SCALAR_LIMBS: usize = secp256k1::SCALAR_LIMBS;
    pub type GroupElement = secp256k1::GroupElement;
    pub type Scalar = secp256k1::Scalar;

    #[cfg(feature = "paillier")]
    pub mod paillier {
        use group::{direct_product, self_product};

        use super::Scalar;
        use crate::sign::DIMENSION;

        type UnboundedDComEvalWitness = direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, Scalar>,
            tiresias::RandomnessSpaceGroupElement,
        >;

        #[cfg(feature = "bulletproofs")]
        pub mod bulletproofs {
            use bulletproofs::*;
            use commitment::Pedersen;
            use enhanced_maurer::{
                committed_linear_evaluation, encryption_of_discrete_log, encryption_of_tuple,
            };
            use group::{direct_product, secp256k1::GroupElement, self_product};
            use homomorphic_encryption::GroupsPublicParametersAccessors;
            use maurer::{
                committment_of_discrete_log, discrete_log_ratio_of_committed_values,
                knowledge_of_decommitment, knowledge_of_discrete_log,
            };
            use tiresias::LargeBiPrimeSizedNumber;

            use super::super::*;
            use crate::{
                bulletproofs::*,
                paillier::{
                    CiphertextSpaceGroupElement, DecryptionKeyShare, EncryptionKey,
                    UnboundedEncDHWitness, UnboundedEncDLWitness, PLAINTEXT_SPACE_SCALAR_LIMBS,
                },
                secp256k1::paillier::UnboundedDComEvalWitness,
                sign::DIMENSION,
            };

            pub type ProtocolPublicParameters = crate::ProtocolPublicParameters<
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
            >;

            impl ProtocolPublicParameters {
                pub fn new(paillier_associated_bi_prime: LargeBiPrimeSizedNumber) -> Self {
                    let scalar_group_public_parameters =
                        secp256k1::scalar::PublicParameters::default();

                    let group_public_parameters =
                        secp256k1::group_element::PublicParameters::default();

                    let range_proof_enc_dl_public_parameters =
                        proof::range::bulletproofs::PublicParameters::<RANGE_CLAIMS_PER_SCALAR>::default();

                    let range_proof_dcom_eval_public_parameters =
                        proof::range::bulletproofs::PublicParameters::<NUM_RANGE_CLAIMS>::default();

                    let encryption_scheme_public_parameters =
                        tiresias::encryption_key::PublicParameters::new(
                            paillier_associated_bi_prime,
                        )
                        .unwrap();

                    let unbounded_encdl_witness_public_parameters =
                        encryption_scheme_public_parameters
                            .randomness_space_public_parameters()
                            .clone();

                    let unbounded_encdh_witness_public_parameters =
                        self_product::PublicParameters::new(
                            encryption_scheme_public_parameters
                                .randomness_space_public_parameters()
                                .clone(),
                        );

                    let unbounded_dcom_eval_witness_public_parameters =
                        direct_product::PublicParameters(
                            self_product::PublicParameters::new(
                                scalar_group_public_parameters.clone(),
                            ),
                            encryption_scheme_public_parameters
                                .randomness_space_public_parameters()
                                .clone(),
                        );

                    Self {
                        scalar_group_public_parameters,
                        group_public_parameters,
                        encryption_scheme_public_parameters,
                        range_proof_enc_dl_public_parameters,
                        range_proof_dcom_eval_public_parameters,
                        unbounded_encdl_witness_public_parameters,
                        unbounded_encdh_witness_public_parameters,
                        unbounded_dcom_eval_witness_public_parameters,
                    }
                }
            }

            // TODO: Implement a similar macro like https://github.com/rozbb/rust-hpke/blob/main/src/kem/dhkem.rs (only use::*).
            pub type EncDLCommitmentRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::commitment_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDLDecommitmentRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::decommitment_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDLProofShareRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::proof_share_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDLProofAggregationRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::proof_aggregation_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDLProofAggregationOutput<ProtocolContext> =
                enhanced_maurer::aggregation::Output<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;
            pub type EncDLProof<ProtocolContext> = enhanced_maurer::Proof<
                { maurer::SOUND_PROOFS_REPETITIONS },
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
            >;

            pub type EncDLCommitment<ProtocolContext> =
                <EncDLCommitmentRoundParty<ProtocolContext> as proof::aggregation::CommitmentRoundParty<
                    EncDLProofAggregationOutput<ProtocolContext>,
                >>::Commitment;

            pub type EncDLDecommitment<ProtocolContext> = <EncDLDecommitmentRoundParty<
                ProtocolContext,
            > as proof::aggregation::DecommitmentRoundParty<
                EncDLProofAggregationOutput<ProtocolContext>,
            >>::Decommitment;

            pub type EncDLProofShare<ProtocolContext> =
            <EncDLProofShareRoundParty<ProtocolContext> as proof::aggregation::ProofShareRoundParty<
                EncDLProofAggregationOutput<ProtocolContext>,
            >>::ProofShare;

            pub type EncDHCommitmentRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::commitment_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDHDecommitmentRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::decommitment_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDHProofShareRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::proof_share_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDHProofAggregationRoundParty<ProtocolContext> =
                enhanced_maurer::aggregation::proof_aggregation_round::Party<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDHProofAggregationOutput<ProtocolContext> =
                enhanced_maurer::aggregation::Output<
                    { maurer::SOUND_PROOFS_REPETITIONS },
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
                >;

            pub type EncDHProof<ProtocolContext> = enhanced_maurer::Proof<
                { maurer::SOUND_PROOFS_REPETITIONS },
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
            >;

            pub type DComEvalProof<ProtocolContext> = enhanced_maurer::Proof<
                { maurer::SOUND_PROOFS_REPETITIONS },
                RANGE_CLAIMS_PER_SCALAR,
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
            >;

            pub type EncDHCommitment<ProtocolContext> =
            <EncDHCommitmentRoundParty<ProtocolContext> as proof::aggregation::CommitmentRoundParty<
                EncDHProofAggregationOutput<ProtocolContext>,
            >>::Commitment;

            pub type EncDHDecommitment<ProtocolContext> = <EncDHDecommitmentRoundParty<
                ProtocolContext,
            > as proof::aggregation::DecommitmentRoundParty<
                EncDHProofAggregationOutput<ProtocolContext>,
            >>::Decommitment;

            pub type EncDHProofShare<ProtocolContext> =
            <EncDHProofShareRoundParty<ProtocolContext> as proof::aggregation::ProofShareRoundParty<
                EncDHProofAggregationOutput<ProtocolContext>,
            >>::ProofShare;

            pub type SchnorrProof<ProtocolContext> =
                knowledge_of_discrete_log::Proof<Scalar, GroupElement, ProtocolContext>;

            pub type ComDLProof<ProtocolContext> = maurer::Proof<
                { maurer::SOUND_PROOFS_REPETITIONS },
                committment_of_discrete_log::Language<
                    SCALAR_LIMBS,
                    Scalar,
                    GroupElement,
                    Pedersen<1, SCALAR_LIMBS, Scalar, GroupElement>,
                >,
                ProtocolContext,
            >;

            pub type ComRatioProof<ProtocolContext> = maurer::Proof<
                { maurer::SOUND_PROOFS_REPETITIONS },
                discrete_log_ratio_of_committed_values::Language<
                    SCALAR_LIMBS,
                    Scalar,
                    GroupElement,
                >,
                ProtocolContext,
            >;

            pub type DComProof<ProtocolContext> = maurer::Proof<
                { maurer::SOUND_PROOFS_REPETITIONS },
                knowledge_of_decommitment::Language<
                    { maurer::SOUND_PROOFS_REPETITIONS },
                    SCALAR_LIMBS,
                    Pedersen<1, SCALAR_LIMBS, Scalar, GroupElement>,
                >,
                ProtocolContext,
            >;

            pub type DKGCommitmentRoundParty<ProtocolContext> =
                crate::dkg::centralized_party::commitment_round::Party<
                    SCALAR_LIMBS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                    RangeProof,
                    UnboundedEncDLWitness,
                    ProtocolContext,
                >;

            pub type PublicKeyShareDecommitmentAndProof<ProtocolContext> =
            crate::dkg::centralized_party::decommitment_round::PublicKeyShareDecommitmentAndProof<
                group::Value<GroupElement>,
                SchnorrProof<ProtocolContext>
            >;

            pub type DKGCentralizedPartyOutput = crate::dkg::centralized_party::Output<
                group::Value<GroupElement>,
                group::Value<Scalar>,
                group::Value<CiphertextSpaceGroupElement>,
            >;

            pub type EncryptionOfSecretKeyShareRoundParty<ProtocolContext> =
                crate::dkg::decentralized_party::encryption_of_secret_key_share_round::Party<
                    SCALAR_LIMBS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                    RangeProof,
                    UnboundedEncDLWitness,
                    ProtocolContext,
                >;

            pub type DecommitmentProofVerificationRoundParty<ProtocolContext> =
                crate::dkg::decentralized_party::decommitment_proof_verification_round::Party<
                    SCALAR_LIMBS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                    RangeProof,
                    UnboundedEncDLWitness,
                    ProtocolContext,
                >;

            pub type DKGDecentralizedPartyOutput =
                crate::dkg::decentralized_party::decommitment_proof_verification_round::Output<
                    group::Value<GroupElement>,
                    group::Value<CiphertextSpaceGroupElement>,
                >;

            pub type SecretKeyShareEncryptionAndProof<ProtocolContext> =
                crate::dkg::decentralized_party::SecretKeyShareEncryptionAndProof<
                    group::Value<GroupElement>,
                    group::Value<CommitmentSpaceGroupElement>,
                    group::Value<CiphertextSpaceGroupElement>,
                    EncDLProof<ProtocolContext>,
                >;

            pub type PresignCommitmentRoundParty<ProtocolContext> =
                crate::presign::centralized_party::commitment_round::Party<
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
                >;

            pub type PresignProofVerificationRoundParty<ProtocolContext> =
                crate::presign::centralized_party::proof_verification_round::Party<
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
                >;

            pub type SignatureNonceSharesCommitmentsAndBatchedProof<ProtocolContext> =
            crate::presign::centralized_party::commitment_round::SignatureNonceSharesCommitmentsAndBatchedProof<
                SCALAR_LIMBS,
                group::Value<GroupElement>,
                DComProof<ProtocolContext>,
            >;

            pub type CentralizedPartyPresign = crate::presign::centralized_party::Presign<
                group::Value<GroupElement>,
                group::Value<Scalar>,
                group::Value<CiphertextSpaceGroupElement>,
            >;

            pub type PresignDecentralizedPartyOutput<ProtocolContext> =
                crate::presign::decentralized_party::Output<
                    group::Value<GroupElement>,
                    group::Value<CommitmentSpaceGroupElement>,
                    group::Value<CiphertextSpaceGroupElement>,
                    EncDHProof<ProtocolContext>,
                    EncDLProof<ProtocolContext>,
                >;

            pub type EncryptedMaskAndMaskedNonceShare =
                encryption_of_tuple::StatementSpaceGroupElement<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    EncryptionKey,
                >;

            pub type EncryptedNonceShareAndPublicShare =
                encryption_of_discrete_log::StatementSpaceGroupElement<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >;

            pub type EncryptedMaskedKeyShareRoundParty<ProtocolContext> =
                crate::presign::decentralized_party::encrypted_masked_key_share_and_public_nonce_shares_round::Party<
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
                >;

            pub type EncryptedMaskedNoncesRoundParty<ProtocolContext> =
                crate::presign::decentralized_party::encrypted_masked_nonces_round::Party<
                    SCALAR_LIMBS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                    RangeProof,
                    UnboundedEncDHWitness,
                    ProtocolContext,
                >;

            pub type DecentralizedPartyPresign = crate::presign::decentralized_party::Presign<
                group::Value<GroupElement>,
                group::Value<CiphertextSpaceGroupElement>,
            >;

            pub type PublicNonceEncryptedPartialSignatureAndProof<ProtocolContext> =
                crate::sign::centralized_party::PublicNonceEncryptedPartialSignatureAndProof<
                    group::Value<GroupElement>,
                    group::Value<CommitmentSpaceGroupElement>,
                    group::Value<CiphertextSpaceGroupElement>,
                    ComDLProof<ProtocolContext>,
                    ComRatioProof<ProtocolContext>,
                    DComEvalProof<ProtocolContext>,
                >;

            pub type SignatureHomomorphicEvaluationParty<ProtocolContext> =
                crate::sign::centralized_party::signature_homomorphic_evaluation_round::Party<
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
                >;

            pub type SignatureVerificationParty =
                crate::sign::centralized_party::signature_verification_round::Party<
                    SCALAR_LIMBS,
                    GroupElement,
                >;

            pub type SignaturePartialDecryptionParty<ProtocolContext> =
                crate::sign::decentralized_party::signature_partial_decryption_round::Party<
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
                >;

            pub type SignatureThresholdDecryptionParty =
                crate::sign::decentralized_party::signature_threshold_decryption_round::Party<
                    SCALAR_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                    DecryptionKeyShare,
                >;

            pub type SignaturePartialDecryptionProofParty =
            crate::sign::decentralized_party::identifiable_abort::signature_partial_decryption_proof_round::Party<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
                DecryptionKeyShare,
            >;

            pub type SignaturePartialDecryptionProofVerificationParty =
            crate::sign::decentralized_party::identifiable_abort::signature_partial_decryption_verification_round::Party<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
                DecryptionKeyShare,
            >;
        }
    }

    #[cfg(feature = "bulletproofs")]
    pub mod bulletproofs {
        use crypto_bigint::{Uint, U64};
        use group::{ristretto::GroupElement, StatisticalSecuritySizedNumber};
        use proof::range::bulletproofs::RANGE_CLAIM_BITS;

        use super::{Scalar, SCALAR_LIMBS};
        use crate::sign::DIMENSION;

        pub const RANGE_CLAIMS_PER_SCALAR: usize = Uint::<SCALAR_LIMBS>::BITS / RANGE_CLAIM_BITS;
        pub const MASK_LIMBS: usize =
            SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

        pub const RANGE_CLAIMS_PER_MASK: usize = Uint::<MASK_LIMBS>::BITS / RANGE_CLAIM_BITS;

        pub const NUM_RANGE_CLAIMS: usize =
            DIMENSION * RANGE_CLAIMS_PER_SCALAR + RANGE_CLAIMS_PER_MASK;

        pub type MessageSpaceGroupElement = Scalar;
        pub type RandomnessSpaceGroupElement = Scalar;
        pub type CommitmentSpaceGroupElement = GroupElement;
    }
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(benches, sign::benchmark);
