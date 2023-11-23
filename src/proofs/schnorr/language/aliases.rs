// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

pub mod knowledge_of_discrete_log {
    use crate::proofs::{
        schnorr,
        schnorr::{
            aggregation, language,
            language::knowledge_of_discrete_log::{Language, REPETITIONS},
        },
    };

    /// The Witness Space Group Element of a Knowledge of Discrete Log Schnorr Language.
    pub type WitnessSpaceGroupElement<Scalar, GroupElement> =
        language::WitnessSpaceGroupElement<REPETITIONS, Language<Scalar, GroupElement>>;

    /// The Statement Space Group Element of a Knowledge of Discrete Log Schnorr Language.
    pub type StatementSpaceGroupElement<Scalar, GroupElement> =
        language::StatementSpaceGroupElement<REPETITIONS, Language<Scalar, GroupElement>>;

    /// The Public Parameters of a Knowledge of Discrete Log Schnorr Language.
    pub type LanguagePublicParameters<Scalar, GroupElement> =
        language::PublicParameters<REPETITIONS, Language<Scalar, GroupElement>>;

    /// A Knowledge of Discrete Log Schnorr Proof.
    pub type Proof<Scalar, GroupElement, ProtocolContext> =
        schnorr::Proof<REPETITIONS, Language<Scalar, GroupElement>, ProtocolContext>;

    /// A Knowledge of Discrete Log Schnorr Proof Aggregation Commitment Round Party.
    pub type ProofAggregationCommitmentRoundParty<Scalar, GroupElement, ProtocolContext> =
        aggregation::commitment_round::Party<
            REPETITIONS,
            Language<Scalar, GroupElement>,
            ProtocolContext,
        >;

    /// A Knowledge of Discrete Log Schnorr Proof Aggregation Decommitment Round Party.
    pub type ProofAggregationDecommitmentRoundParty<Scalar, GroupElement, ProtocolContext> =
        aggregation::decommitment_round::Party<
            REPETITIONS,
            Language<Scalar, GroupElement>,
            ProtocolContext,
        >;

    /// A Knowledge of Discrete Log Schnorr Proof Aggregation Decommitment.
    pub type Decommitment<Scalar, GroupElement> =
        aggregation::decommitment_round::Decommitment<REPETITIONS, Language<Scalar, GroupElement>>;

    /// A Knowledge of Discrete Log Schnorr Proof Aggregation Proof Share Round Party.
    pub type ProofAggregationProofShareRoundParty<Scalar, GroupElement, ProtocolContext> =
        aggregation::proof_share_round::Party<
            REPETITIONS,
            Language<Scalar, GroupElement>,
            ProtocolContext,
        >;

    /// A Knowledge of Discrete Log Schnorr Proof Aggregation Proof Share.
    pub type ProofShare<Scalar, GroupElement> =
        aggregation::proof_share_round::ProofShare<REPETITIONS, Language<Scalar, GroupElement>>;

    /// A Knowledge of Discrete Log Schnorr Proof Aggregation Proof Aggregation Round Party.
    pub type ProofAggregationProofAggregationRoundParty<Scalar, GroupElement, ProtocolContext> =
        aggregation::proof_aggregation_round::Party<
            REPETITIONS,
            Language<Scalar, GroupElement>,
            ProtocolContext,
        >;
}

pub mod knowledge_of_decommitment {
    use crate::proofs::{
        schnorr,
        schnorr::{aggregation, language, language::knowledge_of_decommitment::Language},
    };

    /// The Public Parameters of a Knowledge of Decommitment Schnorr Language.
    pub type WitnessSpaceGroupElement<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = language::WitnessSpaceGroupElement<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// The Witness Space Group Element of a Knowledge of Decommitment Schnorr Language.
    pub type LanguagePublicParameters<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = language::PublicParameters<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// The Statement Space Group Element of a Knowledge of Decommitment Schnorr Language.
    pub type StatementSpaceGroupElement<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = language::StatementSpaceGroupElement<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// A Knowledge of Decommitment Schnorr Proof.
    pub type Proof<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = schnorr::Proof<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Knowledge of Decommitment Schnorr Proof Aggregation Commitment Round Party.
    pub type ProofAggregationCommitmentRoundParty<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::commitment_round::Party<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Knowledge of Decommitment Schnorr Proof Aggregation Decommitment Round Party.
    pub type ProofAggregationDecommitmentRoundParty<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::decommitment_round::Party<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Knowledge of Decommitment Schnorr Proof Aggregation Decommitment.
    pub type Decommitment<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = aggregation::decommitment_round::Decommitment<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// A Knowledge of Decommitment Schnorr Proof Aggregation Proof Share Round Party.
    pub type ProofAggregationProofShareRoundParty<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::proof_share_round::Party<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Knowledge of Decommitment Schnorr Proof Aggregation Proof Share.
    pub type ProofShare<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = aggregation::proof_share_round::ProofShare<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// A Knowledge of Decommitment Schnorr Proof Aggregation Proof Aggregation Round Party.
    pub type ProofAggregationProofAggregationRoundParty<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::proof_aggregation_round::Party<
        REPETITIONS,
        Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;
}

pub mod discrete_log_ratio_of_commited_values {
    use crate::proofs::{
        schnorr,
        schnorr::{
            aggregation, language,
            language::discrete_log_ratio_of_commited_values::{Language, REPETITIONS},
        },
    };

    /// The Witness Space Group Element of a Ratio Between Committed Values is the Discrete Log
    /// Schnorr Language.
    pub type WitnessSpaceGroupElement<const SCALAR_LIMBS: usize, Scalar, GroupElement> =
        language::WitnessSpaceGroupElement<
            REPETITIONS,
            Language<SCALAR_LIMBS, Scalar, GroupElement>,
        >;

    /// The Statement Space Group Element of a Ratio Between Committed Values is the Discrete Log
    /// Schnorr Language.
    pub type StatementSpaceGroupElement<const SCALAR_LIMBS: usize, Scalar, GroupElement> =
        language::StatementSpaceGroupElement<
            REPETITIONS,
            Language<SCALAR_LIMBS, Scalar, GroupElement>,
        >;

    /// The Public Parameters of a Ratio Between Committed Values is the Discrete Log Schnorr
    /// Language.
    pub type LanguagePublicParameters<const SCALAR_LIMBS: usize, Scalar, GroupElement> =
        language::PublicParameters<REPETITIONS, Language<SCALAR_LIMBS, Scalar, GroupElement>>;

    /// A Ratio Between Committed Values is the Discrete Log Schnorr Proof.
    pub type Proof<const SCALAR_LIMBS: usize, Scalar, GroupElement, ProtocolContext> =
        schnorr::Proof<REPETITIONS, Language<SCALAR_LIMBS, Scalar, GroupElement>, ProtocolContext>;

    /// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Proof Aggregation
    /// Commitment Round Party.
    pub type ProofAggregationCommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        ProtocolContext,
    > = aggregation::commitment_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement>,
        ProtocolContext,
    >;

    /// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Decommitment
    /// Round Party.
    pub type ProofAggregationDecommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        ProtocolContext,
    > = aggregation::decommitment_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement>,
        ProtocolContext,
    >;

    /// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Decommitment.
    pub type Decommitment<const SCALAR_LIMBS: usize, Scalar, GroupElement> =
        aggregation::decommitment_round::Decommitment<
            REPETITIONS,
            Language<SCALAR_LIMBS, Scalar, GroupElement>,
        >;

    /// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Proof Share
    /// Round Party.
    pub type ProofAggregationProofShareRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        ProtocolContext,
    > = aggregation::proof_share_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement>,
        ProtocolContext,
    >;

    /// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Proof Share.
    pub type ProofAggregationProofShareProofShareRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
    > = aggregation::proof_share_round::ProofShare<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement>,
    >;

    /// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Proof
    /// Aggregation Round Party.
    pub type ProofAggregationProofAggregationRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        ProtocolContext,
    > = aggregation::proof_aggregation_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement>,
        ProtocolContext,
    >;
}

pub mod commitment_of_discrete_log {
    use crate::proofs::{
        schnorr,
        schnorr::{
            aggregation, language,
            language::commitment_of_discrete_log::{Language, REPETITIONS},
        },
    };

    /// The Witness Space Group Element of a Commitment of Discrete Log Schnorr Language.
    pub type WitnessSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = language::WitnessSpaceGroupElement<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// The Statement Space Group Element of a Commitment of Discrete Log Schnorr Language.
    pub type StatementSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = language::StatementSpaceGroupElement<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// The Public Parameters of a Commitment of Discrete Log Schnorr Language.
    pub type LanguagePublicParameters<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > = language::PublicParameters<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
    >;

    /// A Commitment of Discrete Log Schnorr Proof.
    pub type Proof<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = schnorr::Proof<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Commitment of Discrete Log Schnorr Proof Aggregation Commitment Round Party.
    pub type ProofAggregationCommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::commitment_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Commitment of Discrete Log Schnorr Proof Aggregation Decommitment Round Party.
    pub type ProofAggregationDecommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::decommitment_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Commitment of Discrete Log Schnorr Proof Aggregation Decommitment.
    pub type Decommitment<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> =
        aggregation::decommitment_round::Decommitment<
            REPETITIONS,
            Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        >;

    /// A Commitment of Discrete Log Schnorr Proof Share Round Party.
    pub type ProofAggregationProofShareRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::proof_share_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;

    /// A Commitment of Discrete Log Schnorr Proof Share.
    pub type ProofShare<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> =
        aggregation::proof_share_round::ProofShare<
            REPETITIONS,
            Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        >;

    /// A Commitment of Discrete Log Schnorr Proof Aggregation Proof Aggregation Round Party.
    pub type ProofAggregationProofAggregationRoundParty<
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
        ProtocolContext,
    > = aggregation::proof_aggregation_round::Party<
        REPETITIONS,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;
}

pub mod encryption_of_tuple {
    use crate::proofs::{
        schnorr,
        schnorr::{
            aggregation, language,
            language::enhanced::encryption_of_tuple::{Language, REPETITIONS},
        },
    };

    /// The Witness Space Group Element of an Encryption of a Tuple Schnorr Language.
    pub type WitnessSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = language::WitnessSpaceGroupElement<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// The Statement Space Group Element of an Encryption of a Tuple Schnorr Language.
    pub type StatementSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = language::StatementSpaceGroupElement<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// The Public Parameters of an Encryption of a Tuple Schnorr Language.
    pub type LanguagePublicParameters<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = language::PublicParameters<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// An Encryption of a Tuple Schnorr Proof.
    pub type Proof<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = schnorr::Proof<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of a Tuple Schnorr Proof Aggregation Commitment Round Party.
    pub type ProofAggregationCommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::commitment_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of a Tuple Schnorr Proof Aggregation Decommitment Round Party.
    pub type ProofAggregationDecommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::decommitment_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of a Tuple Schnorr Proof Aggregation Decommitment.
    pub type Decommitment<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = aggregation::decommitment_round::Decommitment<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// An Encryption of a Tuple Schnorr Proof Aggregation Proof Share Round Party.
    pub type ProofAggregationProofShareRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::proof_share_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of a Tuple Schnorr Proof Aggregation Proof Share.
    pub type ProofShare<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = aggregation::proof_share_round::ProofShare<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// An Encryption of a Tuple Schnorr Proof Aggregation Proof Aggregation Round Party.
    pub type ProofAggregationProofAggregationRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::proof_aggregation_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;
}

pub mod encryption_of_discrete_log {
    use crate::proofs::{
        schnorr,
        schnorr::{
            aggregation, language,
            language::enhanced::encryption_of_discrete_log::{Language, REPETITIONS},
        },
    };

    /// The Witness Space Group Element of an Encryption of Discrete Log Schnorr Language.
    pub type WitnessSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = language::WitnessSpaceGroupElement<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// The Statement Space Group Element of an Encryption of Discrete Log Schnorr Language.
    pub type StatementSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = language::StatementSpaceGroupElement<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// The Public Parameters of an Encryption of Discrete Log Schnorr Language.
    pub type LanguagePublicParameters<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = language::PublicParameters<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// An Encryption of Discrete Log Schnorr Proof.
    pub type Proof<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = schnorr::Proof<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of Discrete Log Schnorr Proof Aggregation Commitment Round Party.
    pub type ProofAggregationCommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::commitment_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of Discrete Log Schnorr Proof Aggregation Decommitment Round Party.
    pub type ProofAggregationDecommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::decommitment_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of Discrete Log Schnorr Proof Aggregation Decommitment.
    pub type Decommitment<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = aggregation::decommitment_round::Decommitment<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// An Encryption of Discrete Log Schnorr Proof Aggregation Proof Share Round Party.
    pub type ProofAggregationProofShareRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::proof_share_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// An Encryption of Discrete Log Schnorr Proof Aggregation Proof Share.
    pub type ProofShare<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    > = aggregation::proof_share_round::ProofShare<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
    >;

    /// An Encryption of Discrete Log Schnorr Proof Proof Aggregation Round Party.
    pub type ProofAggregationProofAggregationRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    > = aggregation::proof_aggregation_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            RangeProof,
        >,
        ProtocolContext,
    >;
}

pub mod committed_linear_evaluation {
    use crate::proofs::{
        schnorr,
        schnorr::{
            aggregation, language,
            language::enhanced::committed_linear_evaluation::{Language, REPETITIONS},
        },
    };

    /// The Witness Space Group Element of a Committed Linear Evaluation Schnorr Language.
    pub type WitnessSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
    > = language::WitnessSpaceGroupElement<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
    >;

    /// The Statement Space Group Element of a Committed Linear Evaluation Schnorr Language.
    pub type StatementSpaceGroupElement<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
    > = language::StatementSpaceGroupElement<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
    >;

    /// The Public Parameters of a Committed Linear Evaluation Schnorr Language.
    pub type LanguagePublicParameters<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
    > = language::PublicParameters<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
    >;

    /// A Committed Linear Evaluation Schnorr Proof.
    pub type Proof<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
        ProtocolContext,
    > = schnorr::Proof<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// A Committed Linear Evaluation Schnorr Proof Aggregation Commitment Round Party.
    pub type ProofAggregationCommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
        ProtocolContext,
    > = aggregation::commitment_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// A Committed Linear Evaluation Schnorr Proof Aggregation Decommitment Round Party.
    pub type ProofAggregationDecommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
        ProtocolContext,
    > = aggregation::decommitment_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// A Committed Linear Evaluation Schnorr Proof Aggregation Decommitment.
    pub type ProDecommitmentofAggregationDecommitmentRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
    > = aggregation::decommitment_round::Decommitment<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
    >;

    /// A Committed Linear Evaluation Schnorr Proof Aggregation Proof Share Round Party.
    pub type ProofAggregationProofShareRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
        ProtocolContext,
    > = aggregation::proof_share_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
        ProtocolContext,
    >;

    /// A Committed Linear Evaluation Schnorr Proof Aggregation Proof Share.
    pub type ProofShare<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
    > = aggregation::proof_share_round::ProofShare<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
    >;

    /// A Committed Linear Evaluation Schnorr Proof Aggregation Proof Aggregation Round Party.
    pub type ProofAggregationProofAggregationRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const DIMENSION: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        EncryptionKey,
        CommitmentScheme,
        RangeProof,
        ProtocolContext,
    > = aggregation::proof_aggregation_round::Party<
        REPETITIONS,
        Language<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            MASK_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            DIMENSION,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            Scalar,
            GroupElement,
            EncryptionKey,
            CommitmentScheme,
            RangeProof,
        >,
        ProtocolContext,
    >;
}
