// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::fmt::Debug;

// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use crypto_bigint::{rand_core::CryptoRngCore, Encoding};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    commitment,
    commitment::{GroupsPublicParametersAccessors, HomomorphicCommitmentScheme},
    group,
    group::{self_product, NumbersGroupElement, Samplable},
    proofs::{
        maurer::{
            aggregation, enhanced,
            enhanced::{EnhanceableLanguage, EnhancedPublicParameters},
        },
        Result,
    },
    PartyID,
};
use crate::group::KnownOrderScalar;

pub mod lightningproofs;

pub mod bulletproofs;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("at least one of the witnesses is out of range")]
    OutOfRange,

    #[error("bulletproofs error")]
    Bulletproofs(#[from] bulletproofs::Error),
}

pub trait RangeProof<
    // The commitment scheme's message space scalar size in limbs
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
>: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Debug + Eq
{
    /// A unique string representing the name of this range proof; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// The maximum number of bits this proof can prove for every witness.
    const RANGE_CLAIM_BITS: usize;

    /// An element of the group from which the range proof's commitment scheme message space is composed,
    /// used to prove a single range claim.
    type RangeClaimGroupElement: KnownOrderScalar<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;

    /// The commitment scheme used for the range proof
    type CommitmentScheme<const NUM_RANGE_CLAIMS: usize>: HomomorphicCommitmentScheme<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, MessageSpaceGroupElement=self_product::GroupElement<NUM_RANGE_CLAIMS, Self::RangeClaimGroupElement>>;

    /// The public parameters of the range proof.
    ///
    /// Includes the public parameters of the commitment scheme, and any range claims if the scheme permits such.
    ///
    /// SECURITY NOTE: Needs to be inserted to the  Fiat-Shamir Transcript of the proof protocol.
    type PublicParameters<const NUM_RANGE_CLAIMS: usize>: AsRef<
        commitment::PublicParameters<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme<NUM_RANGE_CLAIMS>>
    > + Serialize
    + for<'r> Deserialize<'r>
    + Clone
    + PartialEq;

    /// The commitment round party of enhanced Maurer proof aggregation protocol using this range proof.
    type AggregationCommitmentRoundParty<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize>: aggregation::CommitmentRoundParty<AggregationOutput<REPETITIONS, NUM_RANGE_CLAIMS, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, UnboundedWitnessSpaceGroupElement, Self, Language, ProtocolContext>>;

    /// Proves in zero-knowledge that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn prove<const NUM_RANGE_CLAIMS: usize>(
        public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        witnesses: Vec<CommitmentSchemeMessageSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        commitments_randomness: Vec<CommitmentSchemeRandomnessSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        transcript: Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Vec<commitment::CommitmentSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme<NUM_RANGE_CLAIMS>>>)>;

    /// Starts a new enhanced Maurer proof aggregation session, by returning its commitment round party instance.
    fn new_enhanced_session<const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize>(
        party_id: PartyID,
        threshold: PartyID,
        number_of_parties: PartyID,
        language_public_parameters: EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            Self,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        protocol_context: ProtocolContext,
        witnesses: Vec<
            enhanced::WitnessSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                Self,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    ) -> Self::AggregationCommitmentRoundParty<REPETITIONS, NUM_RANGE_CLAIMS, UnboundedWitnessSpaceGroupElement, Language, ProtocolContext>;

    /// Verifies that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn verify<const NUM_RANGE_CLAIMS: usize>(
        &self,
        public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        commitments: Vec<CommitmentSchemeCommitmentSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        transcript: Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()>;
}

pub type AggregationOutput<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = (
    enhanced::Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        Proof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >,
    Vec<
        enhanced::StatementSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            Proof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
    >,
);

pub type CommitmentRoundParty<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = Proof::AggregationCommitmentRoundParty<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    UnboundedWitnessSpaceGroupElement,
    Language,
    ProtocolContext,
>;

pub type Commitment<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = <CommitmentRoundParty<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    UnboundedWitnessSpaceGroupElement,
    Proof,
    Language,
    ProtocolContext,
> as aggregation::CommitmentRoundParty<
    AggregationOutput<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        Proof,
        Language,
        ProtocolContext,
    >,
>>::Commitment;

pub type DecommitmentRoundParty<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = <Proof::AggregationCommitmentRoundParty<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    UnboundedWitnessSpaceGroupElement,
    Language,
    ProtocolContext,
> as aggregation::CommitmentRoundParty<
    AggregationOutput<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        Proof,
        Language,
        ProtocolContext,
    >,
>>::DecommitmentRoundParty;

pub type Decommitment<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = <DecommitmentRoundParty<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    UnboundedWitnessSpaceGroupElement,
    Proof,
    Language,
    ProtocolContext,
> as aggregation::DecommitmentRoundParty<
    AggregationOutput<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        Proof,
        Language,
        ProtocolContext,
    >,
>>::Decommitment;

pub type ProofShareRoundParty<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = <DecommitmentRoundParty<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    UnboundedWitnessSpaceGroupElement,
    Proof,
    Language,
    ProtocolContext,
> as aggregation::DecommitmentRoundParty<
    AggregationOutput<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        Proof,
        Language,
        ProtocolContext,
    >,
>>::ProofShareRoundParty;

pub type ProofShare<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = <ProofShareRoundParty<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    UnboundedWitnessSpaceGroupElement,
    Proof,
    Language,
    ProtocolContext,
> as aggregation::ProofShareRoundParty<
    AggregationOutput<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        Proof,
        Language,
        ProtocolContext,
    >,
>>::ProofShare;

pub type ProofAggregationRoundParty<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Proof: RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> = <ProofShareRoundParty<
    REPETITIONS,
    NUM_RANGE_CLAIMS,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    UnboundedWitnessSpaceGroupElement,
    Proof,
    Language,
    ProtocolContext,
> as aggregation::ProofShareRoundParty<
    AggregationOutput<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        Proof,
        Language,
        ProtocolContext,
    >,
>>::ProofAggregationRoundParty;

pub trait PublicParametersAccessors<
    'a,
    const NUM_RANGE_CLAIMS: usize,
    RangeClaimPublicParameters: 'a,
    RandomnessSpacePublicParameters: 'a,
    CommitmentSpacePublicParameters: 'a,
    CommitmentSchemePublicParameters: 'a,
>: AsRef<CommitmentSchemePublicParameters> where
    CommitmentSchemePublicParameters: AsRef<
        commitment::GroupsPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    >,
{
    fn commitment_scheme_public_parameters(&'a self) -> &'a CommitmentSchemePublicParameters {
        self.as_ref()
    }

    fn range_claim_public_parameters(&'a self) -> &'a RangeClaimPublicParameters {
        &self
            .commitment_scheme_public_parameters()
            .message_space_public_parameters()
            .public_parameters
    }
}

impl<
        'a,
        const NUM_RANGE_CLAIMS: usize,
        RangeClaimPublicParameters: 'a,
        RandomnessSpacePublicParameters: 'a,
        CommitmentSpacePublicParameters: 'a,
        CommitmentSchemePublicParameters: 'a,
        T: AsRef<CommitmentSchemePublicParameters>,
    >
    PublicParametersAccessors<
        'a,
        NUM_RANGE_CLAIMS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    > for T
where
    CommitmentSchemePublicParameters: AsRef<
        commitment::GroupsPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    >,
{
}

pub type PublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::PublicParameters<
    NUM_RANGE_CLAIMS,
>;

pub type CommitmentScheme<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
    NUM_RANGE_CLAIMS,
>;

pub type RangeClaimGroupElement<const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize, Proof> =
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RangeClaimGroupElement;

pub type CommitmentSchemePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::PublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::MessageSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::MessageSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::MessageSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::RandomnessSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::RandomnessSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::RandomnessSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::CommitmentSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::CommitmentSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::CommitmentSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

// TODO: tests?
