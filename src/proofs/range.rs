// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{commitments, commitments::HomomorphicCommitmentScheme, proofs::Result};

pub mod bulletproofs;

pub trait RangeProof<
    // The commitment scheme's message space scalar size in limbs
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims (the lower bound is fixed to zero.)
    const RANGE_CLAIM_LIMBS: usize,
>: Serialize + for<'a> Deserialize<'a> + Clone where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
{
    /// A unique string representing the name of this range proof; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// The commitment scheme used for the range proof
    type CommitmentScheme: HomomorphicCommitmentScheme<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;

    /// The public parameters of the range proof.
    ///
    /// Includes the public parameters of the commitment scheme, and any range claims if the scheme permits such.
    ///
    /// SECURITY NOTE: Needs to be inserted to the  Fiat-Shamir Transcript of the proof protocol.
    type PublicParameters: AsRef<
        commitments::PublicParameters<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme>
    > + Serialize
    + for<'r> Deserialize<'r>
    + Clone
    + PartialEq;

    /// Proves in zero-knowledge that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn prove(
        public_parameters: &Self::PublicParameters,
        witnesses: Vec<[Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
        commitments_randomness: Vec<commitments::RandomnessSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme>>,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Vec<commitments::CommitmentSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme>>)>;

    /// Verifies that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn verify(
        &self,
        public_parameters: &Self::PublicParameters,
        commitments: Vec<commitments::CommitmentSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme>>,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()>;
}

pub type PublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = <Proof as RangeProof<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
>>::PublicParameters;

pub type CommitmentScheme<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = <Proof as RangeProof<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
>>::CommitmentScheme;

pub type CommitmentSchemePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::PublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeMessageSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::MessageSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeMessageSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::MessageSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeMessageSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::MessageSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeRandomnessSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::RandomnessSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeRandomnessSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::RandomnessSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeRandomnessSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::RandomnessSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeCommitmentSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::CommitmentSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeCommitmentSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::CommitmentSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;

pub type CommitmentSchemeCommitmentSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    Proof,
> = commitments::CommitmentSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
    >>::CommitmentScheme,
>;
