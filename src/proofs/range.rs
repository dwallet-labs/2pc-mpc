// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use crypto_bigint::{rand_core::CryptoRngCore, Encoding};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    commitments,
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{self_product, NumbersGroupElement, Samplable},
    proofs::{
        schnorr::{aggregation::CommitmentRoundParty, enhanced, enhanced::EnhanceableLanguage},
        Result,
    },
};

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
>: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq
{
    /// A unique string representing the name of this range proof; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// The maximum number of bits this proof can prove for every witness.
    const RANGE_CLAIM_BITS: usize;

    /// An element of the group from which the range proof's commitment scheme message space is composed,
    /// used to prove a single range claim.
    type RangeClaimGroupElement: NumbersGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;

    /// The commitment scheme used for the range proof
    type CommitmentScheme<const NUM_RANGE_CLAIMS: usize>: HomomorphicCommitmentScheme<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, MessageSpaceGroupElement=self_product::GroupElement<NUM_RANGE_CLAIMS, Self::RangeClaimGroupElement>>;

    /// The public parameters of the range proof.
    ///
    /// Includes the public parameters of the commitment scheme, and any range claims if the scheme permits such.
    ///
    /// SECURITY NOTE: Needs to be inserted to the  Fiat-Shamir Transcript of the proof protocol.
    type PublicParameters<const NUM_RANGE_CLAIMS: usize>: AsRef<
        commitments::PublicParameters<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme<NUM_RANGE_CLAIMS>>
    > + Serialize
    + for<'r> Deserialize<'r>
    + Clone
    + PartialEq;

    // /// The commitment round party of enhanced Schnorr proof aggregation protocol using this range proof.
    // type AggregationCommitmentRoundParty<const REPETITIONS: usize,
    //     const NUM_RANGE_CLAIMS: usize,
    //     UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
    //     Language: EnhanceableLanguage<
    //         REPETITIONS,
    //         NUM_RANGE_CLAIMS,
    //         COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    //         UnboundedWitnessSpaceGroupElement,
    //     >,
    //     ProtocolContext: Clone + Serialize>: CommitmentRoundParty<AggregationOutput<REPETITIONS, NUM_RANGE_CLAIMS, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, UnboundedWitnessSpaceGroupElement, Self, Language, ProtocolContext>>;

    /// Proves in zero-knowledge that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn prove<const NUM_RANGE_CLAIMS: usize>(
        public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        witnesses: Vec<CommitmentSchemeMessageSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        commitments_randomness: Vec<CommitmentSchemeRandomnessSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        transcript: Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Vec<commitments::CommitmentSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme<NUM_RANGE_CLAIMS>>>)>;

    // /// Starts a new enhanced Schnorr proof aggregation session, by returning its commitment round party instance.
    // fn new_enhanced_session<const REPETITIONS: usize,
    //     const NUM_RANGE_CLAIMS: usize,
    //     UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
    //     Language: EnhanceableLanguage<
    //         REPETITIONS,
    //         NUM_RANGE_CLAIMS,
    //         COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    //         UnboundedWitnessSpaceGroupElement,
    //     >,
    //     ProtocolContext: Clone + Serialize>(
    //     public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
    //     // TODO: schnorr witnesses etc.
    //     witnesses: Vec<CommitmentSchemeMessageSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
    //     commitments_randomness: Vec<CommitmentSchemeRandomnessSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
    //     transcript: &mut Transcript,
    //     rng: &mut impl CryptoRngCore,
    // ) -> Self::AggregationCommitmentRoundParty<REPETITIONS, NUM_RANGE_CLAIMS, UnboundedWitnessSpaceGroupElement, Language, ProtocolContext>;

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

pub trait CommitmentPublicParametersAccessor<CommitmentPublicParameters>:
    AsRef<CommitmentPublicParameters>
{
    fn commitment_scheme_public_parameters(&self) -> &CommitmentPublicParameters {
        self.as_ref()
    }
}

impl<CommitmentPublicParameters, T: AsRef<CommitmentPublicParameters>>
    CommitmentPublicParametersAccessor<CommitmentPublicParameters> for T
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
> = commitments::PublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::MessageSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::MessageSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::MessageSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::RandomnessSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::RandomnessSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::RandomnessSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::CommitmentSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::CommitmentSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitments::CommitmentSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

// TODO: tests?

// TODO: do i even need benches here?

// #[cfg(feature = "benchmarking")]
// mod benches {
//     use criterion::Criterion;
//     use rand_core::OsRng;
//
//     use super::*;
//     use crate::{
//         group::additive_group_of_integers_modulu_n::power_of_two_moduli,
//         proofs::schnorr::{
//             language, language::enhanced::tests::generate_witnesses, EnhancedLanguage,
//         },
//     };
//
//     pub(crate) fn benchmark<
//         const REPETITIONS: usize,
//         const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
//         const NUM_RANGE_CLAIMS: usize,
//     //         const WITNESS_MASK_LIMBS: usize,
//         Lang: EnhancedLanguage<
//             REPETITIONS,
//             COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//
//
//         >,
//     >(
//         language_public_parameters: &Lang::PublicParameters,
//         range_proof_public_parameters: &PublicParameters<
//             COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//
//             Lang::RangeProof,
//         >,
//         c: &mut Criterion,
//     ) where
//         Uint<RANGE_CLAIM_LIMBS>: Encoding,
//         Uint<WITNESS_MASK_LIMBS>: Encoding,
//     {
//         let mut g = c.benchmark_group(Lang::NAME);
//
//         g.sample_size(10);
//
//         for batch_size in [1, 10, 100, 1000] {
//             let witnesses = generate_witnesses::<
//                 REPETITIONS,
//                 COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//                 NUM_RANGE_CLAIMS,
//
//
//                 Lang,
//             >(language_public_parameters, batch_size);
//
//             let (constrained_witnesses, commitment_randomnesses): (
//                 Vec<[Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS]>,
//                 Vec<
//                     language::enhanced::RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
//                         REPETITIONS,
//                         COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//                         NUM_RANGE_CLAIMS,
//
//
//                         Lang,
//                     >,
//                 >,
//             ) = witnesses
//                 .clone()
//                 .into_iter()
//                 .map(|witness| {
//                     let (constrained_witness, commitment_randomness, _) = witness.into();
//
//                     let constrained_witness:
// [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>;                         NUM_RANGE_CLAIMS]
// = constrained_witness.into();
//
//                     let constrained_witness: [Uint<RANGE_CLAIM_LIMBS>; NUM_RANGE_CLAIMS] =
//                         constrained_witness.map(|witness_part| {
//                             let witness_part_value: Uint<WITNESS_MASK_LIMBS> =
// witness_part.into();
//
//                             (&witness_part_value).into()
//                         });
//
//                     (constrained_witness, commitment_randomness)
//                 })
//                 .unzip();
//
//             g.bench_function(
//                 format!("range::RangeProof::prove() over {batch_size} statements"),
//                 |bench| {
//                     bench.iter(|| {
//                         language::enhanced::RangeProof::<
//                             REPETITIONS,
//                             COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//                             NUM_RANGE_CLAIMS,
//
//
//                             Lang,
//                         >::prove(
//                             range_proof_public_parameters,
//                             constrained_witnesses.clone(),
//                             commitment_randomnesses.clone(),
//                             &mut Transcript::new(b"benchmarking"),
//                             &mut OsRng,
//                         )
//                         .unwrap()
//                     });
//                 },
//             );
//
//             let (range_proof, commitments) = language::enhanced::RangeProof::<
//                 REPETITIONS,
//                 COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//                 NUM_RANGE_CLAIMS,
//
//
//                 Lang,
//             >::prove(
//                 range_proof_public_parameters,
//                 constrained_witnesses,
//                 commitment_randomnesses,
//                 &mut Transcript::new(b"benchmarking"),
//                 &mut OsRng,
//             )
//             .unwrap();
//
//             g.bench_function(
//                 format!("range::RangeProof::verify() over {batch_size} statements"),
//                 |bench| {
//                     bench.iter(|| {
//                         range_proof.verify(
//                             &range_proof_public_parameters,
//                             commitments.clone(),
//                             &mut Transcript::new(b"benchmarking"),
//                             &mut OsRng,
//                         )
//                     });
//                 },
//             );
//         }
//
//         g.finish();
//     }
// }
