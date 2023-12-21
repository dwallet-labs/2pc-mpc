// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    commitments, group,
    group::SamplableWithin,
    proofs,
    proofs::{
        range,
        schnorr::{enhanced::EnhanceableLanguage, language::enhanced::EnhancedLanguage},
        transcript_protocol::TranscriptProtocol,
    },
};

/// An Enhanced Batched Schnorr Zero-Knowledge Proof.
/// Implements Appendix B. Schnorr Protocols in the paper.
pub type Proof<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // The range proof commitment scheme's message space scalar size in limbs
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The unbounded witness group element
    UnboundedWitnessSpaceGroupElement: SamplableWithin,
    // The enhanceable language we are proving
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    RangeProof: range::RangeProof<MESSAGE_SPACE_SCALAR_LIMBS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> = private::Proof<
    super::Proof<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            MESSAGE_SPACE_SCALAR_LIMBS,
            range::CommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, RangeProof>,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >,
    RangeProof,
>;

mod private {
    use super::*;

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Proof<SchnorrProof, RangeProof> {
        pub(crate) schnorr_proof: SchnorrProof,
        pub(crate) range_proof: RangeProof,
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + SamplableWithin,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        RangeProof: range::RangeProof<MESSAGE_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >
    Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        Language,
        RangeProof,
        ProtocolContext,
    >
where
    Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
    commitments::MessageSpaceValue<
        MESSAGE_SPACE_SCALAR_LIMBS,
        range::CommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, RangeProof>,
    >: From<[Uint<MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS]>,
{
    /// Prove an enhanced batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        range_proof_public_parameters: &range::PublicParameters<
            MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<(Self, Vec<Language::StatementSpaceGroupElement>)> {
        let mut transcript =
            Self::setup_range_proof(protocol_context, range_proof_public_parameters)?;

        // let (constrained_witnesses, commitment_randomnesses): (Vec<[_; NUM_RANGE_CLAIMS]>,
        // Vec<_>) =     witnesses
        //         .clone()
        //         .into_iter()
        //         .map(|witness| {
        //             let constrained_witness: [_; NUM_RANGE_CLAIMS] =
        //                 (*witness.constrained_witness()).into();
        //
        //             let constrained_witness: [_; NUM_RANGE_CLAIMS] =
        //                 constrained_witness.map(|witness_part| {
        //                     let witness_part_value: Uint<MESSAGE_SPACE_SCALAR_LIMBS> =
        //                         witness_part.into();
        //
        //                     (&witness_part_value).into()
        //                 });
        //
        //             (
        //                 constrained_witness,
        //                 witness.range_proof_commitment_randomness().clone(),
        //             )
        //         })
        //         .unzip();
        //

        // // TODO: commitments are being computed twice. In order to avoid this, I would need to
        // // somehow partially compute the group homomorphism, which is problematic..
        // // TODO: perhaps introduce a "prove_inner()" function
        // let (range_proof, _) = RangeProof::prove(
        //     range_proof_public_parameters,
        //     constrained_witnesses,
        //     commitment_randomnesses,
        //     &mut transcript,
        //     rng,
        // )?;

        // let (schnorr_proof, statements) =
        //     super::Proof::<REPETITIONS, Language, ProtocolContext>::prove(
        //         None,
        //         protocol_context,
        //         language_public_parameters,
        //         witnesses,
        //         rng,
        //     )?;
        //
        // Ok((
        //     Proof {
        //         schnorr_proof,
        //         range_proof,
        //     },
        //     statements,
        // ))

        todo!()
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof.
    pub fn verify(
        &self,
        number_of_parties: Option<usize>,
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        range_proof_public_parameters: &range::PublicParameters<
            MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        statements: Vec<Language::StatementSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<()> {
        todo!()
        // // TODO: here we should validate all the sizes are good etc. for example
        // WITNESS_MASK_LIMBS // // and RANGE_CLAIM_LIMBS and the message space thingy
        //
        // let mut transcript =
        //     Self::setup_range_proof(protocol_context, range_proof_public_parameters)?;
        //
        // let commitments: Vec<_> = statements
        //     .clone()
        //     .into_iter()
        //     .map(|statement| statement.range_proof_commitment().clone())
        //     .collect();
        //
        // // TODO: make sure I did the range test
        // // TODO: sum commitments in aggregation or something - maybe this can actually remove the
        // // multicommitment code?
        //
        // self.schnorr_proof
        //     .verify(
        //         number_of_parties,
        //         protocol_context,
        //         language_public_parameters,
        //         statements,
        //     )
        //     .and(self.range_proof.verify(
        //         range_proof_public_parameters,
        //         commitments,
        //         &mut transcript,
        //         rng,
        //     ))
    }

    fn setup_range_proof(
        protocol_context: &ProtocolContext,
        range_proof_public_parameters: &range::PublicParameters<
            MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
    ) -> proofs::Result<Transcript> {
        // TODO: choice of parameters, batching conversation in airport.
        // if WITNESS_MASK_LIMBS
        //     != RANGE_CLAIM_LIMBS
        //         + super::ChallengeSizedNumber::LIMBS
        //         + StatisticalSecuritySizedNumber::LIMBS
        //     || WITNESS_MASK_LIMBS > RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
        //     || Uint::<RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(
        //         &Uint::<WITNESS_MASK_LIMBS>::MAX,
        //     ) >= language::enhanced::RangeProofCommitmentSchemeMessageSpaceGroupElement::<
        //       RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS,
        //       RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Language,
        //     >::scalar_lower_bound_from_public_parameters(
        //         &range_proof_public_parameters
        //             .as_ref()
        //             .as_ref()
        //             .message_space_public_parameters,
        //     )
        // {
        //     // TODO: the lower bound check fails
        //     // TODO: dedicated error?
        //     return Err(Error::InvalidParameters);
        // }

        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        transcript.append_message(
            b"range proof used for the enhanced Schnorr proof",
            RangeProof::NAME.as_bytes(),
        );

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        Ok(transcript)
    }
}

// TODO: work out enhanced proofs, then fix tests

// TODO: DRY these tests code, perhaps using a trait for a Proof.

// #[cfg(any(test, feature = "benchmarking"))]
// pub(crate) mod tests {
//     use std::{array, iter, marker::PhantomData};
//
//     use crypto_bigint::{Random, Wrapping, U128, U256};
//     use rand_core::OsRng;
//
//     use super::*;
//     use crate::{
//         group::{ristretto, secp256k1},
//         proofs::{
//             range,
//             range::RangeProof,
//             schnorr::{enhanced, language},
//         },
//         ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
//     };
//
//     pub(crate) fn generate_valid_proof<
//         const NUM_RANGE_CLAIMS: usize,
//         Scalar: BoundedGroupElement<SCALAR_LIMBS>,
//         GroupElement: BoundedGroupElement<SCALAR_LIMBS>,
//         Lang: EnhancedLanguage<NUM_RANGE_CLAIMS, SCALAR_LIMBS, Scalar, GroupElement>,
//     >(
//         language_public_parameters: &Lang::PublicParameters,
//         range_proof_public_parameters: &language::enhanced::RangeProofPublicParameters<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//         >,
//         witnesses: Vec<Lang::WitnessSpaceGroupElement>,
//     ) -> (
//         enhanced::Proof<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//             PhantomData<()>,
//         >,
//         Vec<Lang::StatementSpaceGroupElement>,
//     )
//     where
//         Uint<RANGE_CLAIM_LIMBS>: Encoding,
//         Uint<SCALAR_LIMBS>: Encoding,
//     {
//         enhanced::Proof::prove(
//             &PhantomData,
//             language_public_parameters,
//             range_proof_public_parameters,
//             witnesses,
//             &mut OsRng,
//         )
//         .unwrap()
//     }
//
//     #[allow(dead_code)]
//     pub(crate) fn valid_proof_verifies<
//         const REPETITIONS: usize,
//         const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
//         const NUM_RANGE_CLAIMS: usize,
//         const RANGE_CLAIM_LIMBS: usize,
//         const SCALAR_LIMBS: usize,
//         Lang: EnhancedLanguage<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//         >,
//     >(
//         language_public_parameters: &Lang::PublicParameters,
//         range_proof_public_parameters: &RangeProofPublicParameters<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//         >,
//         batch_size: usize,
//     ) where
//         Uint<RANGE_CLAIM_LIMBS>: Encoding,
//         Uint<SCALAR_LIMBS>: Encoding,
//     {
//         let witnesses = generate_witnesses::<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//         >(language_public_parameters, batch_size);
//
//         let (proof, statements) = generate_valid_proof::<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//         >(
//             language_public_parameters,
//             range_proof_public_parameters,
//             witnesses.clone(),
//         );
//
//         let res = proof.verify(
//             None,
//             &PhantomData,
//             language_public_parameters,
//             range_proof_public_parameters,
//             statements,
//             &mut OsRng,
//         );
//
//         assert!(
//             res.is_ok(),
//             "valid enhanced proofs should verify, got error: {:?}",
//             res.err().unwrap()
//         );
//     }
//
//     #[allow(dead_code)]
//     pub(crate) fn proof_with_out_of_range_witness_fails<
//         const REPETITIONS: usize,
//         const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
//         const NUM_RANGE_CLAIMS: usize,
//         const RANGE_CLAIM_LIMBS: usize,
//         const SCALAR_LIMBS: usize,
//         Lang: EnhancedLanguage<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//         >,
//     >(
//         language_public_parameters: &Lang::PublicParameters,
//         range_proof_public_parameters: &RangeProofPublicParameters<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//         >,
//         batch_size: usize,
//     ) where
//         Uint<RANGE_CLAIM_LIMBS>: Encoding,
//         Uint<SCALAR_LIMBS>: Encoding,
//     {
//         let mut witnesses = generate_witnesses::<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//         >(language_public_parameters, batch_size);
//
//         let (constrained_witnesses, commitment_randomness, unbounded_witness) =
//             witnesses.first().unwrap().clone().into();
//         let mut constrained_witnesses: [power_of_two_moduli::GroupElement<SCALAR_LIMBS>;
//             NUM_RANGE_CLAIMS] = constrained_witnesses.into();
//
//         // just out of range by 1
//         constrained_witnesses[0] = power_of_two_moduli::GroupElement::new(
//             (Uint::<SCALAR_LIMBS>::MAX
//                 >> (Uint::<SCALAR_LIMBS>::BITS
//                     - <range::bulletproofs::RangeProof as RangeProof< {ristretto::SCALAR_LIMBS //
//                       }, { range::bulletproofs::RANGE_CLAIM_LIMBS },
//                     >>::RANGE_CLAIM_BITS))
//                 .wrapping_add(&Uint::<SCALAR_LIMBS>::ONE),
//             &constrained_witnesses[0].public_parameters(),
//         )
//         .unwrap();
//
//         let out_of_range_witness = (
//             constrained_witnesses.into(),
//             commitment_randomness,
//             unbounded_witness,
//         )
//             .into();
//
//         witnesses[0] = out_of_range_witness;
//
//         let (proof, statements) = generate_valid_proof::<
//             REPETITIONS,
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             NUM_RANGE_CLAIMS,
//             RANGE_CLAIM_LIMBS,
//             SCALAR_LIMBS,
//             Lang,
//         >(
//             language_public_parameters,
//             range_proof_public_parameters,
//             witnesses.clone(),
//         );
//
//         assert!(
//             matches!(
//                 proof
//                     .verify(
//                         None,
//                         &PhantomData,
//                         language_public_parameters,
//                         range_proof_public_parameters,
//                         statements,
//                         &mut OsRng,
//                     )
//                     .err()
//                     .unwrap(),
//                 proofs::Error::Bulletproofs(bulletproofs::ProofError::VerificationError)
//             ),
//             "out of range error should fail on range verification"
//         );
//     }
// }
