// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{Encoding, Uint};

use super::{
    language::{
        PublicParameters, StatementSpaceGroupElement, StatementSpacePublicParameters,
        WitnessSpaceGroupElement, WitnessSpacePublicParameters,
    },
    GroupsPublicParameters,
};
use crate::{
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        GroupElement, Samplable,
    },
    proofs,
    proofs::range,
};

pub mod committed_linear_evaluation;
pub mod encryption_of_discrete_log;

pub type ConstrainedWitnessGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const WITNESS_MASK_LIMBS: usize,
> = self_product::GroupElement<
    NUM_RANGE_CLAIMS,
    power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>,
>;
pub type ConstrainedWitnessValue<const NUM_RANGE_CLAIMS: usize, const WITNESS_MASK_LIMBS: usize> =
    group::Value<
        self_product::GroupElement<
            NUM_RANGE_CLAIMS,
            power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>,
        >,
    >;
pub type ConstrainedWitnessPublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const WITNESS_MASK_LIMBS: usize,
> = group::PublicParameters<
    self_product::GroupElement<
        NUM_RANGE_CLAIMS,
        power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>,
    >,
>;

// - our witness is [WITNESS_MASK_LIMBS; NUM_RANGE_CLAIMS]
// in the case of the real witness, we pass NUM_RANGE_CLAIMS and think of it as WITNESS_MASK_LIMBS.
// But in the case of the witness mask, we actually pass it as WITNESS_MASK_LIMBS and it is of that
// size.
pub type EnhancedLanguageWitness<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = direct_product::ThreeWayGroupElement<
    ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, WITNESS_MASK_LIMBS>,
    RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
    UnconstrainedWitnessSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

// Now in the statement of the homomorphism of the enhanced schnorr language, we have
// the commitment of the range proof. Since the range proof know only RANGE_CLAIM_LIMBS,
// or even you can say, it only knows the MessageSpaceGroupElement=EC-SCALAR in bulletproof of that
// commitment, we need somehow to call .commit() with WITNESS_MASK_LIMBS numbers.
// - yes, we don't use that commit later for .prove_range(). So we don't care that proof will fail.
// But, we do use it in group_homomorhpism(), and I'm afraid it will go through modulation for the
// witness mask there. yes, but this is coupling !!!! it assumes more knowledge on the range proof.
// ??? what group? we were always talking about the Paillier encryption
// yes, I remember, but that was for optimizing the range proof Pedersen - for proving it secure
// without safe primes. no no, even if the witness is one bit, I can't do this...
// because you are coupling! we are using generic range proofs... stop coupling!
// ????????/
// i am always talking about bulletproofs - I am talking about the commitment scheme of the range
// proof. This is bulletproof. But it is the range proof - bulletproof - that defines this
// commitment scheme. not the schnorr lagnuage. but this is again coupling
// noooooooo
// I dont care if its 64 bit, 32 bit or whatever. Even the fact you are thinking of how many bits
// they are, it is coupling!!!! witness size + challenge (computational security ) size +
// statistical security < order of the message space of the commitment scheme of the range proof??
// because we cannot go through modulation for the masked witness in the commitment shceme? what
// will happen if we do? why ok. So we have coupling but we know it is well defined. That's ok.
// lets speak on the specific parameters. we have witness = 64, challenge = 128, statistical = 64.
// => 256 > q. so should use computational = 127? or I can simply repeat the proof if it fails.
// But it will fail with ±50% chance no? can you speak I didn't hear
// 50% = the probability of sampling a 256-bit with the MSB off
pub type EnhancedLanguageStatement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = direct_product::GroupElement<
    RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
    RemainingStatementSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

/// An Enhacned Schnorr Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof` with range claims.
/// As defined in Appendix B. Schnorr Protocols in the paper.
pub trait EnhancedLanguage<
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims
    const RANGE_CLAIM_LIMBS: usize,
    // The size of the witness mask. Must be equal to RANGE_CLAIM_LIMBS + ComputationalSecuritySizedNumber::LIMBS + StatisticalSecuritySizedNumber::LIMBS
    const WITNESS_MASK_LIMBS: usize,
>: super::Language<
    WitnessSpaceGroupElement = EnhancedLanguageWitness<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self
    >,
    StatementSpaceGroupElement = EnhancedLanguageStatement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self
    >>
    where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        Uint<WITNESS_MASK_LIMBS>: Encoding,
{
    /// The unconstrained part of the witness group element.
    type UnboundedWitnessSpaceGroupElement: GroupElement + Samplable;

    /// An element in the associated statement space, that will be the image of the homomorphism alongside the range proof commitment.
    type RemainingStatementSpaceGroupElement: GroupElement;

    /// The range proof used to prove the constrained witnesses are within the range specified in the public parameters.
    type RangeProof: proofs::RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>;
}

pub type UnconstrainedWitnessSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, const WITNESS_MASK_LIMBS: usize,
    L
> = <
    L as EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS>
>::UnboundedWitnessSpaceGroupElement;

pub type UnboundedWitnessSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::PublicParameters<
    UnconstrainedWitnessSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;
pub type UnboundedWitnessSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::Value<
    UnconstrainedWitnessSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RemainingStatementSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, const WITNESS_MASK_LIMBS: usize,
    L
> = <
    L as EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS>
>::RemainingStatementSpaceGroupElement;

pub type RemainingStatementSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::PublicParameters<
    RemainingStatementSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;
pub type RemainingStatementSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::Value<
    RemainingStatementSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProof<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = <L as EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS>>::RangeProof;

pub type RangeProofCommitmentScheme<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentScheme<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemePublicParameters<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeMessageSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeMessageSpaceGroupElement<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeMessageSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeMessageSpacePublicParameters<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeMessageSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeMessageSpaceValue<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeRandomnessSpaceGroupElement<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeRandomnessSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeRandomnessSpacePublicParameters<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeRandomnessSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeRandomnessSpaceValue<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeCommitmentSpaceGroupElement<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeCommitmentSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeCommitmentSpacePublicParameters<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;

pub type RangeProofCommitmentSchemeCommitmentSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeCommitmentSpaceValue<
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, L>,
>;
