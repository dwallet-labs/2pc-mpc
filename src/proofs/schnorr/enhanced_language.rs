// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{Encoding, Uint};

use crate::{group, proofs};
use crate::group::{direct_product, GroupElement, Samplable, self_product};
use crate::group::additive_group_of_integers_modulu_n::power_of_two_moduli;
use crate::proofs::range;

use super::GroupsPublicParameters;
use super::language::{
    PublicParameters, StatementSpaceGroupElement, StatementSpacePublicParameters,
    WitnessSpaceGroupElement, WitnessSpacePublicParameters,
};

pub mod committed_linear_evaluation;
pub mod encryption_of_discrete_log;

pub type EnhancedLanguageWitness<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = direct_product::ThreeWayGroupElement<
    self_product::GroupElement<
        NUM_RANGE_CLAIMS,
        power_of_two_moduli::GroupElement<RANGE_CLAIM_LIMBS>, // TODO: change to witness mask limb
    >,
    RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS, // TODO: change to witness mask limb
        L
    >,
    UnconstrainedWitnessSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>,
>;

pub type EnhancedLanguageStatement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = direct_product::GroupElement<
    RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        L,
    >,
    RemainingStatementSpaceGroupElement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        L,
    >,
>;

/// An Enhacned Schnorr Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof` with range claims.
/// As defined in Appendix B. Schnorr Protocols in the paper.
pub trait EnhancedLanguage<
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims
    const RANGE_CLAIM_LIMBS: usize,
>: super::Language<
    WitnessSpaceGroupElement=EnhancedLanguageWitness<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        Self
    >,
    StatementSpaceGroupElement=EnhancedLanguageStatement<
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        Self
    >>
    where Uint<RANGE_CLAIM_LIMBS>: Encoding,
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
    const RANGE_CLAIM_LIMBS: usize,
    L
> = <L as EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::UnboundedWitnessSpaceGroupElement;

pub type UnboundedWitnessSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = group::PublicParameters<UnconstrainedWitnessSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;
pub type UnboundedWitnessSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = group::Value<UnconstrainedWitnessSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RemainingStatementSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = <L as EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::RemainingStatementSpaceGroupElement;

pub type RemainingStatementSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = group::PublicParameters<RemainingStatementSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;
pub type RemainingStatementSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = group::Value<RemainingStatementSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProof<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    L
> = <L as EnhancedLanguage<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>>::RangeProof;

pub type RangeProofCommitmentScheme<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentScheme<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemePublicParameters<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeMessageSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeMessageSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeMessageSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeMessageSpacePublicParameters<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeMessageSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeMessageSpaceValue<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeRandomnessSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeRandomnessSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeRandomnessSpacePublicParameters<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeRandomnessSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeRandomnessSpaceValue<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeCommitmentSpaceGroupElement<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;


pub type RangeProofCommitmentSchemeCommitmentSpacePublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeCommitmentSpacePublicParameters<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;

pub type RangeProofCommitmentSchemeCommitmentSpaceValue<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize, L> = range::CommitmentSchemeCommitmentSpaceValue<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, RangeProof<NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS, L>>;
