// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Mul;

use crypto_bigint::{Encoding, Uint};
use tiresias::secret_sharing::shamir::Polynomial;

use crate::{
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, self_product,
        BoundedGroupElement, GroupElement, Samplable,
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
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = direct_product::ThreeWayGroupElement<
    ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, WITNESS_MASK_LIMBS>,
    RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
    UnconstrainedWitnessSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type EnhancedLanguageStatement<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = direct_product::GroupElement<
    RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
    RemainingStatementSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

/// An Enhacned Schnorr Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof` with range claims.
/// As defined in Appendix B. Schnorr Protocols in the paper.
pub trait EnhancedLanguage<
    // The range proof commitment scheme's message space scalar size in limbs
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // An upper bound over the range claims
    const RANGE_CLAIM_LIMBS: usize,
    // The size of the witness mask. Must be equal to RANGE_CLAIM_LIMBS + ComputationalSecuritySizedNumber::LIMBS + StatisticalSecuritySizedNumber::LIMBS
    const WITNESS_MASK_LIMBS: usize,
>: super::Language<
    WitnessSpaceGroupElement=EnhancedLanguageWitness<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        Self
    >,
    StatementSpaceGroupElement=EnhancedLanguageStatement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
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
    type RangeProof: proofs::RangeProof<RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, RANGE_CLAIM_LIMBS>;
}

fn witness_mask_base_to_scalar<
    const RANGE_CLAIMS_PER_WITNESS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    Scalar: BoundedGroupElement<SCALAR_LIMBS> + Copy + Mul<Scalar, Output = Scalar>,
>(
    witness_in_witness_mask_base: [Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_WITNESS],
    scalar_group_public_parameters: &group::PublicParameters<Scalar>,
) -> proofs::Result<Scalar>
where
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
{
    // TODO: perform all the checks here, checking add - also check that no modulation occurs in
    // LIMBS for the entire computation

    // TODO: RANGE_CLAIM_LIMBS < SCALAR_LIMBS
    let delta: Uint<SCALAR_LIMBS> =
        Uint::<SCALAR_LIMBS>::from(&Uint::<RANGE_CLAIM_LIMBS>::MAX).wrapping_add(&1u64.into());

    let delta = Scalar::new(delta.into(), scalar_group_public_parameters)?;

    // TODO: WITNESS_MASK_LIMBS < SCALAR_LIMBS
    let witness_in_witness_mask_base: group::Result<Vec<Scalar>> = witness_in_witness_mask_base
        .into_iter()
        .map(|witness| {
            Scalar::new(
                Uint::<SCALAR_LIMBS>::from(&witness).into(),
                scalar_group_public_parameters,
            )
        })
        .collect();

    let polynomial = Polynomial::try_from(witness_in_witness_mask_base?)
        .map_err(|_| proofs::Error::InvalidParameters)?;

    Ok(polynomial.evaluate(&delta))
}

pub type UnconstrainedWitnessSpaceGroupElement<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = <L as EnhancedLanguage<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    WITNESS_MASK_LIMBS,
>>::UnboundedWitnessSpaceGroupElement;

pub type UnboundedWitnessSpacePublicParameters<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::PublicParameters<
    UnconstrainedWitnessSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;
pub type UnboundedWitnessSpaceValue<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::Value<
    UnconstrainedWitnessSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RemainingStatementSpaceGroupElement<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = <L as EnhancedLanguage<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    WITNESS_MASK_LIMBS,
>>::RemainingStatementSpaceGroupElement;

pub type RemainingStatementSpacePublicParameters<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::PublicParameters<
    RemainingStatementSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;
pub type RemainingStatementSpaceValue<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = group::Value<
    RemainingStatementSpaceGroupElement<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProof<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = <L as EnhancedLanguage<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    WITNESS_MASK_LIMBS,
>>::RangeProof;

pub type RangeProofPublicParameters<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::PublicParameters<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentScheme<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentScheme<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemePublicParameters<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemePublicParameters<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeMessageSpaceGroupElement<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeMessageSpaceGroupElement<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeMessageSpacePublicParameters<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeMessageSpacePublicParameters<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeMessageSpaceValue<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeMessageSpaceValue<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeRandomnessSpaceGroupElement<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeRandomnessSpaceGroupElement<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeRandomnessSpacePublicParameters<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeRandomnessSpacePublicParameters<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeRandomnessSpaceValue<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeRandomnessSpaceValue<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeCommitmentSpaceGroupElement<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeCommitmentSpaceGroupElement<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeCommitmentSpacePublicParameters<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeCommitmentSpacePublicParameters<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

pub type RangeProofCommitmentSchemeCommitmentSpaceValue<
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    L,
> = range::CommitmentSchemeCommitmentSpaceValue<
    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    NUM_RANGE_CLAIMS,
    RANGE_CLAIM_LIMBS,
    RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        L,
    >,
>;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::{array, iter, marker::PhantomData};

    use crypto_bigint::Random;
    use rand_core::OsRng;

    use super::*;
    use crate::{
        proofs::schnorr::{
            enhanced, language,
            language::{
                StatementSpaceGroupElement, WitnessSpaceGroupElement, WitnessSpacePublicParameters,
            },
        },
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    // TODO: challenge instead of computational?
    pub(crate) const WITNESS_MASK_LIMBS: usize = range::bulletproofs::RANGE_CLAIM_LIMBS
        + ComputationalSecuritySizedNumber::LIMBS
        + StatisticalSecuritySizedNumber::LIMBS;

    pub(crate) const RANGE_CLAIMS_PER_SCALAR: usize = 4;

    pub(crate) fn generate_witnesses<
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Lang: EnhancedLanguage<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
        >,
    >(
        witness_space_public_parameters: &WitnessSpacePublicParameters<Lang>,
        batch_size: usize,
    ) -> Vec<WitnessSpaceGroupElement<Lang>>
    where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        Uint<WITNESS_MASK_LIMBS>: Encoding,
    {
        iter::repeat_with(|| {
            let (_, commitment_randomness, unconstrained_witness) =
                WitnessSpaceGroupElement::<Lang>::sample(
                    &mut OsRng,
                    &witness_space_public_parameters,
                )
                .unwrap()
                .into();

            (
                array::from_fn(|_| {
                    Uint::<{ WITNESS_MASK_LIMBS }>::from(&Uint::<RANGE_CLAIM_LIMBS>::random(
                        &mut OsRng,
                    ))
                    .into()
                })
                .into(),
                commitment_randomness,
                unconstrained_witness,
            )
                .into()
        })
        .take(batch_size)
        .collect()
    }

    pub(crate) fn generate_valid_proof<
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Lang: EnhancedLanguage<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
        >,
    >(
        language_public_parameters: &Lang::PublicParameters,
        range_proof_public_parameters: &language::enhanced::RangeProofPublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
        >,
        witnesses: Vec<WitnessSpaceGroupElement<Lang>>,
    ) -> (
        enhanced::Proof<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
            PhantomData<()>,
        >,
        Vec<StatementSpaceGroupElement<Lang>>,
    )
    where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        Uint<WITNESS_MASK_LIMBS>: Encoding,
    {
        enhanced::Proof::prove(
            &PhantomData,
            language_public_parameters,
            range_proof_public_parameters,
            witnesses,
            &mut OsRng,
        )
        .unwrap()
    }

    #[allow(dead_code)]
    pub(crate) fn valid_proof_verifies<
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Lang: EnhancedLanguage<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
        >,
    >(
        language_public_parameters: &Lang::PublicParameters,
        range_proof_public_parameters: &RangeProofPublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
        >,
        batch_size: usize,
    ) where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        Uint<WITNESS_MASK_LIMBS>: Encoding,
    {
        let witnesses = generate_witnesses::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
        >(
            &language_public_parameters
                .as_ref()
                .witness_space_public_parameters,
            batch_size,
        );

        let (proof, statements) = generate_valid_proof::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
        >(
            language_public_parameters,
            range_proof_public_parameters,
            witnesses.clone(),
        );

        let res = proof.verify(
            &PhantomData,
            language_public_parameters,
            range_proof_public_parameters,
            statements,
            &mut OsRng,
        );

        assert!(
            res.is_ok(),
            "valid enhanced proofs should verify, got error: {:?}",
            res.err().unwrap()
        );
    }

    #[allow(dead_code)]
    pub(crate) fn proof_with_out_of_range_witness_fails<
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        Lang: EnhancedLanguage<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
        >,
    >(
        language_public_parameters: &Lang::PublicParameters,
        range_proof_public_parameters: &RangeProofPublicParameters<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
        >,
        batch_size: usize,
    ) where
        Uint<RANGE_CLAIM_LIMBS>: Encoding,
        Uint<WITNESS_MASK_LIMBS>: Encoding,
    {
        let mut witnesses = generate_witnesses::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
        >(
            &language_public_parameters
                .as_ref()
                .witness_space_public_parameters,
            batch_size,
        );

        let (constrained_witnesses, commitment_randomness, unconstrained_witness) =
            witnesses.first().unwrap().clone().into();
        let mut constrained_witnesses: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>;
            NUM_RANGE_CLAIMS] = constrained_witnesses.into();
        // just out of range by 1
        constrained_witnesses[0] =
            Uint::<{ WITNESS_MASK_LIMBS }>::from(&Uint::<RANGE_CLAIM_LIMBS>::MAX)
                .wrapping_add(&Uint::<WITNESS_MASK_LIMBS>::ONE)
                .into();
        let out_of_range_witness = (
            constrained_witnesses.into(),
            commitment_randomness,
            unconstrained_witness,
        )
            .into();

        witnesses[0] = out_of_range_witness;

        let (proof, statements) = generate_valid_proof::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            Lang,
        >(
            language_public_parameters,
            range_proof_public_parameters,
            witnesses.clone(),
        );

        assert!(
            matches!(
                proof
                    .verify(
                        &PhantomData,
                        language_public_parameters,
                        range_proof_public_parameters,
                        statements,
                        &mut OsRng,
                    )
                    .err()
                    .unwrap(),
                proofs::Error::Bulletproofs(bulletproofs::ProofError::VerificationError)
            ),
            "out of range error should fail on range verification"
        );
    }
}
