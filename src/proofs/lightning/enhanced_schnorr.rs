// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::array;
use std::marker::PhantomData;

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;
use tiresias::secret_sharing::shamir::Polynomial;

use crate::{
    ahe, group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product,
        direct_product::ThreeWayPublicParameters, paillier, self_product, BoundedGroupElement,
        GroupElement as _, KnownOrderScalar, Samplable,
    },
    proofs,
    proofs::{schnorr, schnorr::language::GroupsPublicParameters},
};

pub const REPETITIONS: usize = 1;

#[derive(Clone, PartialEq)]
pub struct EnhancedLanguage<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    UnboundedWitnessSpaceGroupElement,
    Language,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _unbounded_witness_choice: PhantomData<UnboundedWitnessSpaceGroupElement>,
    _language_choice: PhantomData<Language>,
}

pub type ConstrainedWitnessGroupElement<const NUM_RANGE_CLAIMS: usize, const SCALAR_LIMBS: usize> =
    self_product::GroupElement<NUM_RANGE_CLAIMS, power_of_two_moduli::GroupElement<SCALAR_LIMBS>>;
pub type ConstrainedWitnessValue<const NUM_RANGE_CLAIMS: usize, const SCALAR_LIMBS: usize> =
    group::Value<
        self_product::GroupElement<
            NUM_RANGE_CLAIMS,
            power_of_two_moduli::GroupElement<SCALAR_LIMBS>,
        >,
    >;
pub type ConstrainedWitnessPublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
> = group::PublicParameters<
    self_product::GroupElement<NUM_RANGE_CLAIMS, power_of_two_moduli::GroupElement<SCALAR_LIMBS>>,
>;

pub type EnhancedLanguageWitness<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    Scalar: BoundedGroupElement<SCALAR_LIMBS>,
    UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
> = direct_product::ThreeWayGroupElement<
    ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
    Scalar,
    UnboundedWitnessSpaceGroupElement,
>;

pub type EnhancedLanguageStatement<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement: BoundedGroupElement<SCALAR_LIMBS>,
    Language: schnorr::Language<REPETITIONS>,
> = direct_product::GroupElement<GroupElement, Language::StatementSpaceGroupElement>;

// TODO: proper bounds security wise.
impl<
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        Scalar: BoundedGroupElement<SCALAR_LIMBS> + Samplable,
        GroupElement: BoundedGroupElement<SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            NUM_RANGE_CLAIMS,
            SCALAR_LIMBS,
            Scalar,
            UnboundedWitnessSpaceGroupElement,
        >,
    > schnorr::Language<REPETITIONS>
    for EnhancedLanguage<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        Scalar,
        GroupElement,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    type WitnessSpaceGroupElement = EnhancedLanguageWitness<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        Scalar,
        UnboundedWitnessSpaceGroupElement,
    >;
    type StatementSpaceGroupElement =
        EnhancedLanguageStatement<NUM_RANGE_CLAIMS, SCALAR_LIMBS, GroupElement, Language>;
    type PublicParameters = PublicParameters<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        UnboundedWitnessSpaceGroupElement::PublicParameters,
        group::PublicParameters<Language::StatementSpaceGroupElement>,
        Language::PublicParameters,
    >;
    const NAME: &'static str = Language::NAME;

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> crate::proofs::Result<Self::StatementSpaceGroupElement> {
        todo!()
    }
}

pub(in crate::proofs) trait EnhanceableLanguage<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    Scalar: BoundedGroupElement<SCALAR_LIMBS> + Samplable,
    UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
>: schnorr::Language<REPETITIONS>
{
    // TODO: name?
    // TODO: return Result?
    // TODO: params, maybe seperate, and have constrained and unbounded, and thats it because
    // randomness is for the commitment of the rangeproof?
    fn convert_witness(
        constrained_witness: ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
        unbounded_witness: UnboundedWitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement>;

    // TODO: helper functions to parse and convert

    // TODO: what to do with plaintext element? whose responsability?

    // TODO: also get encryption randomness? should we encrypt here?
}

// does this have to be known order scalar?
pub trait DecomposableWitness<const RANGE_CLAIMS_PER_SCALAR: usize, const SCALAR_LIMBS: usize>:
    KnownOrderScalar<SCALAR_LIMBS>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn decompose_into_constrained_witness(
        self,
        range_claim_bits: usize,
    ) -> ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS> {
        let witness: Uint<SCALAR_LIMBS> = self.into();

        let witness_in_range_claim_base: [power_of_two_moduli::GroupElement<SCALAR_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR] = array::from_fn(|i| {
            Uint::<SCALAR_LIMBS>::from(
                &((witness >> (i * range_claim_bits))
                    & ((Uint::<SCALAR_LIMBS>::ONE << range_claim_bits)
                        .wrapping_sub(&Uint::<SCALAR_LIMBS>::ONE))),
            )
            .into()
        });

        witness_in_range_claim_base.into()
    }

    fn compose_from_constrained_witness(
        constrained_witness: ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS>,
        plaintext_space_public_parameters: &paillier::PlaintextSpacePublicParameters,
        range_claim_bits: usize, // TODO:  ???
    ) -> proofs::Result<paillier::PlaintextSpaceGroupElement> {
        // TODO: perform all the checks here, checking add - also check that no modulation occursin
        // // LIMBS for the entire computation

        // TODO: RANGE_CLAIM_LIMBS < SCALAR_LIMBS
        // TODO: use RANGE_CLAIM_BITS instead?
        let delta: Uint<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }> =
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::ONE << range_claim_bits;

        let delta = paillier::PlaintextSpaceGroupElement::new(
            delta.into(),
            plaintext_space_public_parameters,
        )?;

        let witness_in_witness_mask_base: [_; RANGE_CLAIMS_PER_SCALAR] = constrained_witness.into();

        // TODO: SCALAR_LIMBS < PLAINTEXT_SPACE_SCALAR_LIMBS ?
        let witness_in_witness_mask_base = witness_in_witness_mask_base
            .into_iter()
            .map(|witness| {
                paillier::PlaintextSpaceGroupElement::new(
                    Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(
                        &Uint::<SCALAR_LIMBS>::from(witness),
                    )
                    .into(),
                    plaintext_space_public_parameters,
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let polynomial = Polynomial::try_from(witness_in_witness_mask_base)
            .map_err(|_| proofs::Error::InvalidParameters)?;

        Ok(polynomial.evaluate(&delta))
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const SCALAR_LIMBS: usize,
        Scalar: KnownOrderScalar<SCALAR_LIMBS>,
    > DecomposableWitness<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS> for Scalar
where
    Uint<SCALAR_LIMBS>: Encoding,
{
}

// TODO: accessors

#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    ScalarPublicParameters,
    GroupElementPublicParameters,
    UnboundedWitnessSpacePublicParameters,
    LanguageStatementSpacePublicParameters,
    LanguagePublicParameters,
> where
    Uint<SCALAR_LIMBS>: Encoding,
{
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            ConstrainedWitnessPublicParameters<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
            ScalarPublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            GroupElementPublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    >,
    pub language_public_parameters: LanguagePublicParameters,
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        ScalarPublicParameters,
        GroupElementPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::ThreeWayPublicParameters<
                ConstrainedWitnessPublicParameters<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
                ScalarPublicParameters,
                UnboundedWitnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                GroupElementPublicParameters,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    >
    for PublicParameters<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        ScalarPublicParameters,
        GroupElementPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        ThreeWayPublicParameters<
            ConstrainedWitnessPublicParameters<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
            ScalarPublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            GroupElementPublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    > {
        &self.groups_public_parameters
    }
}
