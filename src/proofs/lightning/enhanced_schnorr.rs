// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use crate::{
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product,
        direct_product::ThreeWayPublicParameters, self_product, BoundedGroupElement, Samplable,
    },
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

impl<
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        Scalar: BoundedGroupElement<SCALAR_LIMBS> + Samplable,
        GroupElement: BoundedGroupElement<SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhancableLanguage<
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

pub(in crate::proofs) trait EnhancableLanguage<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    Scalar: BoundedGroupElement<SCALAR_LIMBS>,
    UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
>: schnorr::Language<REPETITIONS>
{
    // TODO: name?
    // TODO: return Result?
    // TODO: params, maybe seperate, and have constrained and unbounded, and thats it because
    // randomness is for the commitment of the rangeproof?
    fn convert_witness(
        enhanced_witness: EnhancedLanguageWitness<
            NUM_RANGE_CLAIMS,
            SCALAR_LIMBS,
            Scalar,
            UnboundedWitnessSpaceGroupElement,
        >,
    ) -> Self::WitnessSpaceGroupElement;

    // TODO: helper functions to parse and convert

    // TODO: what to do with plaintext element? whose responsability?

    // TODO: also get encryption randomness? should we encrypt here?
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
