// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::array;
use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;
use tiresias::secret_sharing::shamir::Polynomial;

use crate::{
    ahe,
    commitments::{pedersen, HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product,
        direct_product::ThreeWayPublicParameters, paillier, self_product, BoundedGroupElement,
        GroupElement as _, KnownOrderScalar, Samplable,
    },
    helpers::flat_map_results,
    proofs,
    proofs::{schnorr, schnorr::language::GroupsPublicParameters},
};

pub const REPETITIONS: usize = 1;

// TODO: do this generically for encryption key and range proof.

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
        Scalar: BoundedGroupElement<SCALAR_LIMBS>
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Samplable
            + Copy,
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
    Scalar::Value: From<Uint<SCALAR_LIMBS>>,
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
        GroupElement::Value,
        UnboundedWitnessSpaceGroupElement::PublicParameters,
        group::PublicParameters<Language::StatementSpaceGroupElement>,
        Language::PublicParameters,
    >;
    const NAME: &'static str = Language::NAME;

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &Self::PublicParameters,
    ) -> crate::proofs::Result<Self::StatementSpaceGroupElement> {
        let language_witness = Language::convert_witness(
            witness.constrained_witness(),
            witness.unbounded_witness(),
            &enhanced_language_public_parameters.language_public_parameters,
        )?;

        let language_statement = Language::group_homomorphism(
            &language_witness,
            &enhanced_language_public_parameters.language_public_parameters,
        )?;

        let commitment_message: [Scalar; NUM_RANGE_CLAIMS] = flat_map_results(
            <&[_; NUM_RANGE_CLAIMS]>::from(witness.constrained_witness()).map(
                |constrained_witness_part| {
                    let constrained_witness_part: Uint<SCALAR_LIMBS> =
                        constrained_witness_part.into();

                    Scalar::new(
                        constrained_witness_part.into(),
                        enhanced_language_public_parameters.scalar_public_parameters(),
                    )
                },
            ),
        )?;

        let pedersen =
            Pedersen::new(&enhanced_language_public_parameters.pedersen_public_parameters)?;

        let range_proof_commitment = pedersen.commit(
            &commitment_message.into(),
            witness.range_proof_commitment_randomness(),
        );

        Ok((range_proof_commitment, language_statement).into())
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
    fn convert_witness(
        constrained_witness: &ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
        unbounded_witness: &UnboundedWitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement>;
}

// TODO: perhaps this could just be in `enhanced` and use any encryption key.
// TODO: in rlwe, message space is Scalar and the randomness is Rq
// so the range check needs to happen on the randomness element not the plaintext.
// TODO: does this have to be known order scalar?
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
        constrained_witness: &ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS>,
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

        let witness_in_witness_mask_base: &[_; RANGE_CLAIMS_PER_SCALAR] =
            constrained_witness.into();

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
    GroupPublicParameters,
    GroupElementValue,
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
            GroupPublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    >,
    pub pedersen_public_parameters: pedersen::PublicParameters<
        NUM_RANGE_CLAIMS,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
    pub language_public_parameters: LanguagePublicParameters,
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
    PublicParameters<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    // todo
    // pub fn new();

    pub fn scalar_public_parameters(&self) -> &ScalarPublicParameters {
        let (_, scalar_public_parameters, _) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        scalar_public_parameters
    }
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
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
                GroupPublicParameters,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    >
    for PublicParameters<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
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
            GroupPublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    > {
        &self.groups_public_parameters
    }
}

pub trait EnhancedLanguageWitnessAccessors<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
    Scalar: BoundedGroupElement<SCALAR_LIMBS>,
    UnboundedWitnessSpaceGroupElement: group::GroupElement,
>
{
    fn constrained_witness(
        &self,
    ) -> &ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS>;

    fn range_proof_commitment_randomness(&self) -> &Scalar;

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement;
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        Scalar: BoundedGroupElement<SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement,
    >
    EnhancedLanguageWitnessAccessors<
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        Scalar,
        UnboundedWitnessSpaceGroupElement,
    >
    for direct_product::ThreeWayGroupElement<
        ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS>,
        Scalar,
        UnboundedWitnessSpaceGroupElement,
    >
{
    fn constrained_witness(
        &self,
    ) -> &ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, SCALAR_LIMBS> {
        let (constrained_witness, ..): (_, _, _) = self.into();

        constrained_witness
    }

    fn range_proof_commitment_randomness(&self) -> &Scalar {
        let (_, randomness, _) = self.into();

        randomness
    }

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement {
        let (_, _, unbounded_witness) = self.into();

        unbounded_witness
    }
}

pub trait EnhancedLanguageStatementAccessors<
    GroupElement: group::GroupElement,
    LanguageStatementSpaceGroupElement: group::GroupElement,
>
{
    fn range_proof_commitment(&self) -> &GroupElement;

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement;
}

impl<
        GroupElement: group::GroupElement,
        LanguageStatementSpaceGroupElement: group::GroupElement,
    > EnhancedLanguageStatementAccessors<GroupElement, LanguageStatementSpaceGroupElement>
    for direct_product::GroupElement<GroupElement, LanguageStatementSpaceGroupElement>
{
    fn range_proof_commitment(&self) -> &GroupElement {
        let (range_proof_commitment, _) = self.into();

        range_proof_commitment
    }

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement {
        let (_, language_statement) = self.into();

        language_statement
    }
}

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    pub const RANGE_CLAIMS_PER_SCALAR: usize = 2;
}
