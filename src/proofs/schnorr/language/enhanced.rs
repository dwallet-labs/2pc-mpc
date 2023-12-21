// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::array;
use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{Encoding, Uint, U128};
use serde::Serialize;
use tiresias::secret_sharing::shamir::Polynomial;

use crate::{
    ahe, commitments,
    commitments::{
        pedersen, GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme, Pedersen,
    },
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product,
        direct_product::ThreeWayPublicParameters, paillier, self_product, BoundedGroupElement,
        GroupElement as _, GroupElement, KnownOrderScalar, Samplable, SamplableWithin,
    },
    helpers::flat_map_results,
    proofs,
    proofs::{
        range, schnorr,
        schnorr::{
            language,
            language::{GroupsPublicParameters, GroupsPublicParametersAccessors as _},
        },
    },
    ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
};

/// An Enhanced Schnorr Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof` with range claims.
/// As defined in Appendix B. Schnorr Protocols in the paper.
#[derive(Clone, PartialEq)]
pub struct EnhancedLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme,
    UnboundedWitnessSpaceGroupElement,
    Language,
> {
    _unbounded_witness_choice: PhantomData<UnboundedWitnessSpaceGroupElement>,
    _language_choice: PhantomData<Language>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

pub type ConstrainedWitnessGroupElement<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
> = self_product::GroupElement<
    NUM_RANGE_CLAIMS,
    power_of_two_moduli::GroupElement<MESSAGE_SPACE_SCALAR_LIMBS>,
>;

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + SamplableWithin,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    > schnorr::Language<REPETITIONS>
    for EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        MESSAGE_SPACE_SCALAR_LIMBS,
        CommitmentScheme,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
where
    Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
    group::Value<CommitmentScheme::MessageSpaceGroupElement>:
        From<[Uint<MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS]>,
{
    type WitnessSpaceGroupElement = direct_product::ThreeWayGroupElement<
        ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS>,
        CommitmentScheme::RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement = direct_product::GroupElement<
        CommitmentScheme::CommitmentSpaceGroupElement,
        Language::StatementSpaceGroupElement,
    >;

    type PublicParameters = PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        MESSAGE_SPACE_SCALAR_LIMBS,
        commitments::RandomnessSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
        commitments::CommitmentSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>,
        CommitmentScheme::PublicParameters,
        UnboundedWitnessSpaceGroupElement::PublicParameters,
        group::PublicParameters<Language::StatementSpaceGroupElement>,
        Language::PublicParameters,
    >;
    const NAME: &'static str = Language::NAME;

    fn randomizer_subrange(
        enhanced_language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<(
        Self::WitnessSpaceGroupElement,
        Self::WitnessSpaceGroupElement,
    )> {
        // TODO
        // let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
        // + ComputationalSecuritySizedNumber::BITS
        // + StatisticalSecuritySizedNumber::BITS;

        // TODO: check that this is < SCALAR_LIMBS?

        // TODO: formula + challenge : in lightning its 1, in bp 128
        let sampling_bit_size: usize = U128::BITS + StatisticalSecuritySizedNumber::BITS;

        let lower_bound =
            ([Uint::<MESSAGE_SPACE_SCALAR_LIMBS>::ZERO.into(); NUM_RANGE_CLAIMS]).into();

        let upper_bound = ([(Uint::<MESSAGE_SPACE_SCALAR_LIMBS>::ONE << sampling_bit_size)
            .wrapping_sub(&Uint::<MESSAGE_SPACE_SCALAR_LIMBS>::ONE)
            .into(); NUM_RANGE_CLAIMS])
            .into();

        let lower_bound = (
            lower_bound,
            CommitmentScheme::RandomnessSpaceGroupElement::lower_bound(
                enhanced_language_public_parameters
                    .commitment_scheme_public_parameters
                    .randomness_space_public_parameters(),
            )?,
            UnboundedWitnessSpaceGroupElement::lower_bound(
                enhanced_language_public_parameters.unbounded_witness_public_parameters(),
            )?,
        )
            .into();

        let upper_bound = (
            upper_bound,
            CommitmentScheme::RandomnessSpaceGroupElement::upper_bound(
                enhanced_language_public_parameters
                    .commitment_scheme_public_parameters
                    .randomness_space_public_parameters(),
            )?,
            UnboundedWitnessSpaceGroupElement::upper_bound(
                enhanced_language_public_parameters.unbounded_witness_public_parameters(),
            )?,
        )
            .into();

        Ok((lower_bound, upper_bound))
    }

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &Self::PublicParameters,
    ) -> crate::proofs::Result<Self::StatementSpaceGroupElement> {
        let language_witness = Language::compose_witness(
            witness.constrained_witness(),
            witness.unbounded_witness(),
            &enhanced_language_public_parameters.language_public_parameters,
        )?;

        let language_statement = Language::group_homomorphism(
            &language_witness,
            &enhanced_language_public_parameters.language_public_parameters,
        )?;

        let commitment_scheme = CommitmentScheme::new(
            &enhanced_language_public_parameters.commitment_scheme_public_parameters,
        )?;

        let commitment_message_value =
            <[_; NUM_RANGE_CLAIMS]>::from(witness.constrained_witness().value()).into();

        let commitment_message = CommitmentScheme::MessageSpaceGroupElement::new(
            commitment_message_value,
            enhanced_language_public_parameters
                .commitment_scheme_public_parameters
                .message_space_public_parameters(),
        )?;

        let range_proof_commitment = commitment_scheme.commit(
            &commitment_message,
            witness.range_proof_commitment_randomness(),
        );

        Ok((range_proof_commitment, language_statement).into())
    }
}

// TODO: use this code in protocols.
pub(crate) trait EnhanceableLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
>: schnorr::Language<REPETITIONS>
{
    // TODO: solve all these refs & clones, here and in accessors. Perhaps partial move is ok.
    fn compose_witness(
        constrained_witness: &ConstrainedWitnessGroupElement<
            NUM_RANGE_CLAIMS,
            MESSAGE_SPACE_SCALAR_LIMBS,
        >,
        unbounded_witness: &UnboundedWitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement>;

    fn decompose_witness(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<(
        ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement,
    )>;
}

pub trait DecomposableWitness<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const WITNESS_LIMBS: usize,
>: KnownOrderScalar<WITNESS_LIMBS> where
    Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<WITNESS_LIMBS>: Encoding,
    Self::Value: From<Uint<WITNESS_LIMBS>>,
{
    fn decompose(
        self,
        range_claim_bits: usize,
    ) -> ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, MESSAGE_SPACE_SCALAR_LIMBS> {
        // TODO: sanity checks, return result?
        let witness: Uint<WITNESS_LIMBS> = self.into();

        let witness_in_range_claim_base: [power_of_two_moduli::GroupElement<
            MESSAGE_SPACE_SCALAR_LIMBS,
        >; RANGE_CLAIMS_PER_SCALAR] = array::from_fn(|i| {
            Uint::<MESSAGE_SPACE_SCALAR_LIMBS>::from(
                &((witness >> (i * range_claim_bits))
                    & ((Uint::<WITNESS_LIMBS>::ONE << range_claim_bits)
                        .wrapping_sub(&Uint::<WITNESS_LIMBS>::ONE))),
            )
            .into()
        });

        witness_in_range_claim_base.into()
    }

    fn compose(
        constrained_witness: &ConstrainedWitnessGroupElement<
            RANGE_CLAIMS_PER_SCALAR,
            MESSAGE_SPACE_SCALAR_LIMBS,
        >,
        public_parameters: &Self::PublicParameters,
        range_claim_bits: usize, // TODO:  ???
    ) -> proofs::Result<Self> {
        // TODO: perform all the checks here, checking add - also check that no modulation occursin
        // // LIMBS for the entire computation

        // TODO: MESSAGE_SPACE_SCALAR_LIMBS < WITNESS_LIMBS
        let delta: Uint<WITNESS_LIMBS> = Uint::<WITNESS_LIMBS>::ONE << range_claim_bits;

        let delta = Self::new(delta.into(), public_parameters)?;

        let witness_in_witness_mask_base: &[_; RANGE_CLAIMS_PER_SCALAR] =
            constrained_witness.into();

        // TODO: WITNESS_LIMBS < PLAINTEXT_SPACE_SCALAR_LIMBS ?
        let witness_in_witness_mask_base = witness_in_witness_mask_base
            .into_iter()
            .map(|witness| {
                Self::new(
                    Uint::<WITNESS_LIMBS>::from(&Uint::<MESSAGE_SPACE_SCALAR_LIMBS>::from(witness))
                        .into(),
                    public_parameters,
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
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const WITNESS_LIMBS: usize,
        Witness: KnownOrderScalar<WITNESS_LIMBS>,
    > DecomposableWitness<RANGE_CLAIMS_PER_SCALAR, MESSAGE_SPACE_SCALAR_LIMBS, WITNESS_LIMBS>
    for Witness
where
    Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<WITNESS_LIMBS>: Encoding,
    Self::Value: From<Uint<WITNESS_LIMBS>>,
{
}

// TODO: accessors

#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
    UnboundedWitnessSpacePublicParameters,
    LanguageStatementSpacePublicParameters,
    LanguagePublicParameters,
> where
    Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
{
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            group::PublicParameters<
                ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS>,
            >,
            RandomnessSpacePublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CommitmentSpacePublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub language_public_parameters: LanguagePublicParameters,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters: Clone,
        LanguagePublicParameters,
    >
    PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        MESSAGE_SPACE_SCALAR_LIMBS,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
where
    Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
{
    pub fn new<CommitmentScheme, UnboundedWitnessSpaceGroupElement, Language>(
        unbounded_witness_public_parameters: UnboundedWitnessSpacePublicParameters,
        commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
        language_public_parameters: LanguagePublicParameters,
    ) -> Self
    where
        Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
        CommitmentScheme: HomomorphicCommitmentScheme<
            MESSAGE_SPACE_SCALAR_LIMBS,
            PublicParameters = CommitmentSchemePublicParameters,
        >,
        CommitmentScheme::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentScheme::CommitmentSpaceGroupElement:
            group::GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        CommitmentSchemePublicParameters: AsRef<
            commitments::GroupsPublicParameters<
                group::PublicParameters<CommitmentScheme::MessageSpaceGroupElement>,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
        UnboundedWitnessSpaceGroupElement:
            group::GroupElement<PublicParameters = UnboundedWitnessSpacePublicParameters>,
        Language: language::Language<REPETITIONS, PublicParameters = LanguagePublicParameters>,
        LanguagePublicParameters: AsRef<
            GroupsPublicParameters<
                group::PublicParameters<Language::WitnessSpaceGroupElement>,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    {
        let constrained_witness_public_parameters =
            self_product::PublicParameters::<NUM_RANGE_CLAIMS, _>::new(());

        Self {
            groups_public_parameters: language::GroupsPublicParameters {
                witness_space_public_parameters: (
                    constrained_witness_public_parameters,
                    commitment_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                    unbounded_witness_public_parameters,
                )
                    .into(),
                statement_space_public_parameters: (
                    commitment_scheme_public_parameters
                        .commitment_space_public_parameters()
                        .clone(),
                    language_public_parameters
                        .statement_space_public_parameters()
                        .clone(),
                )
                    .into(),
            },
            commitment_scheme_public_parameters,
            language_public_parameters,
        }
    }

    pub fn unbounded_witness_public_parameters(&self) -> &UnboundedWitnessSpacePublicParameters {
        let (_, _, unbounded_witness_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        unbounded_witness_public_parameters
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::ThreeWayPublicParameters<
                group::PublicParameters<
                    ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS>,
                >,
                RandomnessSpacePublicParameters,
                UnboundedWitnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CommitmentSpacePublicParameters,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    >
    for PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        MESSAGE_SPACE_SCALAR_LIMBS,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
where
    Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            group::PublicParameters<
                ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS>,
            >,
            RandomnessSpacePublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CommitmentSpacePublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    > {
        &self.groups_public_parameters
    }
}

pub trait EnhancedLanguageWitnessAccessors<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RandomnessSpaceGroupElement: group::GroupElement,
    UnboundedWitnessSpaceGroupElement: group::GroupElement,
>
{
    fn constrained_witness(
        &self,
    ) -> &ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS>;

    fn range_proof_commitment_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement;
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RandomnessSpaceGroupElement: group::GroupElement,
        UnboundedWitnessSpaceGroupElement: group::GroupElement,
    >
    EnhancedLanguageWitnessAccessors<
        NUM_RANGE_CLAIMS,
        MESSAGE_SPACE_SCALAR_LIMBS,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
    for direct_product::ThreeWayGroupElement<
        ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS>,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
{
    fn constrained_witness(
        &self,
    ) -> &ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, MESSAGE_SPACE_SCALAR_LIMBS> {
        let (constrained_witness, ..): (_, _, _) = self.into();

        constrained_witness
    }

    fn range_proof_commitment_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness, _) = self.into();

        randomness
    }

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement {
        let (_, _, unbounded_witness) = self.into();

        unbounded_witness
    }
}

pub trait EnhancedLanguageStatementAccessors<
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
    LanguageStatementSpaceGroupElement: group::GroupElement,
>
{
    fn range_proof_commitment(&self) -> &CommitmentScheme::CommitmentSpaceGroupElement;

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement;
}

impl<
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
        LanguageStatementSpaceGroupElement: group::GroupElement,
    >
    EnhancedLanguageStatementAccessors<
        MESSAGE_SPACE_SCALAR_LIMBS,
        CommitmentScheme,
        LanguageStatementSpaceGroupElement,
    >
    for direct_product::GroupElement<
        CommitmentScheme::CommitmentSpaceGroupElement,
        LanguageStatementSpaceGroupElement,
    >
{
    fn range_proof_commitment(&self) -> &CommitmentScheme::CommitmentSpaceGroupElement {
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
    use ahe::paillier::tests::N;
    use crypto_bigint::U256;
    use rand_core::OsRng;

    use super::*;
    use crate::{ahe::GroupsPublicParametersAccessors, group::secp256k1};

    pub const RANGE_CLAIMS_PER_SCALAR: usize = { secp256k1::SCALAR_LIMBS / U128::LIMBS }; // TODO: proper range claims bits

    type EnhancedLang<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement,
        Lang,
    > = EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { secp256k1::SCALAR_LIMBS },
        Pedersen<
            NUM_RANGE_CLAIMS,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >,
        UnboundedWitnessSpaceGroupElement,
        Lang,
    >;

    pub fn scalar_lower_bound() -> paillier::PlaintextSpaceGroupElement {
        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        paillier::PlaintextSpaceGroupElement::new(
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::ZERO,
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap()
    }

    pub fn scalar_upper_bound() -> paillier::PlaintextSpaceGroupElement {
        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        paillier::PlaintextSpaceGroupElement::new(
            (&secp256k1::ORDER.wrapping_sub(&U256::ONE)).into(),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap()
    }

    pub(crate) fn enhanced_language_public_parameters<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + SamplableWithin,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { secp256k1::SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
    ) -> language::PublicParameters<
        REPETITIONS,
        EnhancedLang<REPETITIONS, NUM_RANGE_CLAIMS, UnboundedWitnessSpaceGroupElement, Lang>,
    > {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        // TODO: move this shared logic somewhere e.g. DRY
        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let message_generators = array::from_fn(|_| {
            let generator =
                secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap()
                    * generator;

            generator.value()
        });

        let randomness_generator =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap()
                * generator;

        // TODO: this is not safe; we need a proper way to derive generators
        let pedersen_public_parameters = pedersen::PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
            message_generators,
            randomness_generator.value(),
        );

        language::enhanced::PublicParameters::new::<
            Pedersen<
                NUM_RANGE_CLAIMS,
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
            >,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            pedersen_public_parameters,
            language_public_parameters,
        )
    }

    pub(crate) fn generate_witnesses<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + group::SamplableWithin,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        enhanced_language_public_parameters: &language::PublicParameters<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                MESSAGE_SPACE_SCALAR_LIMBS,
                CommitmentScheme,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    ) -> Vec<
        language::WitnessSpaceGroupElement<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                MESSAGE_SPACE_SCALAR_LIMBS,
                CommitmentScheme,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    >
    where
        Uint<MESSAGE_SPACE_SCALAR_LIMBS>: Encoding,
        group::Value<CommitmentScheme::MessageSpaceGroupElement>:
            From<[Uint<MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS]>,
    {
        witnesses
            .into_iter()
            .map(|witness| {
                let (constrained_witness, unbounded_element) = Language::decompose_witness(
                    &witness,
                    &enhanced_language_public_parameters.language_public_parameters,
                )
                .unwrap();

                let commitment_randomness = CommitmentScheme::RandomnessSpaceGroupElement::sample(
                    enhanced_language_public_parameters
                        .commitment_scheme_public_parameters
                        .randomness_space_public_parameters(),
                    &mut OsRng,
                )
                .unwrap();

                (
                    constrained_witness,
                    commitment_randomness,
                    unbounded_element,
                )
                    .into()
            })
            .collect()
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
//                     - <range::bulletproofs::RangeProof as RangeProof< { ristretto::SCALAR_LIMBS
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
