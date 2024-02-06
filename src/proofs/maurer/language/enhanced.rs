// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use core::array;
use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{rand_core::CryptoRngCore, Uint, U128, CheckedMul, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use tiresias::secret_sharing::shamir::Polynomial;

use crate::{homomorphic_encryption, commitment, commitment::{
    pedersen, GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme, Pedersen,
}, group, group::{
    KnownOrderGroupElement,
    direct_product, direct_product::ThreeWayPublicParameters, paillier, self_product,
    BoundedGroupElement, GroupElement as _, GroupElement, KnownOrderScalar, Samplable,
}, helpers::FlatMapResults, proofs, proofs::{
    range,
    range::{
        CommitmentScheme, CommitmentSchemeCommitmentSpaceGroupElement,
        CommitmentSchemeCommitmentSpacePublicParameters,
        CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeMessageSpacePublicParameters,
        CommitmentSchemePublicParameters, CommitmentSchemeRandomnessSpaceGroupElement,
        CommitmentSchemeRandomnessSpacePublicParameters, PublicParametersAccessors,
        RangeClaimGroupElement,
    },
    maurer,
    maurer::{
        language,
        language::{GroupsPublicParameters, GroupsPublicParametersAccessors as _},
    },
}, ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber, Error, PartyID};

/// An Enhanced Maurer Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Maurer zero-knowledge `Proof` with range claims.
/// As defined in Appendix B. Maurer Protocols in the paper.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnhancedLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> {
    _unbounded_witness_choice: PhantomData<UnboundedWitnessSpaceGroupElement>,
    _language_choice: PhantomData<Language>,
    _range_proof_choice: PhantomData<RangeProof>,
}

pub trait EnhanceableLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
>: maurer::Language<REPETITIONS>
{
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        unbounded_witness: UnboundedWitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement>;

    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        UnboundedWitnessSpaceGroupElement,
    )>;
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: range::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    > maurer::Language<REPETITIONS>
    for EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
{
    type WitnessSpaceGroupElement = direct_product::ThreeWayGroupElement<
        CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        CommitmentSchemeRandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        UnboundedWitnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement = direct_product::GroupElement<
        CommitmentSchemeCommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        Language::StatementSpaceGroupElement,
    >;

    type PublicParameters = PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        group::PublicParameters<RangeProof::RangeClaimGroupElement>,
        CommitmentSchemeRandomnessSpacePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        CommitmentSchemeCommitmentSpacePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        RangeProof::PublicParameters<NUM_RANGE_CLAIMS>,
        UnboundedWitnessSpaceGroupElement::PublicParameters,
        group::PublicParameters<Language::StatementSpaceGroupElement>,
        Language::PublicParameters,
    >;

    const NAME: &'static str = Language::NAME;

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &Self::PublicParameters,
    ) -> crate::proofs::Result<Self::StatementSpaceGroupElement> {
        let decomposed_witness: [_; NUM_RANGE_CLAIMS] =
            witness.range_proof_commitment_message().clone().into();

        let decomposed_witness = decomposed_witness
            .map(Into::<Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::into);

        let language_witness = Language::compose_witness(
            decomposed_witness,
            witness.unbounded_witness().clone(),
            &enhanced_language_public_parameters.language_public_parameters,
            RangeProof::RANGE_CLAIM_BITS,
        )?;

        let language_statement = Language::homomorphose(
            &language_witness,
            &enhanced_language_public_parameters.language_public_parameters,
        )?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters(),
        )?;

        let commitment_message_value =
            <[_; NUM_RANGE_CLAIMS]>::from(witness.range_proof_commitment_message().value()).into();

        let commitment_message = CommitmentSchemeMessageSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::new(
            commitment_message_value,
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .message_space_public_parameters(),
        )?;

        let range_proof_commitment = commitment_scheme.commit(
            &commitment_message,
            witness.range_proof_commitment_randomness(),
        );

        Ok((range_proof_commitment, language_statement).into())
    }
}

pub trait DecomposableWitness<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const WITNESS_LIMBS: usize,
>: KnownOrderScalar<WITNESS_LIMBS>
{
    fn decompose(
        self,
        range_claim_bits: usize,
    ) -> [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR] {
        // TODO: sanity checks, return result?
        let witness: Uint<WITNESS_LIMBS> = self.into();

        let mask = (Uint::<WITNESS_LIMBS>::ONE << range_claim_bits)
            .wrapping_sub(&Uint::<WITNESS_LIMBS>::ONE);

        array::from_fn(|i| {
            Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(
                &((witness >> (i * range_claim_bits))
                    & mask),
            )
        })
    }

    fn compose(
        decomposed_witness: &[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
             RANGE_CLAIMS_PER_SCALAR],
        public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<Self> {
        // // TODO: put tests in both functions.
        // let order = Self::order_from_public_parameters(
        //     &public_parameters,
        // );
        //
        // let delta: Uint<WITNESS_LIMBS> = Uint::<WITNESS_LIMBS>::ONE << range_claim_bits;
        // if delta.checked_mul(&Uint::from(PartyID::MAX+1)).map(|bound | order <= bound).unwrap()  {
        //     // return error, doc
        //     todo!();
        // }

        // MESSAGE_SPACE_ORDER > 2^RANGE_CLAIM_BITS*(NUM_RANGE_CLAIMS*ComputationalSecuritySizedNumber*ComputationalSecuritySizedNumber + StatisticalSecuritySizedNumber)
        // TODO: to do this, I need to know commitment scheme. Maybe just get the range proof and be done with it?

        let delta: Uint<WITNESS_LIMBS> = Uint::<WITNESS_LIMBS>::ONE << range_claim_bits;
        let delta = Self::new(delta.into(), public_parameters)?;
        let decomposed_witness = decomposed_witness
            .into_iter()
            .map(|witness| {
                Self::new(
                    // TODO: need to check this is ok?
                    Uint::<WITNESS_LIMBS>::from(&Uint::<
                        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    >::from(witness))
                    .into(),
                    public_parameters,
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let polynomial = Polynomial::try_from(decomposed_witness)
            .map_err(|_| proofs::Error::InvalidParameters)?;

        Ok(polynomial.evaluate(&delta))
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const WITNESS_LIMBS: usize,
        Witness: KnownOrderScalar<WITNESS_LIMBS>,
    >
    DecomposableWitness<
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        WITNESS_LIMBS,
    > for Witness
{
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: range::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    >
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
{
    pub fn generate_witness(
        witness: Language::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &language::PublicParameters<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<
        language::WitnessSpaceGroupElement<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    > {
        let (decomposed_witness, unbounded_element) = Language::decompose_witness(
            witness,
            &enhanced_language_public_parameters.language_public_parameters,
            RangeProof::RANGE_CLAIM_BITS,
        )?;

        let range_proof_commitment_message = decomposed_witness
            .map(group::Value::<RangeProof::RangeClaimGroupElement>::from)
            .map(|value| {
                RangeProof::RangeClaimGroupElement::new(
                    value,
                    enhanced_language_public_parameters
                        .range_proof_public_parameters
                        .range_claim_public_parameters(),
                )
            })
            .flat_map_results()?
            .into();

        let commitment_randomness = CommitmentSchemeRandomnessSpaceGroupElement::<
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::sample(
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .randomness_space_public_parameters(),
            rng,
        )?;

        Ok((
            range_proof_commitment_message,
            commitment_randomness,
            unbounded_element,
        )
            .into())
    }

    pub fn generate_witnesses(
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        enhanced_language_public_parameters: &language::PublicParameters<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> proofs::Result<
        Vec<
            language::WitnessSpaceGroupElement<
                REPETITIONS,
                EnhancedLanguage<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Language,
                >,
            >,
        >,
    > {
        witnesses
            .into_iter()
            .map(|witness| {
                Self::generate_witness(witness, enhanced_language_public_parameters, rng)
            })
            .collect::<proofs::Result<Vec<_>>>()
    }
}

#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeClaimPublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    RangeProofPublicParameters,
    UnboundedWitnessSpacePublicParameters,
    LanguageStatementSpacePublicParameters,
    LanguagePublicParameters,
> {
    groups_public_parameters: GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CommitmentSpacePublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    >,
    pub range_proof_public_parameters: RangeProofPublicParameters,
    language_public_parameters: LanguagePublicParameters,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeClaimPublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
        RangeProofPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters: Clone,
        LanguagePublicParameters,
    >
    PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
{
    pub fn new<RangeProof, UnboundedWitnessSpaceGroupElement, Language>(
        unbounded_witness_public_parameters: UnboundedWitnessSpacePublicParameters,
        range_proof_public_parameters: RangeProofPublicParameters,
        language_public_parameters: LanguagePublicParameters,
    ) -> proofs::Result<Self>
    where
        RangeProof: range::RangeProof<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PublicParameters<NUM_RANGE_CLAIMS> = RangeProofPublicParameters,
        >,
        CommitmentSchemeRandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentSchemeCommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: group::GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        RangeProof::RangeClaimGroupElement:
            group::GroupElement<PublicParameters = RangeClaimPublicParameters>,
        CommitmentSchemePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: AsRef<
            commitment::GroupsPublicParameters<
                self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
        RangeProofPublicParameters: AsRef<
            CommitmentSchemePublicParameters<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
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
        // We require {\color{blue} $q > \Delta\cdot (d(\ell+1+\omegalen) \cdot 2^{\kappa+s} + 2^{\kappa})$}.
        let order = CommitmentSchemeMessageSpaceGroupElement::<                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,>::order_from_public_parameters(
            range_proof_public_parameters.commitment_scheme_public_parameters().message_space_public_parameters(),
        );

        let delta: Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS> = Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE << RangeProof::RANGE_CLAIM_BITS;
        let number_of_range_claims = U64::from(u64::try_from(2*NUM_RANGE_CLAIMS).map_err(|_| proofs::Error::InvalidParameters)?); // We multiply by two for the + 1
        let bound = Option::from(delta.checked_mul(&(&number_of_range_claims.into())).and_then(|bound| bound.checked_mul(&(Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE << ComputationalSecuritySizedNumber::BITS))).and_then(|bound| bound.checked_mul(&(Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE << StatisticalSecuritySizedNumber::BITS)))).ok_or(proofs::Error::InvalidParameters)?;
        if order <= bound {
            return Err(proofs::Error::InvalidParameters);
        }

        Ok(Self {
            groups_public_parameters: language::GroupsPublicParameters {
                witness_space_public_parameters: (
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .message_space_public_parameters()
                        .clone(),
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .randomness_space_public_parameters()
                        .clone(),
                    unbounded_witness_public_parameters,
                )
                    .into(),
                statement_space_public_parameters: (
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .commitment_space_public_parameters()
                        .clone(),
                    language_public_parameters
                        .statement_space_public_parameters()
                        .clone(),
                )
                    .into(),
            },
            range_proof_public_parameters,
            language_public_parameters,
        })
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
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeClaimPublicParameters,
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
                self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
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
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
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
    MessageSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
    UnboundedWitnessSpaceGroupElement: group::GroupElement,
>
{
    fn range_proof_commitment_message(&self) -> &MessageSpaceGroupElement;

    fn range_proof_commitment_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement;
}

impl<
        MessageSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
        UnboundedWitnessSpaceGroupElement: group::GroupElement,
    >
    EnhancedLanguageWitnessAccessors<
        MessageSpaceGroupElement,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
    for direct_product::ThreeWayGroupElement<
        MessageSpaceGroupElement,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
{
    fn range_proof_commitment_message(&self) -> &MessageSpaceGroupElement {
        let (range_proof_commitment_message, ..): (_, _, _) = self.into();

        range_proof_commitment_message
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
    CommitmentSpaceGroupElement: group::GroupElement,
    LanguageStatementSpaceGroupElement: group::GroupElement,
>
{
    fn range_proof_commitment(&self) -> &CommitmentSpaceGroupElement;

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement;
}

impl<
        CommitmentSpaceGroupElement: group::GroupElement,
        LanguageStatementSpaceGroupElement: group::GroupElement,
    >
    EnhancedLanguageStatementAccessors<
        CommitmentSpaceGroupElement,
        LanguageStatementSpaceGroupElement,
    >
    for direct_product::GroupElement<
        CommitmentSpaceGroupElement,
        LanguageStatementSpaceGroupElement,
    >
{
    fn range_proof_commitment(&self) -> &CommitmentSpaceGroupElement {
        let (range_proof_commitment, _) = self.into();

        range_proof_commitment
    }

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement {
        let (_, language_statement) = self.into();

        language_statement
    }
}

pub type EnhancedPublicParameters<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = language::PublicParameters<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

pub type WitnessSpaceGroupElement<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = language::WitnessSpaceGroupElement<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

pub type StatementSpaceGroupElement<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = language::StatementSpaceGroupElement<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use homomorphic_encryption::paillier::tests::N;
    use crypto_bigint::U256;
    use rand_core::OsRng;

    use super::*;
    use crate::{
        homomorphic_encryption::GroupsPublicParametersAccessors,
        group::secp256k1,
        proofs::range::{
            bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RangeClaimGroupElement,
        },
    };

    pub const RANGE_CLAIMS_PER_SCALAR: usize =
        { Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS / range::bulletproofs::RANGE_CLAIM_BITS };

    pub(super) type EnhancedLang<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement,
        Lang,
    > = EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        range::bulletproofs::RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Lang,
    >;

    pub(crate) fn generate_scalar_plaintext() -> paillier::PlaintextSpaceGroupElement {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let scalar =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let paillier_public_parameters = homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();

        paillier::PlaintextSpaceGroupElement::new(
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(scalar.value())),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap()
    }

    pub(crate) fn enhanced_language_public_parameters<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
    ) -> language::PublicParameters<
        REPETITIONS,
        EnhancedLang<REPETITIONS, NUM_RANGE_CLAIMS, UnboundedWitnessSpaceGroupElement, Lang>,
    > {
        maurer::enhanced::PublicParameters::new::<
            range::bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            range::bulletproofs::PublicParameters::default(),
            language_public_parameters,
        ).unwrap()
    }
}
