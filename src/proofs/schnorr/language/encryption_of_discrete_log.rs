// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

// TODO
// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

pub use crate::proofs::lightning::enhanced_schnorr::REPETITIONS;
use crate::{
    ahe,
    ahe::{paillier::EncryptionKey as PaillierEncryptionKey, GroupsPublicParametersAccessors},
    commitments::{HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{
        direct_product, paillier, BoundedGroupElement, GroupElement as _, GroupElement,
        KnownOrderScalar, Samplable,
    },
    proofs,
    proofs::{
        lightning,
        lightning::{
            enhanced_schnorr::{
                ConstrainedWitnessGroupElement, DecomposableWitness, EnhanceableLanguage,
            },
            range_claim_bits,
        },
        schnorr,
        schnorr::language::GroupsPublicParameters,
    },
    AdditivelyHomomorphicEncryptionKey,
};

/// Encryption of Discrete Log Schnorr Language
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group and additively homomorphic
/// encryption scheme in this language, we choose to provide a fully generic
/// implementation.
///
/// However knowledge-soundness proofs are group and encryption scheme dependent, and thus we can
/// only assure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
///
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier`.
#[derive(Clone, PartialEq)]
pub struct Language<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, GroupElement, EncryptionKey> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<REPETITIONS>
    for Language<PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>
{
    type WitnessSpaceGroupElement = direct_product::GroupElement<
        EncryptionKey::PlaintextSpaceGroupElement,
        EncryptionKey::RandomnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement =
        direct_product::GroupElement<EncryptionKey::CiphertextSpaceGroupElement, GroupElement>;

    type PublicParameters = PublicParameters<
        GroupElement::PublicParameters,
        GroupElement::Value,
        group::PublicParameters<EncryptionKey::PlaintextSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::RandomnessSpaceGroupElement>,
        group::PublicParameters<EncryptionKey::CiphertextSpaceGroupElement>,
        EncryptionKey::PublicParameters,
    >;

    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let base = GroupElement::new(
            language_public_parameters.generator,
            language_public_parameters.group_public_parameters(),
        )?;

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let encryption_of_discrete_log =
            encryption_key.encrypt_with_randomness(witness.discrete_log(), witness.randomness());

        let base_by_discrete_log = base.scalar_mul(&witness.discrete_log().value());

        Ok((encryption_of_discrete_log, base_by_discrete_log).into())

        // let commitment_scheme =
        //     Pedersen::new(&language_public_parameters.pedersen_public_parameters);
        //
        // let discrete_log_scalar =
        //     <Scalar as DecomposableWitness<SCALAR_LIMBS>>::compose_from_constrained_witness(
        //         *witness.constrained_witness(),
        //         &language_public_parameters.scalar_group_public_parameters,
        //         proofs::lightning::RangeProof::<
        //             SCALAR_LIMBS,
        //             Pedersen<RANGE_CLAIMS_PER_SCALAR, Scalar, GroupElement>,
        //         >::range_claim_bits(),
        //     )?;
        //
        // let discrete_log_plaintext =
        //     <group::paillier::PlaintextGroupElement as DecomposableWitness<
        //         group::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS,
        //     >>::compose_from_constrained_witness(
        //         *witness.constrained_witness(),
        //         language_public_parameters
        //             .paillier_encryption_public_parameters
        //             .plaintext_space_public_parameters(),
        //         proofs::lightning::RangeProof::<
        //             SCALAR_LIMBS,
        //             Pedersen<RANGE_CLAIMS_PER_SCALAR, Scalar, GroupElement>,
        //         >::range_claim_bits(),
        //     )?;
        //
        // let discrete_log_commitment_message = range::CommitmentSchemeMessageSpaceGroupElement::<
        //     RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        //     RANGE_CLAIMS_PER_SCALAR,
        //     RANGE_CLAIM_LIMBS,
        //     RangeProof,
        // >::new(
        //     witness.constrained_witness().value().into(),
        //     &language_public_parameters
        //         .range_proof_public_parameters
        //         .commitment_public_parameters()
        //         .message_space_public_parameters(),
        // )?;
        //
        // // TODO: Need to check that WITNESS_MASK_LIMBS is actually in a size fitting the range
        // proof // commitment scheme without going through modulation, and to implement
        // `From` to // transition.
        // Ok((
        //     commitment_scheme.commit(
        //         &discrete_log_commitment_message,
        //         witness.range_proof_commitment_randomness(),
        //     ),
        //     (
        //         encryption_key.encrypt_with_randomness(
        //             &discrete_log_plaintext,
        //             witness.encryption_randomness(),
        //         ),
        //         discrete_log_scalar * base,
        //     )
        //         .into(),
        // )
        //     .into())
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const SCALAR_LIMBS: usize,
        Scalar: KnownOrderScalar<SCALAR_LIMBS> + Samplable,
        GroupElement: group::GroupElement,
    >
    EnhanceableLanguage<
        RANGE_CLAIMS_PER_SCALAR,
        SCALAR_LIMBS,
        Scalar,
        paillier::RandomnessSpaceGroupElement,
    > for Language<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }, GroupElement, PaillierEncryptionKey>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn convert_witness(
        constrained_witness: ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS>,
        randomness: paillier::RandomnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement> {
        let discrete_log = <Scalar as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            SCALAR_LIMBS,
        >>::compose_from_constrained_witness(
            constrained_witness,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits::<SCALAR_LIMBS>(),
        )?;

        Ok((discrete_log, randomness).into())
    }
}

/// The Public Parameters of the Encryption of Discrete Log Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    GroupPublicParameters,
    GroupElementValue,
    PlaintextSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CiphertextSpacePublicParameters,
    EncryptionKeyPublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::PublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    >,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    // The base of the discrete log
    pub generator: GroupElementValue,
}

impl<
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
    >
    for PublicParameters<
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters: AsRef<
            ahe::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    >
    PublicParameters<
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    pub fn new<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, GroupElement, EncryptionKey>(
        generator: GroupElement::Value,
        group_public_parameters: GroupElement::PublicParameters,
        encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    ) -> Self
    where
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = EncryptionKeyPublicParameters,
        >,
        EncryptionKey::PlaintextSpaceGroupElement:
            group::GroupElement<PublicParameters = PlaintextSpacePublicParameters>,
        EncryptionKey::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        EncryptionKey::CiphertextSpaceGroupElement:
            group::GroupElement<PublicParameters = CiphertextSpacePublicParameters>,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .plaintext_space_public_parameters()
                        .clone(),
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                )
                    .into(),
                statement_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                    group_public_parameters,
                )
                    .into(),
            },
            encryption_scheme_public_parameters,
            generator,
        }
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        group_public_parameters
    }
}

pub trait WitnessAccessors<
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement;

    fn randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::GroupElement<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement {
        let (plaintext, _): (&_, &_) = self.into();

        plaintext
    }

    fn randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness): (&_, &_) = self.into();

        randomness
    }
}

pub trait StatementAccessors<
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement;

    // TODO: name
    fn base_by_discrete_log(&self) -> &GroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement, GroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>
{
    fn ciphertext(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn base_by_discrete_log(&self) -> &GroupElement {
        let (_, base_by_discrete_log): (&_, &_) = self.into();

        base_by_discrete_log
    }
}

// todo: delete

// impl<
//         const SCALAR_LIMBS: usize,
//         const RANGE_CLAIMS_PER_SCALAR: usize,
//         Scalar: LanguageScalar<SCALAR_LIMBS, GroupElement>,
//         GroupElement: group::GroupElement,
//     > EnhancedLanguage<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, Scalar, GroupElement>
//     for Language<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, Scalar, GroupElement>
// where
//     Uint<SCALAR_LIMBS>: Encoding,
//     Scalar::Value: From<Uint<SCALAR_LIMBS>>,
// {
//     type UnboundedWitnessSpaceGroupElement = group::paillier::RandomnessGroupElement;
//
//     type RemainingStatementSpaceGroupElement =
//         direct_product::GroupElement<group::paillier::CiphertextGroupElement, GroupElement>;
// }
//
// pub trait EnhancedLanguageWitnessAccessors<
//     const NUM_RANGE_CLAIMS: usize,
//     const WITNESS_MASK_LIMBS: usize,
//     RangeProofCommitmentSchemeRandomnessSpaceGroupElement: group::GroupElement,
//     RandomnessSpaceGroupElement: group::GroupElement,
// >:
//     super::EnhancedLanguageWitnessAccessors<
//     NUM_RANGE_CLAIMS,
//     WITNESS_MASK_LIMBS,
//     RangeProofCommitmentSchemeRandomnessSpaceGroupElement,
//     RandomnessSpaceGroupElement,
// >
// {
//     // TODO: discrete log
//     fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement {
//         self.unbounded_witness()
//     }
// }
//
// impl<
//         const NUM_RANGE_CLAIMS: usize,
//         const WITNESS_MASK_LIMBS: usize,
//         RangeProofCommitmentSchemeRandomnessSpaceGroupElement: group::GroupElement,
//         RandomnessSpaceGroupElement: group::GroupElement,
//     >
//     EnhancedLanguageWitnessAccessors<
//         NUM_RANGE_CLAIMS,
//         WITNESS_MASK_LIMBS,
//         RangeProofCommitmentSchemeRandomnessSpaceGroupElement,
//         RandomnessSpaceGroupElement,
//     >
//     for direct_product::ThreeWayGroupElement<
//         ConstrainedWitnessGroupElement<NUM_RANGE_CLAIMS, WITNESS_MASK_LIMBS>,
//         RangeProofCommitmentSchemeRandomnessSpaceGroupElement,
//         RandomnessSpaceGroupElement,
//     >
// {
// }
//
// pub trait EnhancedLanguageStatementAccessors<
//     'a,
//     RangeProofCommitmentSchemeCommitmentSpaceGroupElement: 'a + group::GroupElement,
//     CiphertextSpaceGroupElement: 'a + group::GroupElement,
//     GroupElement: 'a + group::GroupElement,
// >:
//     super::EnhancedLanguageStatementAccessors<
//     RangeProofCommitmentSchemeCommitmentSpaceGroupElement,
//     direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>,
// >
// {
//     fn encryption_of_discrete_log(&'a self) -> &'a CiphertextSpaceGroupElement {
//         let (encryption_of_discrete_log, _) = self.remaining_statement().into();
//
//         encryption_of_discrete_log
//     }
//
//     // TODO: is there a better name?
//     fn generator_by_discrete_log(&'a self) -> &'a GroupElement {
//         let (_, generator_by_discrete_log) = self.remaining_statement().into();
//
//         generator_by_discrete_log
//     }
// }
//
// impl<
//         'a,
//         RangeProofCommitmentSchemeCommitmentSpaceGroupElement: 'a + group::GroupElement,
//         CiphertextSpaceGroupElement: 'a + group::GroupElement,
//         GroupElement: 'a + group::GroupElement,
//     >
//     EnhancedLanguageStatementAccessors<
//         'a,
//         RangeProofCommitmentSchemeCommitmentSpaceGroupElement,
//         CiphertextSpaceGroupElement,
//         GroupElement,
//     >
//     for direct_product::GroupElement<
//         RangeProofCommitmentSchemeCommitmentSpaceGroupElement,
//         direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>,
//     >
// {
// }

// impl<
//         const RANGE_CLAIMS_PER_SCALAR: usize,
//         const WITNESS_MASK_LIMBS: usize,
//         GroupElementPublicParameters,
//         ScalarPublicParameters,
//         RangeProofCommitmentRandomnessSpacePublicParameters,
//         RangeProofCommitmentSpacePublicParameters,
//         RangeProofPublicParameters: Clone,
//         EncryptionRandomnessPublicParameters: Clone,
//         CiphertextPublicParameters: Clone,
//         EncryptionKeyPublicParameters,
//         GroupElementValue,
//     >
//     PublicParameters<
//         RANGE_CLAIMS_PER_SCALAR,
//         WITNESS_MASK_LIMBS,
//         GroupElementPublicParameters,
//         ScalarPublicParameters,
//         RangeProofCommitmentRandomnessSpacePublicParameters,
//         RangeProofCommitmentSpacePublicParameters,
//         RangeProofPublicParameters,
//         EncryptionRandomnessPublicParameters,
//         CiphertextPublicParameters,
//         EncryptionKeyPublicParameters,
//         GroupElementValue,
//     >
// where
//     Uint<WITNESS_MASK_LIMBS>: Encoding,
// {
//     pub fn new<
//         const SCALAR_LIMBS: usize,
//         const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
//         const RANGE_CLAIM_LIMBS: usize,
//         const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
//         Scalar: LanguageScalar<SCALAR_LIMBS, GroupElement>,
//         GroupElement,
//         EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
//         RangeProof,
//     >(
//         scalar_group_public_parameters: Scalar::PublicParameters,
//         group_public_parameters: GroupElement::PublicParameters,
//         range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
//         encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
//     ) -> Self
//     where
//         Uint<RANGE_CLAIM_LIMBS>: Encoding,
//         GroupElement: group::GroupElement<
//                 Value = GroupElementValue,
//                 PublicParameters = GroupElementPublicParameters,
//             > + CyclicGroupElement,
//         Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
//         Scalar::Value: From<Uint<SCALAR_LIMBS>>,
//         range::CommitmentSchemeMessageSpaceValue<
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             RANGE_CLAIMS_PER_SCALAR,
//             RANGE_CLAIM_LIMBS,
//             RangeProof,
//         >: From<super::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
//         RangeProof: proofs::RangeProof<
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             RANGE_CLAIM_LIMBS,
//             PublicParameters<RANGE_CLAIMS_PER_SCALAR> = RangeProofPublicParameters,
//         >,
//         range::CommitmentSchemeRandomnessSpaceGroupElement<
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             RANGE_CLAIMS_PER_SCALAR,
//             RANGE_CLAIM_LIMBS,
//             RangeProof,
//         >: group::GroupElement<
//             PublicParameters = RangeProofCommitmentRandomnessSpacePublicParameters,
//         >,
//         range::CommitmentSchemeCommitmentSpaceGroupElement<
//             RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//             RANGE_CLAIMS_PER_SCALAR,
//             RANGE_CLAIM_LIMBS,
//             RangeProof,
//         >: group::GroupElement<PublicParameters = RangeProofCommitmentSpacePublicParameters>,
//         EncryptionKey: AdditivelyHomomorphicEncryptionKey<
//             PLAINTEXT_SPACE_SCALAR_LIMBS,
//             PublicParameters = EncryptionKeyPublicParameters,
//         >,
//         EncryptionKey::RandomnessSpaceGroupElement:
//             group::GroupElement<PublicParameters = EncryptionRandomnessPublicParameters>,
//         EncryptionKey::CiphertextSpaceGroupElement:
//             group::GroupElement<PublicParameters = CiphertextPublicParameters>,
//         EncryptionKeyPublicParameters: AsRef<
//             ahe::GroupsPublicParameters<
//                 ahe::PlaintextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
//                 ahe::RandomnessSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS,
// EncryptionKey>,
// ahe::CiphertextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,             >,
//         >,
//     {
//         // TODO: is this the right value? must be for everything?
//         let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
//             + ComputationalSecuritySizedNumber::BITS
//             + StatisticalSecuritySizedNumber::BITS;
//
//         // TODO: maybe we don't want the generator all the time?
//         let generator = GroupElement::generator_from_public_parameters(&group_public_parameters);
//
//         let unbounded_witness_space_public_parameters = encryption_scheme_public_parameters
//             .randomness_space_public_parameters()
//             .clone();
//
//         let remaining_statement_space_public_parameters = (
//             encryption_scheme_public_parameters
//                 .ciphertext_space_public_parameters()
//                 .clone(),
//             group_public_parameters,
//         )
//             .into();
//
//         Self {
//             groups_public_parameters: super::GroupsPublicParameters::<
//                 RANGE_CLAIMS_PER_SCALAR,
//                 WITNESS_MASK_LIMBS,
//                 RangeProofCommitmentRandomnessSpacePublicParameters,
//                 RangeProofCommitmentSpacePublicParameters,
//                 self_product::PublicParameters<2, EncryptionRandomnessPublicParameters>,
//                 self_product::PublicParameters<2, CiphertextPublicParameters>,
//             >::new::<
//                 REPETITIONS,
//                 RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//                 RANGE_CLAIMS_PER_SCALAR,
//                 RANGE_CLAIM_LIMBS,
//                 WITNESS_MASK_LIMBS,
//                 Language<
//                     SCALAR_LIMBS,
//                     RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
//                     RANGE_CLAIMS_PER_SCALAR,
//                     RANGE_CLAIM_LIMBS,
//                     WITNESS_MASK_LIMBS,
//                     PLAINTEXT_SPACE_SCALAR_LIMBS,
//                     Scalar,
//                     GroupElement,
//                     EncryptionKey,
//                     RangeProof,
//                 >,
//             >(
//                 range_proof_public_parameters.clone(),
//                 unbounded_witness_space_public_parameters,
//                 remaining_statement_space_public_parameters,
//                 sampling_bit_size,
//             ),
//             range_proof_public_parameters,
//             encryption_scheme_public_parameters,
//             scalar_group_public_parameters,
//             generator,
//         }
//     }
//
//     fn group_public_parameters(&self) -> &GroupElementPublicParameters {
//         let (_, remaining_stataement_public_parameters) =
//             self.statement_space_public_parameters().into();
//
//         let (_, group_public_parameters) = remaining_stataement_public_parameters.into();
//
//         group_public_parameters
//     }
// }
//
// impl<
//         const RANGE_CLAIMS_PER_SCALAR: usize,
//         const WITNESS_MASK_LIMBS: usize,
//         GroupElementPublicParameters,
//         ScalarPublicParameters,
//         RangeProofCommitmentRandomnessSpacePublicParameters,
//         RangeProofCommitmentSpacePublicParameters,
//         RangeProofPublicParameters,
//         EncryptionRandomnessPublicParameters,
//         CiphertextPublicParameters,
//         EncryptionKeyPublicParameters,
//         GroupElementValue,
//     >
//     AsRef<
//         super::GroupsPublicParameters<
//             RANGE_CLAIMS_PER_SCALAR,
//             WITNESS_MASK_LIMBS,
//             RangeProofCommitmentRandomnessSpacePublicParameters,
//             RangeProofCommitmentSpacePublicParameters,
//             EncryptionRandomnessPublicParameters,
//             direct_product::PublicParameters<
//                 CiphertextPublicParameters,
//                 GroupElementPublicParameters,
//             >,
//         >,
//     >
//     for PublicParameters<
//         RANGE_CLAIMS_PER_SCALAR,
//         WITNESS_MASK_LIMBS,
//         GroupElementPublicParameters,
//         ScalarPublicParameters,
//         RangeProofCommitmentRandomnessSpacePublicParameters,
//         RangeProofCommitmentSpacePublicParameters,
//         RangeProofPublicParameters,
//         EncryptionRandomnessPublicParameters,
//         CiphertextPublicParameters,
//         EncryptionKeyPublicParameters,
//         GroupElementValue,
//     >
// where
//     Uint<WITNESS_MASK_LIMBS>: Encoding,
// {
//     fn as_ref(
//         &self,
//     ) -> &super::GroupsPublicParameters<
//         RANGE_CLAIMS_PER_SCALAR,
//         WITNESS_MASK_LIMBS,
//         RangeProofCommitmentRandomnessSpacePublicParameters,
//         RangeProofCommitmentSpacePublicParameters,
//         EncryptionRandomnessPublicParameters,
//         direct_product::PublicParameters<CiphertextPublicParameters,
// GroupElementPublicParameters>,
//     > { &self.groups_public_parameters
//     }
// }

// #[cfg(any(test, feature = "benchmarking"))]
// pub(crate) mod tests {
//     use crypto_bigint::{NonZero, Random};
//     use paillier::tests::N;
//     use rand_core::OsRng;
//     use rstest::rstest;
//
//     use super::*;
//     use crate::{
//         ahe::paillier,
//         group::{ristretto, secp256k1, self_product},
//         proofs::{
//             range,
//             range::{bulletproofs, RangeProof},
//             schnorr::{aggregation, language},
//         },
//         ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
//     };
//
//     pub(crate) type Lang = Language<
//         { secp256k1::SCALAR_LIMBS },
//         { ristretto::SCALAR_LIMBS },
//         RANGE_CLAIMS_PER_SCALAR,
//         { range::bulletproofs::RANGE_CLAIM_LIMBS },
//         { WITNESS_MASK_LIMBS },
//         { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
//         secp256k1::Scalar,
//         secp256k1::GroupElement,
//         paillier::EncryptionKey,
//         bulletproofs::RangeProof,
//     >;
//
//     pub(crate) fn public_parameters() -> (
//         language::PublicParameters<REPETITIONS, Lang>,
//         language::enhanced::RangeProofPublicParameters<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >,
//     ) {
//         let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
//
//         let secp256k1_group_public_parameters =
//             secp256k1::group_element::PublicParameters::default();
//
//         let bulletproofs_public_parameters =
//             range::bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();
//
//         let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();
//
//         let language_public_parameters = PublicParameters::new::<
//             { secp256k1::SCALAR_LIMBS },
//             { ristretto::SCALAR_LIMBS },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
//             secp256k1::Scalar,
//             secp256k1::GroupElement,
//             paillier::EncryptionKey,
//             bulletproofs::RangeProof,
//         >(
//             secp256k1_scalar_public_parameters,
//             secp256k1_group_public_parameters,
//             bulletproofs_public_parameters.clone(),
//             paillier_public_parameters,
//         );
//
//         (language_public_parameters, bulletproofs_public_parameters)
//     }
//
//     #[rstest]
//     #[case(1)]
//     #[case(2)]
//     #[case(3)]
//     fn valid_proof_verifies(#[case] batch_size: usize) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::enhanced::tests::valid_proof_verifies::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             batch_size,
//         )
//     }
//
//     #[rstest]
//     #[case(1, 1)]
//     #[case(1, 2)]
//     #[case(2, 1)]
//     #[case(2, 3)]
//     #[case(5, 2)]
//     fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
//         let (language_public_parameters, _) = public_parameters();
//         let witnesses = language::enhanced::tests::generate_witnesses_for_aggregation::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(&language_public_parameters, number_of_parties, batch_size);
//
//         aggregation::tests::aggregates::<REPETITIONS, Lang>(&language_public_parameters,
// witnesses)     }
//
//     #[rstest]
//     #[case(1)]
//     #[case(2)]
//     #[case(3)]
//     fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::enhanced::tests::proof_with_out_of_range_witness_fails::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             batch_size,
//         )
//     }
//
//     #[rstest]
//     #[case(1)]
//     #[case(2)]
//     #[case(3)]
//     fn invalid_proof_fails_verification(#[case] batch_size: usize) {
//         let (language_public_parameters, _) = public_parameters();
//
//         // No invalid values as secp256k1 statically defines group,
//         // `k256::AffinePoint` assures deserialized values are on curve,
//         // and `Value` can only be instantiated through deserialization
//         language::tests::invalid_proof_fails_verification::<REPETITIONS, Lang>(
//             None,
//             None,
//             language_public_parameters,
//             batch_size,
//         )
//     }
// }
//
// #[cfg(feature = "benchmarking")]
// mod benches {
//     use criterion::Criterion;
//
//     use super::*;
//     use crate::{
//         ahe::paillier,
//         group::{ristretto, secp256k1},
//         proofs::{
//             range,
//             schnorr::{
//                 aggregation, language,
//                 language::encryption_of_discrete_log::tests::{public_parameters, Lang},
//             },
//         },
//         ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
//     };
//
//     pub(crate) fn benchmark(c: &mut Criterion) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::benchmark::<REPETITIONS, Lang>(language_public_parameters.clone(), None, c);
//
//         range::benchmark::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             { RANGE_CLAIMS_PER_SCALAR },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             c,
//         );
//
//         aggregation::benchmark_enhanced::<
//             REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             { RANGE_CLAIMS_PER_SCALAR },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//             WITNESS_MASK_LIMBS,
//             Lang,
//         >(language_public_parameters, None, c);
//     }
// }
