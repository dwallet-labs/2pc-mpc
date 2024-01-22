// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::{marker::PhantomData, ops::Mul};

// #[cfg(feature = "benchmarking")]
// pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Uint};
use language::GroupsPublicParameters;
use schnorr::language;
use serde::{Deserialize, Serialize};

use crate::{
    homomorphic_encryption,
    homomorphic_encryption::GroupsPublicParametersAccessors as _,
    commitments::{GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme},
    group,
    group::{
        direct_product, direct_product::ThreeWayPublicParameters, paillier, self_product,
        BoundedGroupElement, GroupElement as _, KnownOrderGroupElement, KnownOrderScalar,
        Samplable,
    },
    proofs,
    proofs::{
        range,
        range::CommitmentSchemeMessageSpaceGroupElement,
        schnorr,
        schnorr::{
            aggregation, proof::SOUND_PROOFS_REPETITIONS,
            enhanced::{
                DecomposableWitness, EnhanceableLanguage, EnhancedLanguageStatementAccessors as _,
                EnhancedLanguageWitnessAccessors as _,
            },
        },
    },
    AdditivelyHomomorphicEncryptionKey, ComputationalSecuritySizedNumber,
    StatisticalSecuritySizedNumber,
};


/// Encryption of a Tuple Schnorr Language
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
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Witness Space Group Element of the Encryption of a Tuple Schnorr Language.
pub type WitnessSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> = direct_product::ThreeWayGroupElement<
    EncryptionKey::PlaintextSpaceGroupElement,
    EncryptionKey::RandomnessSpaceGroupElement,
    EncryptionKey::RandomnessSpaceGroupElement,
>;

/// The Statement Space Group Element of the Encryption of a Tuple Schnorr Language.
pub type StatementSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> = self_product::GroupElement<2, EncryptionKey::CiphertextSpaceGroupElement>;

/// The Public Parameters of the Encryption of a Tuple Schnorr Language.
pub type PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> = private::PublicParameters<
    group::PublicParameters<GroupElement::Scalar>,
    group::PublicParameters<EncryptionKey::PlaintextSpaceGroupElement>,
    group::PublicParameters<EncryptionKey::RandomnessSpaceGroupElement>,
    group::PublicParameters<EncryptionKey::CiphertextSpaceGroupElement>,
    EncryptionKey::PublicParameters,
    group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
>;

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<SOUND_PROOFS_REPETITIONS>
    for Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>
{
    type WitnessSpaceGroupElement =
        WitnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;

    type StatementSpaceGroupElement =
        StatementSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, EncryptionKey>;

    type PublicParameters =
        PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>;

    const NAME: &'static str = "Encryption of a Tuple";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let group_order = GroupElement::Scalar::order_from_public_parameters(
            &language_public_parameters.scalar_group_public_parameters,
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let ciphertext =
            homomorphic_encryption::CiphertextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
                language_public_parameters.ciphertext,
                &language_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        // TODO: name?
        let encrypted_multiplicand = encryption_key
            .encrypt_with_randomness(witness.multiplicand(), witness.multiplicand_randomness());

        // no mask needed, as we're not doing any homomorphic additions? TODO: why
        let mask = witness.multiplicand().neutral();

        // TODO: name?
        let encrypted_product = encryption_key
            .evaluate_circuit_private_linear_combination_with_randomness(
                &[*witness.multiplicand()],
                &[ciphertext],
                &group_order,
                &mask,
                witness.product_randomness(),
            )?;

        Ok([encrypted_multiplicand, encrypted_product].into())
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        SOUND_PROOFS_REPETITIONS,
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
    >
    for Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        GroupElement,
        homomorphic_encryption::paillier::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: &[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
             RANGE_CLAIMS_PER_SCALAR],
        unbounded_witness: &self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<Self::WitnessSpaceGroupElement> {
        let multiplicand = <paillier::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            SCALAR_LIMBS,
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            // TODO: make sure this is safe, e.g. SCALAR_LIMBS >=
            // COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
            &decomposed_witness.map(|range_claim| (&range_claim).into()),
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        let multiplicand_randomness = <[_; 2]>::from(*unbounded_witness)[0];
        let product_randomness = <[_; 2]>::from(*unbounded_witness)[1];

        Ok((multiplicand, multiplicand_randomness, product_randomness).into())
    }

    fn decompose_witness(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> proofs::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR],
        self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
    )> {
        let multiplicand_value: Uint<SCALAR_LIMBS> = (&witness.multiplicand().value()).into();
        let multiplicand = GroupElement::Scalar::new(
            multiplicand_value.into(),
            &language_public_parameters.scalar_group_public_parameters,
        )?;

        Ok((
            multiplicand.decompose(range_claim_bits),
            [
                *witness.multiplicand_randomness(),
                *witness.product_randomness(),
            ]
            .into(),
        ))
    }
}

pub(super) mod private {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Clone)]
    pub struct PublicParameters<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    > {
        pub groups_public_parameters: GroupsPublicParameters<
            direct_product::ThreeWayPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
        >,
        pub scalar_group_public_parameters: ScalarPublicParameters,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        // TODO: name
        pub ciphertext: CiphertextSpaceValue,
    }
}

impl<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::ThreeWayPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
        >,
    >
    for private::PublicParameters<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        ThreeWayPublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
        CiphertextSpaceValue,
    >
    private::PublicParameters<
        ScalarPublicParameters,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
{
    pub fn new<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey,
    >(
        scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        ciphertext: CiphertextSpaceValue,
    ) -> Self
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
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
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                )
                    .into(),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, EncryptionKey::CiphertextSpaceGroupElement>,
                >::new(
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                ),
            },
            scalar_group_public_parameters,
            encryption_scheme_public_parameters,
            ciphertext,
        }
    }
}

pub trait WitnessAccessors<
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    // TODO: names
    fn multiplicand(&self) -> &PlaintextSpaceGroupElement;

    fn multiplicand_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn product_randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::ThreeWayGroupElement<
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
        RandomnessSpaceGroupElement,
    >
{
    fn multiplicand(&self) -> &PlaintextSpaceGroupElement {
        let (multiplicand, ..): (&_, &_, &_) = self.into();

        multiplicand
    }

    fn multiplicand_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, multiplicand_randomness, _): (&_, &_, &_) = self.into();

        multiplicand_randomness
    }

    fn product_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, _, product_randomness): (&_, &_, &_) = self.into();

        product_randomness
    }
}

pub trait StatementAccessors<CiphertextSpaceGroupElement: group::GroupElement> {
    // TODO: names
    fn encrypted_multiplicand(&self) -> &CiphertextSpaceGroupElement;

    fn encrypted_product(&self) -> &CiphertextSpaceGroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement>
    for self_product::GroupElement<2, CiphertextSpaceGroupElement>
{
    fn encrypted_multiplicand(&self) -> &CiphertextSpaceGroupElement {
        let value: &[_; 2] = self.into();

        &value[0]
    }

    fn encrypted_product(&self) -> &CiphertextSpaceGroupElement {
        let value: &[_; 2] = self.into();

        &value[1]
    }
}

pub type EnhancedProof<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
    UnboundedWitnessSpaceGroupElement,
    RangeProof,
    ProtocolContext,
> = schnorr::enhanced::Proof<
    SOUND_PROOFS_REPETITIONS,
    NUM_RANGE_CLAIMS,
    MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>,
    ProtocolContext,
>;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::{array, iter};

    use crypto_bigint::{NonZero, Random, U128, U256};
    use paillier::tests::N;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        homomorphic_encryption::paillier,
        commitments::Pedersen,
        group::{ristretto, secp256k1, self_product},
        proofs::schnorr::{aggregation, language},
        ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
    };

    pub type Lang = Language<
        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { U256::LIMBS },
        secp256k1::GroupElement,
        paillier::EncryptionKey,
    >;

    use crate::{
        commitments::pedersen,
        proofs::schnorr::language::enhanced::tests::{
            enhanced_language_public_parameters, generate_scalar_plaintext, RANGE_CLAIMS_PER_SCALAR,
        },
    };

    pub(crate) fn public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters = homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let plaintext = paillier::PlaintextSpaceGroupElement::new(
            // TODO: random?
            Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64(42u64),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext = paillier_encryption_key
            .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
            .unwrap()
            .1
            .value();

        let language_public_parameters = PublicParameters::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >::new::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >(
            secp256k1_scalar_public_parameters,
            paillier_public_parameters,
            ciphertext,
        );

        language_public_parameters
    }

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let multiplicand = generate_scalar_plaintext();

            let multiplicand_randomness = paillier::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let product_randomness = paillier::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (multiplicand, multiplicand_randomness, product_randomness).into()
        })
        .take(batch_size)
        .collect()
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();
        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        let unbounded_witness_public_parameters = self_product::PublicParameters::new(
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        schnorr::proof::enhanced::tests::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 2)]
    #[case(8, 1)]
    #[case(8, 4)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = self_product::PublicParameters::new(
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        schnorr::proof::enhanced::tests::aggregates::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }
}

// #[cfg(any(test, feature = "benchmarking"))]
// pub(crate) mod tests {
//     use crypto_bigint::{NonZero, Random};
//     use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
//     use paillier::tests::N;
//     use rand_core::OsRng;
//     use rstest::rstest;
//
//     use super::*;
//     use crate::{
//         homomorphic_encryption::paillier,
//         group::{ristretto, secp256k1, self_product},
//         proofs::{
//             range,
//             range::bulletproofs,
//             schnorr::{aggregation, language},
//             RangeProof,
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
//         language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
//         language::enhanced::RangeProofPublicParameters<
//             SOUND_PROOFS_REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//
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
//         let paillier_public_parameters = homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();
//
//         let plaintext = paillier::PlaintextGroupElement::new(
//             Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from_u64(42u64),
//             paillier_public_parameters.plaintext_space_public_parameters(),
//         )
//         .unwrap();
//
//         let paillier_public_parameters = homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();
//
//         let paillier_encryption_key =
//             paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();
//
//         let ciphertext = paillier_encryption_key
//             .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
//             .unwrap()
//             .1
//             .value();
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
//             bulletproofs_public_parameters.clone(),
//             paillier_public_parameters,
//             ciphertext,
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
//             SOUND_PROOFS_REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//
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
//             SOUND_PROOFS_REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//
//             Lang,
//         >(&language_public_parameters, number_of_parties, batch_size);
//
//         aggregation::tests::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(&language_public_parameters,
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
//             SOUND_PROOFS_REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             RANGE_CLAIMS_PER_SCALAR,
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//
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
//         language::tests::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
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
//     use language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS};
//
//     use super::*;
//     use crate::{
//         homomorphic_encryption::paillier,
//         group::{ristretto, secp256k1},
//         proofs::{
//             range,
//             schnorr::{
//                 aggregation, language,
//                 language::encryption_of_tuple::tests::{public_parameters, Lang},
//             },
//         },
//         ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
//     };
//
//     pub(crate) fn benchmark(c: &mut Criterion) {
//         let (language_public_parameters, range_proof_public_parameters) = public_parameters();
//
//         language::benchmark::<SOUND_PROOFS_REPETITIONS, Lang>(language_public_parameters.clone(), None, c);
//
//         range::benchmark::<
//             SOUND_PROOFS_REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             { RANGE_CLAIMS_PER_SCALAR },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//
//             Lang,
//         >(
//             &language_public_parameters,
//             &range_proof_public_parameters,
//             c,
//         );
//
//         aggregation::benchmark_enhanced::<
//             SOUND_PROOFS_REPETITIONS,
//             { ristretto::SCALAR_LIMBS },
//             { RANGE_CLAIMS_PER_SCALAR },
//             { range::bulletproofs::RANGE_CLAIM_LIMBS },
//
//             Lang,
//         >(language_public_parameters, None, c);
//     }
// }
