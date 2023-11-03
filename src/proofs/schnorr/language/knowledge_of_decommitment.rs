// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::{benchmark_secp256k1_range_proof, benchmark_zero_knowledge};
use serde::{Deserialize, Serialize};

use super::GroupsPublicParameters;
use crate::{
    commitments::{HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{self_product, BoundedGroupElement, Samplable},
    proofs,
    proofs::schnorr,
};

/// Knowledge of Decommitment Schnorr Language.
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However knowledge-soundness proofs are group dependent, and thus we can only assure security for
/// groups for which we know how to prove it.
///
/// In the paper, we have prove (or cited a proof) it for any prime known-order group or for
/// Paillier groups based on safe-primes; so it is safe to use with a `PrimeOrderGroupElement` or
/// `PaillierGroupElement`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Language<
    const REPETITIONS: usize,
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar,
        GroupElement,
        CommitmentScheme,
    > schnorr::Language<REPETITIONS>
    for Language<REPETITIONS, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
where
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: group::GroupElement,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
        // TODO: do we need to enforce that? I believe we don't care about randomness.
        RandomnessSpaceGroupElement = Scalar,
        CommitmentSpaceGroupElement = GroupElement,
    >,
{
    type WitnessSpaceGroupElement = self_product::GroupElement<2, Scalar>;
    type StatementSpaceGroupElement = GroupElement;

    type PublicParameters = PublicParameters<
        super::WitnessSpacePublicParameters<REPETITIONS, Self>,
        super::StatementSpacePublicParameters<REPETITIONS, Self>,
        CommitmentScheme::PublicParameters,
    >;

    const NAME: &'static str = "Knowledge of Decommitment";

    /// The number of bits to use for the challenge
    fn challenge_bits(number_of_parties: usize, batch_size: usize) -> usize {
        // TODO ...
        if REPETITIONS == 1 {
            128
        } else {
            1
        }
    }

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok(commitment_scheme.commit(&[*value].into(), randomness))
    }
}

// TODO: these types & names
type ZeroKnowledgeLanguage<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> =
    Language<1, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>;

type RangeProofLanguage<const SCALAR_LIMBS: usize, Scalar, GroupElement> = Language<
    // TODO: should this be const? or parameterized
    128,
    SCALAR_LIMBS,
    Scalar,
    GroupElement,
    // TODO: actually we can use a different randomizer and message spaces, e.g. allowing infinite
    // range (integer commitments)
    Pedersen<1, SCALAR_LIMBS, Scalar, GroupElement>,
>;

/// The Public Parameters of the Knowledge of Decommitment Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    WitnessSpacePublicParameters,
    StatementSpacePublicParameters,
    CommitmentSchemePublicParameters,
> {
    pub groups_public_parameters:
        GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
}

impl<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
    > AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
    for PublicParameters<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
        &self.groups_public_parameters
    }
}

#[cfg(any(test, feature = "benchmarking"))]
mod tests {
    use crypto_bigint::{modular::runtime_mod::DynResidue, Random, U2048};
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::LargeBiPrimeSizedNumber;

    use super::*;
    use crate::{
        ahe::paillier::tests::N,
        commitments::{pedersen, Pedersen},
        group::{multiplicative_group_of_integers_modulu_n, secp256k1, GroupElement, Samplable},
        proofs::schnorr::{aggregation, language, language::Language as _},
    };

    pub(crate) type Secp256k1Language<const REPETITIONS: usize> = Language<
        REPETITIONS,
        { secp256k1::SCALAR_LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        Pedersen<1, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
    >;

    // TODO: name
    pub(crate) type RSALanguage = Language<
        128,
        { LargeBiPrimeSizedNumber::LIMBS },
        multiplicative_group_of_integers_modulu_n::GroupElement<{ LargeBiPrimeSizedNumber::LIMBS }>,
        multiplicative_group_of_integers_modulu_n::GroupElement<{ LargeBiPrimeSizedNumber::LIMBS }>,
        Pedersen<
            1,
            { LargeBiPrimeSizedNumber::LIMBS },
            multiplicative_group_of_integers_modulu_n::GroupElement<
                { LargeBiPrimeSizedNumber::LIMBS },
            >,
            multiplicative_group_of_integers_modulu_n::GroupElement<
                { LargeBiPrimeSizedNumber::LIMBS },
            >,
        >,
    >;

    pub(crate) fn range_proof_rsa_language_public_parameters(
    ) -> language::PublicParameters<128, RSALanguage> {
        let group_public_parameters =
            multiplicative_group_of_integers_modulu_n::PublicParameters::<
                { LargeBiPrimeSizedNumber::LIMBS },
            >::new(N)
            .unwrap();

        let generator =
            multiplicative_group_of_integers_modulu_n::GroupElement::<
                { LargeBiPrimeSizedNumber::LIMBS },
            >::new(
                multiplicative_group_of_integers_modulu_n::Value::<
                    { LargeBiPrimeSizedNumber::LIMBS },
                >::new(
                    LargeBiPrimeSizedNumber::from(2u8), // TODO?
                    &group_public_parameters,
                )
                .unwrap(),
                &group_public_parameters,
            )
            .unwrap();

        let message_generator = multiplicative_group_of_integers_modulu_n::GroupElement::<
            { LargeBiPrimeSizedNumber::LIMBS },
        >::sample(&mut OsRng, &group_public_parameters)
        .unwrap()
            * generator;

        let randomness_generator = multiplicative_group_of_integers_modulu_n::GroupElement::<
            { LargeBiPrimeSizedNumber::LIMBS },
        >::sample(&mut OsRng, &group_public_parameters)
        .unwrap()
            * generator;

        // TODO: this is not safe; we need a proper way to derive generators
        let pedersen_public_parameters = pedersen::public_parameters::<
            1,
            { LargeBiPrimeSizedNumber::LIMBS },
            multiplicative_group_of_integers_modulu_n::GroupElement<
                { LargeBiPrimeSizedNumber::LIMBS },
            >,
            multiplicative_group_of_integers_modulu_n::GroupElement<
                { LargeBiPrimeSizedNumber::LIMBS },
            >,
        >(
            group_public_parameters.clone(),
            group_public_parameters.clone(),
            [message_generator.value()],
            randomness_generator.value(),
        );

        PublicParameters {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<
                        2,
                        multiplicative_group_of_integers_modulu_n::GroupElement<
                            { LargeBiPrimeSizedNumber::LIMBS },
                        >,
                    >,
                >::new(
                    group_public_parameters.clone()
                ),
                statement_space_public_parameters: group_public_parameters,
            },
            commitment_scheme_public_parameters: pedersen_public_parameters,
        }
    }

    pub(crate) fn secp256k1_language_public_parameters<const REPETITIONS: usize>(
    ) -> language::PublicParameters<REPETITIONS, Secp256k1Language<REPETITIONS>> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let message_generator =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
                * generator;

        let randomness_generator =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
                * generator;

        // TODO: this is not safe; we need a proper way to derive generators
        let pedersen_public_parameters = pedersen::public_parameters::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
            [message_generator.value()],
            randomness_generator.value(),
        );

        PublicParameters {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, secp256k1::Scalar>,
                >::new(
                    secp256k1_scalar_public_parameters
                ),
                statement_space_public_parameters: secp256k1_group_public_parameters,
            },
            commitment_scheme_public_parameters: pedersen_public_parameters,
        }
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    // TODO: take pp and reps as parameters to avoid code duplication, do this for all tests
    fn zero_knowledge_valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = secp256k1_language_public_parameters::<1>();

        language::tests::valid_proof_verifies::<1, Secp256k1Language<1>>(
            language_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    // TODO: take pp and reps as parameters to avoid code duplication
    fn range_proof_secp256k1_valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = secp256k1_language_public_parameters::<128>();

        language::tests::valid_proof_verifies::<128, Secp256k1Language<128>>(
            language_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    // TODO: take pp and reps as parameters to avoid code duplication
    fn range_proof_rsa_valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = range_proof_rsa_language_public_parameters();

        language::tests::valid_proof_verifies::<128, RSALanguage>(
            language_public_parameters,
            batch_size,
        )
    }

    #[test]
    fn doesnt_crash_sigsegv2() {
        let doesnt_crash: [u8; 1024 * 293 + 938] = std::array::from_fn(|_| 0u8);
    }

    #[test]
    fn crashes_sigsegv() {
        let mut crashes: [u8; 1024 * 1024 * 1024 * 2] = [0u8; 1024 * 1024 * 1024 * 2];
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = secp256k1_language_public_parameters::<1>();
        let witnesses = language::tests::generate_witnesses_for_aggregation::<
            1,
            Secp256k1Language<1>,
        >(&language_public_parameters, number_of_parties, batch_size);

        aggregation::tests::aggregates::<1, Secp256k1Language<1>>(
            &language_public_parameters,
            witnesses,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = secp256k1_language_public_parameters::<1>();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        language::tests::invalid_proof_fails_verification::<1, Secp256k1Language<1>>(
            None,
            None,
            language_public_parameters,
            batch_size,
        )
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;

    use super::*;
    use crate::{
        group::secp256k1,
        proofs::schnorr::{
            aggregation, language,
            language::knowledge_of_decommitment::tests::{
                secp256k1_language_public_parameters, Secp256k1Language,
            },
        },
    };

    pub(crate) fn benchmark_zero_knowledge(c: &mut Criterion) {
        let language_public_parameters = secp256k1_language_public_parameters::<1>();

        language::benchmark::<1, Secp256k1Language<1>>(language_public_parameters.clone(), c);

        aggregation::benchmark::<1, Secp256k1Language<1>>(language_public_parameters, c);
    }

    pub(crate) fn benchmark_secp256k1_range_proof(c: &mut Criterion) {
        let language_public_parameters = secp256k1_language_public_parameters::<128>();

        language::benchmark::<128, Secp256k1Language<128>>(language_public_parameters.clone(), c);

        aggregation::benchmark::<128, Secp256k1Language<128>>(language_public_parameters, c);
    }
}
