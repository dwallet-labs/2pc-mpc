// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::{
    benchmark_lightningproofs_dcom_eval, benchmark_lightningproofs_encdl,
    benchmark_lightningproofs_single_message, benchmark_zero_knowledge,
};
pub use language::aliases::knowledge_of_decommitment::*;
use serde::{Deserialize, Serialize};

use super::GroupsPublicParameters;
use crate::{
    commitments::{HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{direct_product, self_product, BoundedGroupElement, Samplable},
    proofs,
    proofs::{
        schnorr,
        schnorr::{aggregation, language},
    },
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
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Language<
    const REPETITIONS: usize,
    const BATCH_SIZE: usize,
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
        const BATCH_SIZE: usize,
        const SCALAR_LIMBS: usize,
        Scalar: LanguageScalar<SCALAR_LIMBS, GroupElement>,
        GroupElement: group::GroupElement,
        CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, BATCH_SIZE, Scalar, GroupElement>,
    > schnorr::Language<REPETITIONS>
    for Language<REPETITIONS, BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
{
    type WitnessSpaceGroupElement =
        direct_product::GroupElement<self_product::GroupElement<BATCH_SIZE, Scalar>, Scalar>;
    type StatementSpaceGroupElement = GroupElement;

    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
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
        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok(commitment_scheme.commit(
            &witness.commitment_message(),
            witness.commitment_randomness(),
        ))
    }
}

pub trait WitnessAccessors<const BATCH_SIZE: usize, Scalar: group::GroupElement> {
    fn commitment_message(&self) -> &self_product::GroupElement<BATCH_SIZE, Scalar>;

    fn commitment_randomness(&self) -> &Scalar;
}

impl<const BATCH_SIZE: usize, Scalar: group::GroupElement> WitnessAccessors<BATCH_SIZE, Scalar>
    for direct_product::GroupElement<self_product::GroupElement<BATCH_SIZE, Scalar>, Scalar>
{
    fn commitment_message(&self) -> &self_product::GroupElement<BATCH_SIZE, Scalar> {
        let value: (&self_product::GroupElement<BATCH_SIZE, Scalar>, &Scalar) = self.into();

        value.0
    }

    fn commitment_randomness(&self) -> &Scalar {
        let value: (&self_product::GroupElement<BATCH_SIZE, Scalar>, &Scalar) = self.into();

        value.1
    }
}

// TODO: these types & names, implement RangeProof for them
pub const ZERO_KNOWLEDGE_REPETITIONS: usize = 1;

pub type ZeroKnowledgeLanguage<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> =
    Language<ZERO_KNOWLEDGE_REPETITIONS, 1, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>;

type RangeProofLanguage<const SCALAR_LIMBS: usize, const BATCH_SIZE: usize, Scalar, GroupElement> =
    Language<
        // TODO: should this be const? or parameterized
        128,
        BATCH_SIZE,
        SCALAR_LIMBS,
        Scalar,
        GroupElement,
        // TODO: actually we can use a different randomizer and message spaces, e.g. allowing
        // infinite range (integer commitments)
        Pedersen<1, SCALAR_LIMBS, Scalar, GroupElement>,
    >;

/// The Public Parameters of the Knowledge of Decommitment Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    ScalarPublicParameters,
    GroupElementPublicParameters,
    CommitmentSchemePublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::PublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            ScalarPublicParameters,
        >,
        GroupElementPublicParameters,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters: Clone,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
    >
    PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
    >
{
    pub fn new<
        const REPETITIONS: usize,
        const SCALAR_LIMBS: usize,
        Scalar: LanguageScalar<SCALAR_LIMBS, GroupElement>,
        GroupElement,
        CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, BATCH_SIZE, Scalar, GroupElement>,
    >(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<PublicParameters = GroupElementPublicParameters>,
        CommitmentScheme: HomomorphicCommitmentScheme<
            SCALAR_LIMBS,
            PublicParameters = CommitmentSchemePublicParameters,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: direct_product::PublicParameters(
                    self_product::PublicParameters::<BATCH_SIZE, ScalarPublicParameters>::new(
                        scalar_group_public_parameters.clone(),
                    ),
                    scalar_group_public_parameters,
                ),
                statement_space_public_parameters: group_public_parameters,
            },
            commitment_scheme_public_parameters,
        }
    }
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
                ScalarPublicParameters,
            >,
            GroupElementPublicParameters,
        >,
    >
    for PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupElementPublicParameters,
        CommitmentSchemePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            ScalarPublicParameters,
        >,
        GroupElementPublicParameters,
    > {
        &self.groups_public_parameters
    }
}

#[cfg(any(test, feature = "benchmarking"))]
mod tests {
    use core::array;

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

    pub(crate) type Secp256k1Language<const REPETITIONS: usize, const BATCH_SIZE: usize> = Language<
        REPETITIONS,
        BATCH_SIZE,
        { secp256k1::SCALAR_LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        Pedersen<
            BATCH_SIZE,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >,
    >;

    pub(crate) fn secp256k1_language_public_parameters<
        const REPETITIONS: usize,
        const BATCH_SIZE: usize,
    >() -> language::PublicParameters<REPETITIONS, Secp256k1Language<REPETITIONS, BATCH_SIZE>> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let message_generators = array::from_fn(|_| {
            let generator =
                secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
                    * generator;

            generator.value()
        });

        let randomness_generator =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap()
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

        PublicParameters::new::<
            REPETITIONS,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Pedersen<
                BATCH_SIZE,
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
            >,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            pedersen_public_parameters,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    // TODO: take pp and reps as parameters to avoid code duplication, do this for all tests
    fn zero_knowledge_valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = secp256k1_language_public_parameters::<1, 1>();

        language::tests::valid_proof_verifies::<1, Secp256k1Language<1, 1>>(
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
        let language_public_parameters = secp256k1_language_public_parameters::<128, 1>();

        language::tests::valid_proof_verifies::<128, Secp256k1Language<128, 1>>(
            language_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = secp256k1_language_public_parameters::<1, 1>();
        let witnesses = language::tests::generate_witnesses_for_aggregation::<
            1,
            Secp256k1Language<1, 1>,
        >(&language_public_parameters, number_of_parties, batch_size);

        aggregation::tests::aggregates::<1, Secp256k1Language<1, 1>>(
            &language_public_parameters,
            witnesses,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = secp256k1_language_public_parameters::<1, 1>();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        language::tests::invalid_proof_fails_verification::<1, Secp256k1Language<1, 1>>(
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
        let language_public_parameters = secp256k1_language_public_parameters::<1, 1>();

        language::benchmark::<1, Secp256k1Language<1, 1>>(
            language_public_parameters.clone(),
            Some("zk".to_string()),
            c,
        );

        aggregation::benchmark::<1, Secp256k1Language<1, 1>>(
            language_public_parameters,
            Some("zk".to_string()),
            c,
        );
    }

    pub(crate) fn benchmark_lightningproofs_single_message(c: &mut Criterion) {
        let language_public_parameters = secp256k1_language_public_parameters::<128, 1>();

        language::benchmark::<128, Secp256k1Language<128, 1>>(
            language_public_parameters.clone(),
            Some("single".to_string()),
            c,
        );

        aggregation::benchmark::<128, Secp256k1Language<128, 1>>(
            language_public_parameters,
            Some("single".to_string()),
            c,
        );
    }

    pub(crate) fn benchmark_lightningproofs_encdl(c: &mut Criterion) {
        let language_public_parameters = secp256k1_language_public_parameters::<128, 2>();

        language::benchmark::<128, Secp256k1Language<128, 2>>(
            language_public_parameters.clone(),
            Some("EncDL".to_string()),
            c,
        );

        aggregation::benchmark::<128, Secp256k1Language<128, 2>>(
            language_public_parameters,
            Some("EncDL".to_string()),
            c,
        );
    }

    pub(crate) fn benchmark_lightningproofs_dcom_eval(c: &mut Criterion) {
        let language_public_parameters = secp256k1_language_public_parameters::<128, 7>();

        language::benchmark::<128, Secp256k1Language<128, 7>>(
            language_public_parameters.clone(),
            Some("DComEval".to_string()),
            c,
        );

        aggregation::benchmark::<128, Secp256k1Language<128, 7>>(
            language_public_parameters,
            Some("DComEval".to_string()),
            c,
        );
    }
}
