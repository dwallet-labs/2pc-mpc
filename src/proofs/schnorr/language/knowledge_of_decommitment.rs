// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::{
    benchmark_lightningproofs_dcom_eval, benchmark_lightningproofs_encdl,
    benchmark_lightningproofs_single_message, benchmark_zero_knowledge,
};
// pub use language::aliases::knowledge_of_decommitment::*;
use serde::{Deserialize, Serialize};

use super::GroupsPublicParameters;
use crate::{
    commitments,
    commitments::{GroupsPublicParametersAccessors, HomomorphicCommitmentScheme},
    group,
    group::{direct_product, self_product, BoundedGroupElement, Samplable},
    proofs,
    proofs::{
        schnorr,
        schnorr::{aggregation, language},
    },
    ComputationalSecuritySizedNumber,
};

// TODO: name
pub const ZERO_KNOWLEDGE_REPETITIONS: usize = 1;

/// Knowledge of Decommitment Schnorr Language.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const REPETITIONS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
> {
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<
        const REPETITIONS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
    > schnorr::Language<REPETITIONS>
    for Language<REPETITIONS, MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>
where
    CommitmentScheme::MessageSpaceGroupElement: Samplable,
    CommitmentScheme::RandomnessSpaceGroupElement: Samplable,
{
    type WitnessSpaceGroupElement = direct_product::GroupElement<
        CommitmentScheme::MessageSpaceGroupElement,
        CommitmentScheme::RandomnessSpaceGroupElement,
    >;
    type StatementSpaceGroupElement = CommitmentScheme::CommitmentSpaceGroupElement;

    type PublicParameters = PublicParameters<
        group::PublicParameters<CommitmentScheme::MessageSpaceGroupElement>,
        group::PublicParameters<CommitmentScheme::RandomnessSpaceGroupElement>,
        group::PublicParameters<CommitmentScheme::CommitmentSpaceGroupElement>,
        CommitmentScheme::PublicParameters,
    >;

    const NAME: &'static str = "Knowledge of Decommitment";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok(commitment_scheme.commit(
            witness.commitment_message(),
            witness.commitment_randomness(),
        ))
    }
}

pub trait WitnessAccessors<
    CommitmentSchemeMessageSpaceGroupElement,
    CommitmentSchemeRandomnessSpaceGroupElement,
>
{
    fn commitment_message(&self) -> &CommitmentSchemeMessageSpaceGroupElement;

    fn commitment_randomness(&self) -> &CommitmentSchemeRandomnessSpaceGroupElement;
}

impl<CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement>
    WitnessAccessors<
        CommitmentSchemeMessageSpaceGroupElement,
        CommitmentSchemeRandomnessSpaceGroupElement,
    >
    for direct_product::GroupElement<
        CommitmentSchemeMessageSpaceGroupElement,
        CommitmentSchemeRandomnessSpaceGroupElement,
    >
{
    fn commitment_message(&self) -> &CommitmentSchemeMessageSpaceGroupElement {
        let value: (&_, &_) = self.into();

        value.0
    }

    fn commitment_randomness(&self) -> &CommitmentSchemeRandomnessSpaceGroupElement {
        let value: (&_, &_) = self.into();

        value.1
    }
}

/// The Public Parameters of the Knowledge of Decommitment Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::PublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        CommitmentSpacePublicParameters,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
}

impl<
        MessageSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
        CommitmentSchemePublicParameters,
    >
    PublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    >
{
    pub fn new<
        const REPETITIONS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme,
    >(
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    ) -> Self
    where
        CommitmentScheme::MessageSpaceGroupElement:
            group::GroupElement<PublicParameters = MessageSpacePublicParameters>,
        CommitmentScheme::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentScheme::CommitmentSpaceGroupElement:
            group::GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        CommitmentScheme: HomomorphicCommitmentScheme<
            MESSAGE_SPACE_SCALAR_LIMBS,
            PublicParameters = CommitmentSchemePublicParameters,
        >,
        CommitmentSchemePublicParameters: AsRef<
            commitments::GroupsPublicParameters<
                MessageSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: direct_product::PublicParameters(
                    commitment_scheme_public_parameters
                        .message_space_public_parameters()
                        .clone(),
                    commitment_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                ),
                statement_space_public_parameters: commitment_scheme_public_parameters
                    .commitment_space_public_parameters()
                    .clone(),
            },
            commitment_scheme_public_parameters,
        }
    }
}

impl<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                MessageSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            CommitmentSpacePublicParameters,
        >,
    >
    for PublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        CommitmentSpacePublicParameters,
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
        { secp256k1::SCALAR_LIMBS },
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
        PublicParameters::new::<
            REPETITIONS,
            { secp256k1::SCALAR_LIMBS },
            Pedersen<
                BATCH_SIZE,
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
            >,
        >(
            pedersen::PublicParameters::default::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
            >()
            .unwrap(),
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
