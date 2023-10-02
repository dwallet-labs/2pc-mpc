// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
use serde::Serialize;

use super::GroupsPublicParameters;
use crate::{
    commitments::HomomorphicCommitmentScheme,
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
#[derive(Clone, Serialize)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> schnorr::Language
    for Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
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
        RandomnessSpaceGroupElement = Scalar,
        CommitmentSpaceGroupElement = GroupElement,
    >,
{
    type WitnessSpaceGroupElement = self_product::GroupElement<2, Scalar>;
    type StatementSpaceGroupElement = GroupElement;

    type PublicParameters = PublicParameters<
        super::WitnessSpacePublicParameters<Self>,
        super::StatementSpacePublicParameters<Self>,
        CommitmentScheme::PublicParameters,
    >;

    const NAME: &'static str = "Knowledge of Decommitment";

    fn group_homomorphism(
        witness: &super::WitnessSpaceGroupElement<Self>,
        language_public_parameters: &super::PublicParameters<Self>,
    ) -> proofs::Result<super::StatementSpaceGroupElement<Self>> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok(commitment_scheme.commit(&[*value].into(), randomness))
    }
}

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
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        commitments::{pedersen, Pedersen},
        group::{secp256k1, GroupElement, Samplable},
        proofs::schnorr::language,
    };

    pub(crate) fn language_public_parameters() -> language::PublicParameters<
        Language<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Pedersen<1, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
        >,
    > {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

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
            [secp256k1_group_public_parameters.generator],
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
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        language::tests::valid_proof_verifies::<
            Language<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                Pedersen<
                    1,
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
            >,
        >(language_public_parameters, batch_size)
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        language::tests::invalid_proof_fails_verification::<
            Language<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                Pedersen<
                    1,
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
            >,
        >(None, None, language_public_parameters, batch_size)
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;

    use super::*;
    use crate::{
        commitments::Pedersen,
        group::secp256k1,
        proofs::schnorr::{
            language, language::knowledge_of_decommitment::tests::language_public_parameters,
        },
    };

    pub(crate) fn benchmark(c: &mut Criterion) {
        language::benchmark::<
            Language<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
                Pedersen<
                    1,
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::Scalar,
                    secp256k1::GroupElement,
                >,
            >,
        >(language_public_parameters(), c);
    }
}
