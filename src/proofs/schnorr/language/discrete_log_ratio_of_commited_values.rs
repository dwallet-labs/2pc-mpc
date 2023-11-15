// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
use std::{marker::PhantomData, ops::Mul};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
use serde::{Deserialize, Serialize};

use super::GroupsPublicParameters;
use crate::{
    commitments,
    commitments::{pedersen, HomomorphicCommitmentScheme, Pedersen},
    group,
    group::{self_product, CyclicGroupElement, GroupElement, KnownOrderGroupElement, Samplable},
    proofs,
    proofs::{
        schnorr,
        schnorr::{aggregation, language},
    },
};

pub(crate) const REPETITIONS: usize = 1;

/// Ratio Between Committed Values is the Discrete Log Schnorr Language.
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However knowledge-soundness proofs are group dependent, and thus we can only assure security for
/// groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
}
impl<const SCALAR_LIMBS: usize, Scalar, GroupElement> schnorr::Language<REPETITIONS>
    for Language<SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: group::GroupElement,
{
    type WitnessSpaceGroupElement = self_product::GroupElement<3, Scalar>;
    type StatementSpaceGroupElement = self_product::GroupElement<2, GroupElement>;

    type PublicParameters = PublicParameters<
        super::WitnessSpacePublicParameters<REPETITIONS, Self>,
        super::StatementSpacePublicParameters<REPETITIONS, Self>,
        commitments::PublicParameters<
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, Scalar, GroupElement>,
        >,
        GroupElement::Value,
    >;
    const NAME: &'static str = "Ratio Between Committed Values is the Discrete Log";

    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> proofs::Result<Self::StatementSpaceGroupElement> {
        let [message, first_randomness, second_randomness]: &[Scalar; 3] = witness.into();

        let commitment_scheme =
            Pedersen::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        // The paper specifies a trick to transform this langauge into a homomorphism:
        // Use $g^x$ as the base for the message of the second commitment, and then the commitment
        // on $m*x$ becomes the commitment on $m$, with the discrete log $x$ now appearing
        // in the message base of the second commitment.
        // TODO: can we assure somehow that the generators are independent (message from
        // randomness)?
        let altered_base_commitment_scheme_public_parameters =
            pedersen::public_parameters::<1, SCALAR_LIMBS, Scalar, GroupElement>(
                language_public_parameters
                    .groups_public_parameters
                    .witness_space_public_parameters
                    .public_parameters
                    .clone(),
                language_public_parameters
                    .groups_public_parameters
                    .statement_space_public_parameters
                    .public_parameters
                    .clone(),
                [language_public_parameters.base_by_discrete_log],
                language_public_parameters
                    .commitment_scheme_public_parameters
                    .randomness_generator
                    .clone(),
            );

        let altered_base_commitment_scheme =
            Pedersen::new(&altered_base_commitment_scheme_public_parameters)?;

        Ok([
            commitment_scheme.commit(&[*message].into(), first_randomness),
            altered_base_commitment_scheme.commit(&[*message].into(), second_randomness),
        ]
        .into())
    }
}

/// The Public Parameters of the Ratio Between Committed Values is the Discrete Log Schnorr
/// Language.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PublicParameters<
    WitnessSpacePublicParameters,
    StatementSpacePublicParameters,
    PedersenPublicParameters,
    GroupElementValue,
> {
    pub groups_public_parameters:
        GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>,
    commitment_scheme_public_parameters: PedersenPublicParameters,
    // The base $g$ by the discrete log (witness $x$) $g^x$ used as the public key in the paper.
    base_by_discrete_log: GroupElementValue,
}

impl<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        PedersenPublicParameters,
        GroupElementValue,
    > AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
    for PublicParameters<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        PedersenPublicParameters,
        GroupElementValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
        &self.groups_public_parameters
    }
}

/// The Public Parameters of a Ratio Between Committed Values is the Discrete Log Schnorr Language.
pub type LanguagePublicParameters<const SCALAR_LIMBS: usize, Scalar, GroupElement> =
    language::PublicParameters<REPETITIONS, Language<SCALAR_LIMBS, Scalar, GroupElement>>;

/// A Ratio Between Committed Values is the Discrete Log Schnorr Proof.
pub type Proof<const SCALAR_LIMBS: usize, Scalar, GroupElement, ProtocolContext> =
    schnorr::Proof<REPETITIONS, Language<SCALAR_LIMBS, Scalar, GroupElement>, ProtocolContext>;

/// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Proof Aggregation Commitment
/// Round Party.
pub type ProofAggregationCommitmentRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    ProtocolContext,
> = aggregation::commitment_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement>,
    ProtocolContext,
>;

/// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Decommitment
/// Round Party.
pub type ProofAggregationDecommitmentRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    ProtocolContext,
> = aggregation::decommitment_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement>,
    ProtocolContext,
>;

/// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Proof Share Round
/// Party.
pub type ProofAggregationProofShareRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    ProtocolContext,
> = aggregation::proof_share_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement>,
    ProtocolContext,
>;

/// A Ratio Between Committed Values is the Discrete Log Schnorr Proof Aggregation Proof Aggregation
/// Round Party.
pub type ProofAggregationProofAggregationRoundParty<
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    ProtocolContext,
> = aggregation::proof_aggregation_round::Party<
    REPETITIONS,
    Language<SCALAR_LIMBS, Scalar, GroupElement>,
    ProtocolContext,
>;

#[cfg(any(test, feature = "benchmarking"))]
mod tests {
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        commitments::pedersen,
        group,
        group::{secp256k1, GroupElement, Samplable},
        proofs::schnorr::{aggregation, language},
    };

    pub(crate) type Lang =
        Language<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>;

    pub(crate) fn language_public_parameters() -> language::PublicParameters<REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let discrete_log =
            secp256k1::Scalar::sample(&mut OsRng, &secp256k1_scalar_public_parameters).unwrap();

        let base_by_discrete_log = discrete_log * generator;

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
                    self_product::GroupElement<3, secp256k1::Scalar>,
                >::new(
                    secp256k1_scalar_public_parameters.clone()
                ),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, secp256k1::GroupElement>,
                >::new(
                    secp256k1_group_public_parameters.clone()
                ),
            },
            commitment_scheme_public_parameters: pedersen_public_parameters,
            base_by_discrete_log: base_by_discrete_log.value(),
        }
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        language::tests::valid_proof_verifies::<REPETITIONS, Lang>(
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
        let language_public_parameters = language_public_parameters();
        let witnesses = language::tests::generate_witnesses_for_aggregation::<REPETITIONS, Lang>(
            &language_public_parameters,
            number_of_parties,
            batch_size,
        );

        aggregation::tests::aggregates::<REPETITIONS, Lang>(&language_public_parameters, witnesses)
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
        language::tests::invalid_proof_fails_verification::<REPETITIONS, Lang>(
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
            language::discrete_log_ratio_of_commited_values::{
                tests::{language_public_parameters, Lang},
                REPETITIONS,
            },
        },
    };

    pub(crate) fn benchmark(c: &mut Criterion) {
        let language_public_parameters = language_public_parameters();

        language::benchmark::<REPETITIONS, Lang>(language_public_parameters.clone(), c);

        aggregation::benchmark::<REPETITIONS, Lang>(language_public_parameters, c);
    }
}
