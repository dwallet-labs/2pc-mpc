// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
// todo
// pub use enhanced::{
//     committed_linear_evaluation, encryption_of_discrete_log, encryption_of_tuple,
// EnhancedLanguage, };
use proofs::Result;
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{GroupElement, Samplable, SamplableWithin},
    proofs,
};

pub mod commitment_of_discrete_log;
pub mod discrete_log_ratio_of_commited_values;
// pub mod enhanced;
mod committed_linear_evaluation;
pub mod encryption_of_discrete_log;
pub mod encryption_of_tuple;
pub mod knowledge_of_decommitment;
pub mod knowledge_of_discrete_log;

pub(super) mod enhanced;

// TODO: add + Serialize + for<'a> Deserialize<'a> to the trait ?!? why can't I

// TODO: take REPETITIONS, add bits

/// A Schnorr Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof`.
/// As defined in Appendix B. Schnorr Protocols in the paper.
pub trait Language<
    // Number of times schnorr proofs for this language should be repeated to achieve sufficient security
    const REPETITIONS: usize,
>: Clone + PartialEq {
    /// An element of the witness space $(\HH_\pp, +)$
    // TODO: Theoretically I don't need `SamplableWithin` for the witness of every language, just for the enhanced ones, and even there not necessairily generically. 
    // But can we forsee use-cases for languages that have witneses that doesn't satisfy SamplableWithin?
    type WitnessSpaceGroupElement: GroupElement + SamplableWithin;

    /// An element in the associated statement space $(\GG_\pp, \cdot)$,
    type StatementSpaceGroupElement: GroupElement;

    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$.
    ///
    /// Includes the public parameters of the witness, and statement groups.
    ///
    /// Group public parameters are encoded separately in
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `StatementSpaceGroupElement::PublicParameters`.
    type PublicParameters: AsRef<
        GroupsPublicParameters<
            group::PublicParameters<Self::WitnessSpaceGroupElement>,
            group::PublicParameters<Self::StatementSpaceGroupElement>,
        >,
    > + Serialize
    + PartialEq
    + Clone;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// The number of bits to use for the challenge
    fn challenge_bits(number_of_parties: usize, batch_size: usize) -> usize {
        // TODO: what's the formula?
        128
    }

    /// The subrange of valid values from which the randomizers for the proof should be sampled.
    fn randomizer_subrange(language_public_parameters: &Self::PublicParameters) -> Result<(Self::WitnessSpaceGroupElement, Self::WitnessSpaceGroupElement)> {
        let lower_bound = Self::WitnessSpaceGroupElement::lower_bound(language_public_parameters.witness_space_public_parameters())?;
        let upper_bound = Self::WitnessSpaceGroupElement::upper_bound(language_public_parameters.witness_space_public_parameters())?;

        Ok((lower_bound, upper_bound))
    }

    // TODO: rename to `homomorphose`
    /// A group homomorphism $\phi:\HH\to\GG$  from $(\HH_\pp, +)$, the witness space,
    /// to $(\GG_\pp,\cdot)$, the statement space space.
    fn group_homomorphism(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement>;
}

pub type PublicParameters<const REPETITIONS: usize, L> =
    <L as Language<REPETITIONS>>::PublicParameters;
pub type WitnessSpaceGroupElement<const REPETITIONS: usize, L> =
    <L as Language<REPETITIONS>>::WitnessSpaceGroupElement;
pub type WitnessSpacePublicParameters<const REPETITIONS: usize, L> =
    group::PublicParameters<WitnessSpaceGroupElement<REPETITIONS, L>>;
pub type WitnessSpaceValue<const REPETITIONS: usize, L> =
    group::Value<WitnessSpaceGroupElement<REPETITIONS, L>>;
pub type StatementSpaceGroupElement<const REPETITIONS: usize, L> =
    <L as Language<REPETITIONS>>::StatementSpaceGroupElement;
pub type StatementSpacePublicParameters<const REPETITIONS: usize, L> =
    group::PublicParameters<StatementSpaceGroupElement<REPETITIONS, L>>;
pub type StatementSpaceValue<const REPETITIONS: usize, L> =
    group::Value<StatementSpaceGroupElement<REPETITIONS, L>>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
    pub witness_space_public_parameters: WitnessSpacePublicParameters,
    pub statement_space_public_parameters: StatementSpacePublicParameters,
}

pub trait GroupsPublicParametersAccessors<
    'a,
    WitnessSpacePublicParameters: 'a,
    StatementSpacePublicParameters: 'a,
>:
    AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
{
    fn witness_space_public_parameters(&'a self) -> &'a WitnessSpacePublicParameters {
        &self.as_ref().witness_space_public_parameters
    }

    fn statement_space_public_parameters(&'a self) -> &'a StatementSpacePublicParameters {
        &self.as_ref().statement_space_public_parameters
    }
}

impl<
        'a,
        WitnessSpacePublicParameters: 'a,
        StatementSpacePublicParameters: 'a,
        T: AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>,
    >
    GroupsPublicParametersAccessors<
        'a,
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
    > for T
{
}

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::{iter, marker::PhantomData};

    use rand_core::OsRng;

    use super::*;
    use crate::{
        group,
        proofs::{schnorr::Proof, Error},
    };

    pub(crate) fn generate_witnesses<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        subrange: Option<(
            Lang::WitnessSpaceGroupElement,
            Lang::WitnessSpaceGroupElement,
        )>,
        language_public_parameters: &Lang::PublicParameters,
        batch_size: usize,
    ) -> Vec<Lang::WitnessSpaceGroupElement> {
        iter::repeat_with(|| {
            if let Some((lower_bound, upper_bound)) = &subrange {
                Lang::WitnessSpaceGroupElement::sample_within(
                    (lower_bound, upper_bound),
                    language_public_parameters.witness_space_public_parameters(),
                    &mut OsRng,
                )
                .unwrap()
            } else {
                Lang::WitnessSpaceGroupElement::sample(
                    language_public_parameters.witness_space_public_parameters(),
                    &mut OsRng,
                )
                .unwrap()
            }
        })
        .take(batch_size)
        .collect()
    }

    pub(crate) fn generate_witnesses_for_aggregation<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        subrange: Option<(
            Lang::WitnessSpaceGroupElement,
            Lang::WitnessSpaceGroupElement,
        )>,
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) -> Vec<Vec<Lang::WitnessSpaceGroupElement>> {
        iter::repeat_with(|| {
            generate_witnesses::<REPETITIONS, Lang>(
                subrange.clone(),
                language_public_parameters,
                batch_size,
            )
        })
        .take(number_of_parties)
        .collect()
    }

    pub(crate) fn generate_witness<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        subrange: Option<(
            Lang::WitnessSpaceGroupElement,
            Lang::WitnessSpaceGroupElement,
        )>,
        language_public_parameters: &Lang::PublicParameters,
    ) -> Lang::WitnessSpaceGroupElement {
        let witnesses =
            generate_witnesses::<REPETITIONS, Lang>(subrange, language_public_parameters, 1);

        witnesses.first().unwrap().clone()
    }

    pub(crate) fn generate_valid_proof<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) -> (
        Proof<REPETITIONS, Lang, PhantomData<()>>,
        Vec<Lang::StatementSpaceGroupElement>,
    ) {
        Proof::prove(
            None,
            &PhantomData,
            language_public_parameters,
            witnesses,
            &mut OsRng,
        )
        .unwrap()
    }

    #[allow(dead_code)]
    pub(crate) fn valid_proof_verifies<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        subrange: Option<(
            Lang::WitnessSpaceGroupElement,
            Lang::WitnessSpaceGroupElement,
        )>,
        language_public_parameters: Lang::PublicParameters,
        batch_size: usize,
    ) {
        let witnesses = generate_witnesses::<REPETITIONS, Lang>(
            subrange,
            &language_public_parameters,
            batch_size,
        );

        let (proof, statements) = generate_valid_proof::<REPETITIONS, Lang>(
            &language_public_parameters,
            witnesses.clone(),
        );

        assert!(
            proof
                .verify(None, &PhantomData, &language_public_parameters, statements)
                .is_ok(),
            "valid proofs should verify"
        );
    }

    // TODO: why is this considered as dead code, if its being called from a test in other modules?

    #[allow(dead_code)]
    pub(crate) fn invalid_proof_fails_verification<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        subrange: Option<(
            Lang::WitnessSpaceGroupElement,
            Lang::WitnessSpaceGroupElement,
        )>,
        invalid_witness_space_value: Option<WitnessSpaceValue<REPETITIONS, Lang>>,
        invalid_statement_space_value: Option<StatementSpaceValue<REPETITIONS, Lang>>,
        language_public_parameters: Lang::PublicParameters,
        batch_size: usize,
    ) {
        let witnesses = generate_witnesses::<REPETITIONS, Lang>(
            subrange,
            &language_public_parameters,
            batch_size,
        );

        let (valid_proof, statements) = generate_valid_proof::<REPETITIONS, Lang>(
            &language_public_parameters,
            witnesses.clone(),
        );

        let wrong_witness =
            generate_witness::<REPETITIONS, Lang>(None, &language_public_parameters);

        let wrong_statement =
            Lang::group_homomorphism(&wrong_witness, &language_public_parameters).unwrap();

        assert!(
            matches!(
                valid_proof
                    .verify(
                        None,
                        &PhantomData,
                        &language_public_parameters,
                        statements
                            .clone()
                            .into_iter()
                            .take(batch_size - 1)
                            .chain(vec![wrong_statement.clone()])
                            .collect(),
                    )
                    .err()
                    .unwrap(),
                Error::ProofVerification
            ),
            "valid proof shouldn't verify against wrong statements"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.responses = [wrong_witness.value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(
                        None,
                        &PhantomData,
                        &language_public_parameters,
                        statements.clone(),
                    )
                    .err()
                    .unwrap(),
                Error::ProofVerification
            ),
            "proof with a wrong response shouldn't verify"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.statement_masks = [wrong_statement.neutral().value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(
                        None,
                        &PhantomData,
                        &language_public_parameters,
                        statements.clone(),
                    )
                    .err()
                    .unwrap(),
                Error::ProofVerification
            ),
            "proof with a neutral statement_mask shouldn't verify"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.responses = [wrong_witness.neutral().value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(
                        None,
                        &PhantomData,
                        &language_public_parameters,
                        statements.clone(),
                    )
                    .err()
                    .unwrap(),
                Error::ProofVerification
            ),
            "proof with a neutral response shouldn't verify"
        );

        if let Some(invalid_statement_space_value) = invalid_statement_space_value {
            let mut invalid_proof = valid_proof.clone();
            invalid_proof.statement_masks = [invalid_statement_space_value; REPETITIONS];

            assert!(matches!(
            invalid_proof
                .verify(None,
                    &PhantomData,
                    &language_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::GroupInstantiation(group::Error::InvalidGroupElement)),
                    "proof with an invalid statement_mask value should generate an invalid parameter error when checking the element is not in the group"
            );
        }

        if let Some(invalid_witness_space_value) = invalid_witness_space_value {
            let mut invalid_proof = valid_proof.clone();
            invalid_proof.responses = [invalid_witness_space_value; REPETITIONS];

            assert!(matches!(
            invalid_proof
                .verify(None,
                    &PhantomData,
                    &language_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::GroupInstantiation(group::Error::InvalidGroupElement)),
                    "proof with an invalid response value should generate an invalid parameter error when checking the element is not in the group"
            );
        }
    }

    #[allow(dead_code)]
    pub(crate) fn proof_over_invalid_public_parameters_fails_verification<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        prover_language_public_parameters: Lang::PublicParameters,
        verifier_language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let (proof, statements) = generate_valid_proof::<REPETITIONS, Lang>(
            &prover_language_public_parameters,
            witnesses.clone(),
        );

        assert!(
            matches!(
                proof
                    .verify(
                        None,
                        &PhantomData,
                        &verifier_language_public_parameters,
                        statements,
                    )
                    .err()
                    .unwrap(),
                Error::ProofVerification
            ),
            "proof over wrong public parameters shouldn't verify"
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::marker::PhantomData;

    use criterion::Criterion;
    use rand_core::OsRng;

    use super::*;
    use crate::proofs::schnorr::{language::tests::generate_witnesses, Proof};

    pub(crate) fn benchmark<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: Lang::PublicParameters,
        extra_description: Option<String>,
        c: &mut Criterion,
    ) {
        let mut g = c.benchmark_group(format!(
            "{:?} {:?} with {:?} repetitions",
            Lang::NAME,
            extra_description.unwrap_or("".to_string()),
            REPETITIONS
        ));

        g.sample_size(10);

        for batch_size in [1, 10, 100, 1000] {
            let witnesses =
                generate_witnesses::<REPETITIONS, Lang>(&language_public_parameters, batch_size);

            let statements: proofs::Result<Vec<Lang::StatementSpaceGroupElement>> = witnesses
                .iter()
                .map(|witness| Lang::group_homomorphism(witness, &language_public_parameters))
                .collect();
            let statements = statements.unwrap();

            g.bench_function(format!(".value() over {batch_size} statements"), |bench| {
                bench.iter(|| statements.iter().map(|x| x.value()).collect::<Vec<_>>())
            });

            let statements_values: Vec<_> = statements.iter().map(|x| x.value()).collect();

            g.bench_function(
                format!("schnorr::Proof::setup_transcript() over {batch_size} statements"),
                |bench| {
                    bench.iter(|| {
                        Proof::<REPETITIONS, Lang, PhantomData<()>>::setup_transcript(
                            &PhantomData,
                            &language_public_parameters,
                            statements_values.clone(),
                            // just a stub value as the value doesn't affect the benchmarking of
                            // this function
                            &[*statements_values.first().unwrap(); REPETITIONS],
                        )
                    })
                },
            );

            g.bench_function(
                format!("schnorr::Proof::prove_inner() over {batch_size} statements"),
                |bench| {
                    bench.iter(|| {
                        Proof::<REPETITIONS, Lang, PhantomData<()>>::prove_with_statements(
                            0,
                            &PhantomData,
                            &language_public_parameters,
                            witnesses.clone(),
                            statements.clone(),
                            &mut OsRng,
                        )
                        .unwrap()
                    });
                },
            );

            let proof = Proof::<REPETITIONS, Lang, PhantomData<()>>::prove_with_statements(
                0,
                &PhantomData,
                &language_public_parameters,
                witnesses.clone(),
                statements.clone(),
                &mut OsRng,
            )
            .unwrap();

            g.bench_function(
                format!("schnorr::Proof::verify() over {batch_size} statements"),
                |bench| {
                    bench.iter(|| {
                        proof.verify(
                            None,
                            &std::marker::PhantomData,
                            &language_public_parameters,
                            statements.clone(),
                        )
                    });
                },
            );
        }

        g.finish();
    }
}
