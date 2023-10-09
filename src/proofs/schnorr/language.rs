// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
pub use enhanced::{
    committed_linear_evaluation, encryption_of_discrete_log, encryption_of_tuple, EnhancedLanguage,
};
use proofs::Result;
use serde::{Deserialize, Serialize};

use crate::{
    group,
    group::{GroupElement, Samplable},
    proofs,
};

pub mod commitment_of_discrete_log;
pub mod discrete_log_ratio_of_commited_values;
pub mod enhanced;
pub mod knowledge_of_decommitment;
pub mod knowledge_of_discrete_log;

/// A Schnorr Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof`.
/// As defined in Appendix B. Schnorr Protocols in the paper.
pub trait Language: Clone + Serialize {
    /// An element of the witness space $(\HH_\pp, +)$
    type WitnessSpaceGroupElement: GroupElement + Samplable;

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

    /// A group homomorphism $\phi:\HH\to\GG$  from $(\HH_\pp, +)$, the witness space,
    /// to $(\GG_\pp,\cdot)$, the statement space space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement<Self>,
        language_public_parameters: &PublicParameters<Self>,
    ) -> Result<StatementSpaceGroupElement<Self>>;
}

pub(in crate::proofs) type PublicParameters<L> = <L as Language>::PublicParameters;
pub(in crate::proofs) type WitnessSpaceGroupElement<L> = <L as Language>::WitnessSpaceGroupElement;
pub(in crate::proofs) type WitnessSpacePublicParameters<L> =
    group::PublicParameters<WitnessSpaceGroupElement<L>>;
pub(in crate::proofs) type WitnessSpaceValue<L> = group::Value<WitnessSpaceGroupElement<L>>;

pub(in crate::proofs) type StatementSpaceGroupElement<L> =
    <L as Language>::StatementSpaceGroupElement;
pub(in crate::proofs) type StatementSpacePublicParameters<L> =
    group::PublicParameters<StatementSpaceGroupElement<L>>;
pub(in crate::proofs) type StatementSpaceValue<L> = group::Value<StatementSpaceGroupElement<L>>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
    pub witness_space_public_parameters: WitnessSpacePublicParameters,
    pub statement_space_public_parameters: StatementSpacePublicParameters,
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

    pub(crate) fn generate_witnesses<Lang: Language>(
        language_public_parameters: &Lang::PublicParameters,
        batch_size: usize,
    ) -> Vec<WitnessSpaceGroupElement<Lang>> {
        iter::repeat_with(|| {
            WitnessSpaceGroupElement::<Lang>::sample(
                &mut OsRng,
                &language_public_parameters
                    .as_ref()
                    .witness_space_public_parameters,
            )
            .unwrap()
        })
        .take(batch_size)
        .collect()
    }

    pub(crate) fn generate_witnesses_for_aggregation<Lang: Language>(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) -> Vec<Vec<WitnessSpaceGroupElement<Lang>>> {
        iter::repeat_with(|| generate_witnesses::<Lang>(language_public_parameters, batch_size))
            .take(number_of_parties)
            .collect()
    }

    pub(crate) fn generate_witness<Lang: Language>(
        language_public_parameters: &Lang::PublicParameters,
    ) -> WitnessSpaceGroupElement<Lang> {
        let witnesses = generate_witnesses::<Lang>(language_public_parameters, 1);

        witnesses.first().unwrap().clone()
    }

    pub(crate) fn generate_valid_proof<Lang: Language>(
        language_public_parameters: &Lang::PublicParameters,
        witnesses: Vec<WitnessSpaceGroupElement<Lang>>,
    ) -> (
        Proof<Lang, PhantomData<()>>,
        Vec<StatementSpaceGroupElement<Lang>>,
    ) {
        Proof::prove(
            &PhantomData,
            language_public_parameters,
            witnesses,
            &mut OsRng,
        )
        .unwrap()
    }

    // TODO: why is this considered as dead code, if its being called from a test in other modules?

    #[allow(dead_code)]
    pub(crate) fn valid_proof_verifies<Lang: Language>(
        language_public_parameters: Lang::PublicParameters,
        batch_size: usize,
    ) {
        let witnesses = generate_witnesses::<Lang>(&language_public_parameters, batch_size);

        let (proof, statements) =
            generate_valid_proof::<Lang>(&language_public_parameters, witnesses.clone());

        assert!(
            proof
                .verify(&PhantomData, &language_public_parameters, statements)
                .is_ok(),
            "valid proofs should verify"
        );
    }

    #[allow(dead_code)]
    pub(crate) fn invalid_proof_fails_verification<Lang: Language>(
        invalid_witness_space_value: Option<WitnessSpaceValue<Lang>>,
        invalid_statement_space_value: Option<StatementSpaceValue<Lang>>,
        language_public_parameters: Lang::PublicParameters,
        batch_size: usize,
    ) {
        let witnesses = generate_witnesses::<Lang>(&language_public_parameters, batch_size);

        let (valid_proof, statements) =
            generate_valid_proof::<Lang>(&language_public_parameters, witnesses.clone());

        let wrong_witness = generate_witness::<Lang>(&language_public_parameters);

        let wrong_statement =
            Lang::group_homomorphism(&wrong_witness, &language_public_parameters).unwrap();

        assert!(
            matches!(
                valid_proof
                    .verify(
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
        invalid_proof.response = wrong_witness.value();

        assert!(
            matches!(
                invalid_proof
                    .verify(
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
        invalid_proof.statement_mask = wrong_statement.neutral().value();

        assert!(
            matches!(
                invalid_proof
                    .verify(
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
        invalid_proof.response = wrong_witness.neutral().value();

        assert!(
            matches!(
                invalid_proof
                    .verify(
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
            invalid_proof.statement_mask = invalid_statement_space_value;

            assert!(matches!(
            invalid_proof
                .verify(
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
            invalid_proof.response = invalid_witness_space_value;

            assert!(matches!(
            invalid_proof
                .verify(
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
    pub(crate) fn proof_over_invalid_public_parameters_fails_verification<Lang: Language>(
        prover_language_public_parameters: Lang::PublicParameters,
        verifier_language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<WitnessSpaceGroupElement<Lang>>,
    ) {
        let (proof, statements) =
            generate_valid_proof::<Lang>(&prover_language_public_parameters, witnesses.clone());

        assert!(
            matches!(
                proof
                    .verify(
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

    pub(crate) fn benchmark<Lang: Language>(
        language_public_parameters: Lang::PublicParameters,
        c: &mut Criterion,
    ) {
        let mut g = c.benchmark_group(Lang::NAME);

        g.sample_size(10);

        for batch_size in [1, 10, 100, 1000] {
            let witnesses = generate_witnesses::<Lang>(&language_public_parameters, batch_size);

            let statements: proofs::Result<Vec<StatementSpaceGroupElement<Lang>>> = witnesses
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
                        Proof::<Lang, PhantomData<()>>::setup_transcript(
                            &PhantomData,
                            &language_public_parameters,
                            statements_values.clone(),
                            statements_values.first().unwrap(),
                        )
                    })
                },
            );

            g.bench_function(
                format!("schnorr::Proof::prove_inner() over {batch_size} statements"),
                |bench| {
                    bench.iter(|| {
                        Proof::<Lang, PhantomData<()>>::prove_with_statements(
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

            let proof = Proof::<Lang, PhantomData<()>>::prove_with_statements(
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
