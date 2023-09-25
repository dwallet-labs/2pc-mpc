// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group,
    group::self_product,
    proofs,
    proofs::{schnorr, schnorr::Samplable},
};

type WitnessGroupElement<Scalar> = self_product::GroupElement<2, Scalar>;
type PublicValueGroupElement<GroupElement> = GroupElement;

impl<Scalar, GroupElement, CommitmentScheme>
    schnorr::Language<WitnessGroupElement<Scalar>, PublicValueGroupElement<GroupElement>>
    for Language<CommitmentScheme>
where
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: group::GroupElement,
    CommitmentScheme: HomomorphicCommitmentScheme<
        MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
        RandomnessSpaceGroupElement = Scalar,
        CommitmentSpaceGroupElement = GroupElement,
    >,
{
    type PublicParameters = PublicParameters<CommitmentScheme::PublicParameters>;
    const NAME: &'static str = "Knowledge of Decommitment";

    fn group_homomorphism(
        witness: &WitnessGroupElement<Scalar>,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &group::PublicParameters<WitnessGroupElement<Scalar>>,
        public_value_space_public_parameters: &group::PublicParameters<
            PublicValueGroupElement<GroupElement>,
        >,
    ) -> proofs::Result<PublicValueGroupElement<GroupElement>> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            public_value_space_public_parameters,
        )?;

        Ok(commitment_scheme.commit(&[*value].into(), randomness))
    }
}

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
#[derive(Clone)]
pub struct Language<CommitmentScheme> {
    _commitment_choice: PhantomData<CommitmentScheme>,
}

/// The Public Parameters of the Knowledge of Decommitment Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<CommitmentSchemePublicParameters> {
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
}

/// A Knowledge of Decommitment Schnorr Proof.
#[allow(dead_code)]
pub type Proof<Scalar, GroupElement, CommitmentScheme, ProtocolContext> = schnorr::Proof<
    WitnessGroupElement<Scalar>,
    PublicValueGroupElement<GroupElement>,
    Language<CommitmentScheme>,
    ProtocolContext,
>;
