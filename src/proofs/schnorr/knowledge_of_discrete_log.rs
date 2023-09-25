// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Mul;

use serde::Serialize;

use crate::{
    group, proofs,
    proofs::{schnorr, schnorr::Samplable},
};

type WitnessGroupElement<Scalar> = Scalar;
type PublicValueGroupElement<GroupElement> = GroupElement;

impl<Scalar, GroupElement>
    schnorr::Language<WitnessGroupElement<Scalar>, PublicValueGroupElement<GroupElement>>
    for Language
where
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: group::GroupElement,
{
    type PublicParameters = PublicParameters<GroupElement::Value>;
    const NAME: &'static str = "Knowledge of the Discrete Log";

    fn group_homomorphism(
        witness: &WitnessGroupElement<Scalar>,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &group::PublicParameters<WitnessGroupElement<Scalar>>,
        public_value_space_public_parameters: &group::PublicParameters<
            PublicValueGroupElement<GroupElement>,
        >,
    ) -> proofs::Result<PublicValueGroupElement<GroupElement>> {
        let generator = GroupElement::new(
            language_public_parameters.generator.clone(),
            public_value_space_public_parameters,
        )?;

        Ok(*witness * generator)
    }
}

/// Knowledge of Discrete Log Schnorr Language.
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
#[derive(Clone)]
pub struct Language {}

/// The Public Parameters of the Knowledge of Discrete Log Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<GroupElementValue> {
    pub generator: GroupElementValue,
}

/// A Knowledge of Discrete Log Schnorr Proof.
#[allow(dead_code)]
pub type Proof<Scalar, GroupElement, ProtocolContext> = schnorr::Proof<
    WitnessGroupElement<Scalar>,
    PublicValueGroupElement<GroupElement>,
    Language,
    ProtocolContext,
>;
