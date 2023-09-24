// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{self_product, CyclicGroupElement, Samplable},
    proofs,
    proofs::schnorr,
};

/// Commitment of Discrete Log Schnorr Language
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
pub struct Language<CommitmentScheme> {
    _commitment_choice: PhantomData<CommitmentScheme>,
}

/// The Public Parameters of the Commitment of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<GroupElementValue, CommitmentSchemePublicParameters> {
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub generator: GroupElementValue, // The base of discrete log
}

impl<Scalar, GroupElement, CommitmentScheme>
    schnorr::Language<
        self_product::GroupElement<2, Scalar>,
        self_product::GroupElement<2, GroupElement>,
    > for Language<CommitmentScheme>
where
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: CyclicGroupElement,
    CommitmentScheme: HomomorphicCommitmentScheme<
        MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
        RandomnessSpaceGroupElement = Scalar,
        CommitmentSpaceGroupElement = GroupElement,
    >,
{
    type PublicParameters =
        PublicParameters<GroupElement::Value, CommitmentScheme::PublicParameters>;
    const NAME: &'static str = "Commitment of Discrete Log";

    fn group_homomorphism(
        witness: &self_product::GroupElement<2, Scalar>,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &self_product::PublicParameters<
            2,
            Scalar::PublicParameters,
        >,
        public_value_space_public_parameters: &self_product::PublicParameters<
            2,
            GroupElement::PublicParameters,
        >,
    ) -> proofs::Result<self_product::GroupElement<2, GroupElement>> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let base = GroupElement::new(
            language_public_parameters.generator.clone(),
            &public_value_space_public_parameters.public_parameters,
        )?;

        let commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            &public_value_space_public_parameters.public_parameters,
        )?;

        Ok([
            commitment_scheme.commit(&[*value].into(), randomness),
            *value * base,
        ]
        .into())
    }
}

/// A Commitment of Discrete Log Schnorr Proof
#[allow(dead_code)]
pub type Proof<Scalar, GroupElement, CommitmentScheme, ProtocolContext> = schnorr::Proof<
    self_product::GroupElement<2, Scalar>,
    self_product::GroupElement<2, GroupElement>,
    Language<CommitmentScheme>,
    ProtocolContext,
>;
