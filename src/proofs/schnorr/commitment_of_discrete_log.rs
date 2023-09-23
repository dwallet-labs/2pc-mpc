// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group::{self_product, CyclicGroupElement, KnownOrderGroupElement},
    proofs::{schnorr, schnorr::Samplable},
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
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

/// The Public Parameters of the Commitment of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize)]
pub struct PublicParameters<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable,
    GroupElement: CyclicGroupElement
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    CommitmentScheme: HomomorphicCommitmentScheme<Scalar, Scalar, GroupElement>,
{
    commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    generator: GroupElement::Value, // The base of discrete log

    #[serde(skip_serializing)]
    _scalar_choice: PhantomData<Scalar>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>
    schnorr::Language<
        self_product::GroupElement<2, Scalar>,
        self_product::GroupElement<2, GroupElement>,
    > for Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable,
    GroupElement: CyclicGroupElement
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    CommitmentScheme: HomomorphicCommitmentScheme<Scalar, Scalar, GroupElement>,
{
    type PublicParameters = PublicParameters<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>;
    const NAME: &'static str = "Commitment of Discrete Log";

    fn group_homomorphism(
        witness: &self_product::GroupElement<2, Scalar>,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &self_product::PublicParameters<2, Scalar>,
        public_value_space_public_parameters: &self_product::PublicParameters<2, GroupElement>,
    ) -> crate::group::Result<self_product::GroupElement<2, GroupElement>> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let base = GroupElement::new(
            language_public_parameters.generator.clone(),
            &public_value_space_public_parameters.public_parameters,
        )?;

        let commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            &public_value_space_public_parameters.public_parameters,
        )?;

        Ok([commitment_scheme.commit(value, randomness), base * value].into())
    }
}

/// A Commitment of Discrete Log Schnorr Proof
#[allow(dead_code)]
pub type Proof<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme, ProtocolContext> =
    schnorr::Proof<
        self_product::GroupElement<2, Scalar>,
        self_product::GroupElement<2, GroupElement>,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;
