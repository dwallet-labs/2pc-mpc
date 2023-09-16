// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{
    commitments::HomomorphicCommitmentScheme,
    group::{self_product_group, CyclicGroupElement, KnownOrderGroupElement, Samplable},
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
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> {
    _scalar_choice: PhantomData<Scalar>,
    _point_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

/// The Public Parameters of the Knowledge of Decommitment Schnorr Language.
#[derive(Debug, PartialEq, Serialize)]
pub struct PublicParameters<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        Scalar,
        Scalar,
        GroupElement,
    >,
{
    commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,

    #[serde(skip_serializing)]
    _scalar_choice: PhantomData<Scalar>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>
    schnorr::Language<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
        GroupElement,
    > for Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable<SCALAR_LIMBS>,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    CommitmentScheme: HomomorphicCommitmentScheme<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        Scalar,
        Scalar,
        GroupElement,
    >,
{
    type PublicParameters = PublicParameters<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>;
    const NAME: &'static str = "Knowledge of Decommitment";

    fn group_homomorphism(
        witness: &self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &self_product_group::PublicParameters<
            2,
            SCALAR_LIMBS,
            Scalar,
        >,
        public_value_space_public_parameters: &GroupElement::PublicParameters,
    ) -> crate::group::Result<GroupElement> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            public_value_space_public_parameters,
        )?;

        Ok(commitment_scheme.commit(value, randomness))
    }
}

/// A Knowledge of Decommitment Schnorr Proof.
#[allow(dead_code)]
pub type Proof<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme, ProtocolContext> =
    schnorr::Proof<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
        GroupElement,
        Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>,
        ProtocolContext,
    >;
