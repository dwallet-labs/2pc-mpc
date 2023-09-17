// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{group, group::Samplable, proofs::schnorr};

/// Knowledge of Discrete Log Schnorr Language.
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement> {
    _scalar_choice: PhantomData<Scalar>,
    _point_choice: PhantomData<GroupElement>,
}

/// The Public Parameters of the Knowledge of Discrete Log Schnorr Language.
#[derive(Debug, PartialEq, Serialize)]
pub struct PublicParameters<const SCALAR_LIMBS: usize, Scalar, GroupElement>
where
    Scalar: group::GroupElement<SCALAR_LIMBS> + Samplable<SCALAR_LIMBS>,
    GroupElement: group::GroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
{
    generator: GroupElement::Value,

    #[serde(skip_serializing)]
    _scalar_choice: PhantomData<Scalar>,
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
impl<const SCALAR_LIMBS: usize, Scalar, GroupElement>
    schnorr::Language<SCALAR_LIMBS, SCALAR_LIMBS, Scalar, GroupElement>
    for Language<SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: group::GroupElement<SCALAR_LIMBS> + Samplable<SCALAR_LIMBS>,
    GroupElement: group::GroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
{
    type PublicParameters = PublicParameters<SCALAR_LIMBS, Scalar, GroupElement>;
    const NAME: &'static str = "Knowledge of the Discrete Log";

    fn group_homomorphism(
        witness: &Scalar,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &Scalar::PublicParameters,
        public_value_space_public_parameters: &GroupElement::PublicParameters,
    ) -> group::Result<GroupElement> {
        let generator = GroupElement::new(
            language_public_parameters.generator.clone(),
            public_value_space_public_parameters,
        )?;

        Ok(generator * witness)
    }
}

/// A Knowledge of Discrete Log Schnorr Proof.
#[allow(dead_code)]
pub type Proof<const SCALAR_LIMBS: usize, S, G, ProtocolContext> =
    schnorr::Proof<SCALAR_LIMBS, SCALAR_LIMBS, S, G, Language<SCALAR_LIMBS, S, G>, ProtocolContext>;
