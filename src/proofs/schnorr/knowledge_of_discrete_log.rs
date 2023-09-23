// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{group, group::Samplable, proofs, proofs::schnorr};

/// Knowledge of Discrete Log Schnorr Language.
#[derive(Clone)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
}

/// The Public Parameters of the Knowledge of Discrete Log Schnorr Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<const SCALAR_LIMBS: usize, Scalar, GroupElement>
where
    Scalar: group::GroupElement<SCALAR_LIMBS> + Samplable<SCALAR_LIMBS>,
    GroupElement: group::GroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
{
    pub generator: GroupElement::Value,

    #[serde(skip_serializing)]
    _scalar_choice: PhantomData<Scalar>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement>
    PublicParameters<SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: group::GroupElement<SCALAR_LIMBS> + Samplable<SCALAR_LIMBS>,
    GroupElement: group::GroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
{
    pub fn new(generator: GroupElement::Value) -> Self {
        Self {
            generator,
            _scalar_choice: PhantomData,
        }
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
    ) -> proofs::Result<GroupElement> {
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

#[cfg(test)]
mod tests {
    use crypto_bigint::U256;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        group::{secp256k1, GroupElement},
        proofs::schnorr,
    };

    const SECP256K1_SCALAR_LIMBS: usize = U256::LIMBS;

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        schnorr::tests::valid_proof_verifies::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_SCALAR_LIMBS,
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Language<SECP256K1_SCALAR_LIMBS, secp256k1::Scalar, secp256k1::GroupElement>,
        >(
            PublicParameters::new(secp256k1_group_public_parameters.generator),
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            batch_size,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        schnorr::tests::invalid_proof_fails_verification::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_SCALAR_LIMBS,
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Language<SECP256K1_SCALAR_LIMBS, secp256k1::Scalar, secp256k1::GroupElement>,
        >(
            None,
            None,
            PublicParameters::new(secp256k1_group_public_parameters.generator),
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            batch_size,
        )
    }
}
