// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use serde::Serialize;

use crate::{
    commitments::HomomorphicEncryptionKey,
    group::{self_product_group, CyclicGroupElement, KnownOrderGroupElement},
    proofs::schnorr,
    traits::Samplable,
    AdditivelyHomomorphicEncryptionKey,
};

/// Encryption of Discrete Log Schnorr Language
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
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, EncryptionKey> {
    _scalar_choice: PhantomData<Scalar>,
    _point_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Public Parameters of the Commitment of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize)]
pub struct PublicParameters<const SCALAR_LIMBS: usize, Scalar, GroupElement, EncryptionKey>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<MASK_LIMBS, SCALAR_LIMBS>,
{
    commitment_scheme_public_parameters: EncryptionKey::PublicParameters,
    generator: GroupElement::Value, // The base of discrete log

    #[serde(skip_serializing)]
    _scalar_choice: PhantomData<Scalar>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement, EncryptionKey>
    schnorr::Language<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
        self_product_group::GroupElement<2, SCALAR_LIMBS, GroupElement>,
    > for Language<SCALAR_LIMBS, Scalar, GroupElement, EncryptionKey>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS, Scalar> + Samplable,
    GroupElement: CyclicGroupElement<SCALAR_LIMBS>
        + Mul<Scalar, Output = GroupElement>
        + for<'r> Mul<&'r Scalar, Output = GroupElement>,
    EncryptionKey: HomomorphicEncryptionKey<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        Scalar,
        Scalar,
        GroupElement,
    >,
{
    type PublicParameters = PublicParameters<SCALAR_LIMBS, Scalar, GroupElement, EncryptionKey>;
    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
        language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &self_product_group::PublicParameters<
            2,
            SCALAR_LIMBS,
            Scalar,
        >,
        public_value_space_public_parameters: &self_product_group::PublicParameters<
            2,
            SCALAR_LIMBS,
            GroupElement,
        >,
    ) -> crate::group::Result<self_product_group::GroupElement<2, SCALAR_LIMBS, GroupElement>> {
        let [value, randomness]: &[Scalar; 2] = witness.into();

        let base = GroupElement::new(
            language_public_parameters.generator.clone(),
            &public_value_space_public_parameters.public_parameters,
        )?;

        let commitment_scheme = EncryptionKey::new(
            &language_public_parameters.commitment_scheme_public_parameters,
            &public_value_space_public_parameters.public_parameters,
        )?;

        Ok([Encryption_scheme.commit(value, randomness), base * value].into())
    }
}

/// A Encryption of Discrete Log Schnorr Proof
#[allow(dead_code)]
pub type Proof<const SCALAR_LIMBS: usize, Scalar, GroupElement, EncryptionKey, ProtocolContext> =
    schnorr::Proof<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        self_product_group::GroupElement<2, SCALAR_LIMBS, Scalar>,
        self_product_group::GroupElement<2, SCALAR_LIMBS, GroupElement>,
        Language<SCALAR_LIMBS, Scalar, GroupElement, EncryptionKey>,
        ProtocolContext,
    >;
