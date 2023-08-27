// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::Result;
use crate::{group::GroupElement, marker::Marker};

use crate::{group};

/// A Schnorr Zero-Knowledge Proof Language
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof`
/// As defined in Appendix B. Schnorr Protocols in the paper
pub trait Language<
    // The upper bound for the scalar size of the witness group
    const WITNESS_SCALAR_LIMBS: usize,
    // The upper bound for the scalar size of the associated public-value space group
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    // An element of the witness space $(\HH, +)$
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    // An element in the associated public-value space $(\GG, \cdot)$
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
>
{
    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$
    ///
    /// Used for language-specific parameters (e.g., the public parameters of the commitment scheme
    /// used for proving knowledge of decommitment - the bases $g$, $h$ in the case of Pedersen).
    ///
    /// Group public parameters are encoded separately in
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `PublicValueSpaceGroupElement::PublicParameters`.
    type PublicParameters: Serialize + PartialEq;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// $\phi:\HH\to\GG$ a group homomorphism from $(\HH_\pp, +)$, the witness space, to $(\GG_\pp,
    /// \cdot)$, the statement space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement,
        _language_public_parameters: &Self::PublicParameters,
        _witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        _public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
    ) -> Result<PublicValueSpaceGroupElement, group::Error>;
}

/// An Enhanced Batched Schnorr Zero-Knowledge Proof
/// Implements Appendix B. Schnorr Protocols in the paper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
    L,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext,
> {
    statement_mask: PublicValueSpaceGroupElement::Value,
    response: WitnessSpaceGroupElement::Value,

    _language_choice: Marker<L>,
    _protocol_context_choice: Marker<ProtocolContext>,
}

impl<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        L: Language<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
        >,
        ProtocolContext: Serialize,
    >
    Proof<
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        WitnessSpaceGroupElement,
        PublicValueSpaceGroupElement,
        L,
        ProtocolContext,
    >
{
    #[allow(dead_code)]
    fn new(
        statement_mask: PublicValueSpaceGroupElement,
        response: WitnessSpaceGroupElement,
    ) -> Self {
        Self {
            statement_mask: statement_mask.value(),
            response: response.value(),
            _language_choice: Marker::<L>::new(),
            _protocol_context_choice: Marker::<ProtocolContext>::new(),
        }
    }

    /// Prove an enhanced batched Schnorr zero-knowledge claim
    /// Returns the zero-knowledge proof
    pub fn prove(
        _protocol_context: ProtocolContext,
        _language_public_parameters: &L::PublicParameters,
        _witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        _public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        _witnesses_and_statements: Vec<(WitnessSpaceGroupElement, PublicValueSpaceGroupElement)>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        todo!()
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof
    pub fn verify(
        &self,
        _protocol_context: ProtocolContext,
        _language_public_parameters: &L::PublicParameters,
        _witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        _public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        _statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<()> {
        todo!()
    }
}
