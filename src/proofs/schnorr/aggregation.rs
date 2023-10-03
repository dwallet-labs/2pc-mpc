// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use serde::Serialize;

use crate::{
    proofs,
    proofs::{
        schnorr,
        schnorr::{language, language::StatementSpaceGroupElement},
    },
};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_round;

pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    _language_choice: PhantomData<Language>,
    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<Language: schnorr::Language, ProtocolContext: Clone + Serialize>
    Party<Language, ProtocolContext>
{
    pub fn new(
        witnesses: Vec<language::WitnessSpaceGroupElement<Language>>,
        language_public_parameters: language::PublicParameters<Language>,
        protocol_context: ProtocolContext,
    ) -> proofs::Result<commitment_round::Party<Language, ProtocolContext>> {
        let statements: proofs::Result<Vec<StatementSpaceGroupElement<Language>>> = witnesses
            .iter()
            .map(|witness| Language::group_homomorphism(witness, &language_public_parameters))
            .collect();
        let statements = statements?;

        Ok(commitment_round::Party {
            language_public_parameters,
            protocol_context,
            witnesses,
            statements,
        })
    }
}
