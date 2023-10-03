// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::{
    proofs::{
        schnorr,
        schnorr::{
            language,
            language::{StatementSpaceGroupElement, WitnessSpaceGroupElement},
        },
    },
    ComputationalSecuritySizedNumber,
};

pub struct Party<Language: schnorr::Language, ProtocolContext: Clone + Serialize> {
    pub(super) language_public_parameters: language::PublicParameters<Language>,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<WitnessSpaceGroupElement<Language>>,
    pub(super) statements: Vec<StatementSpaceGroupElement<Language>>,
    pub(super) randomizer: WitnessSpaceGroupElement<Language>,
    pub(super) statement_mask: StatementSpaceGroupElement<Language>,
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}
