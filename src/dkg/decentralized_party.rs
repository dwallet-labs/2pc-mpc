use crate::{
    ahe::paillier,
    group::{ristretto, secp256k1},
    proofs::{range, schnorr::encryption_of_discrete_log},
    ComputationalSecuritySizedNumber, StatisticalSecuritySizedNumber,
};

// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod commitment_round;
pub mod decommitment_round;

const RANGE_CLAIMS_PER_SCALAR: usize = 8;

// TODO: challenge instead of computational?
const WITNESS_MASK_LIMBS: usize = range::bulletproofs::RANGE_CLAIM_LIMBS
    + ComputationalSecuritySizedNumber::LIMBS
    + StatisticalSecuritySizedNumber::LIMBS;

type EncryptionOfSecretKeyShareLanguage = encryption_of_discrete_log::Language<
    { secp256k1::SCALAR_LIMBS },
    { ristretto::SCALAR_LIMBS },
    RANGE_CLAIMS_PER_SCALAR,
    { range::bulletproofs::RANGE_CLAIM_LIMBS },
    { WITNESS_MASK_LIMBS },
    { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
    secp256k1::Scalar,
    secp256k1::GroupElement,
    paillier::EncryptionKey,
    bulletproofs::RangeProof,
>;
