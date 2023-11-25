// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::array;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe, commitments,
    commitments::GroupsPublicParametersAccessors as _,
    dkg::decentralized_party::decommitment_round,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, GroupElement as _,
        PrimeGroupElement, Samplable,
    },
    presign::decentralized_party::first_decommitment_round,
    proofs,
    proofs::{
        range,
        range::CommitmentPublicParametersAccessor as _,
        schnorr::{
            encryption_of_discrete_log, knowledge_of_decommitment::LanguageCommitmentScheme,
            language::enhanced,
        },
    },
    AdditivelyHomomorphicEncryptionKey, Commitment, PartyID,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: proofs::RangeProof<RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_LIMBS>,
    CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    ProtocolContext: Clone + Serialize,
> where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    group::ScalarValue<SCALAR_LIMBS, GroupElement>: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    pub party_id: PartyID,
    pub threshold: PartyID,
    pub number_of_parties: PartyID,
    // TODO: should we get this like that?
    pub protocol_context: ProtocolContext,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    pub first_range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub second_range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
}
