pub use decommitment_proof_verification_round::Output;
use serde::{Deserialize, Serialize};

use crate::{
    ahe, group,
    group::{GroupElement as _, PrimeGroupElement, Samplable},
    proofs,
    proofs::{
        range, schnorr,
        schnorr::{
            encryption_of_discrete_log, enhanced,
            enhanced::{EnhanceableLanguage, EnhancedLanguageStatementAccessors},
            language::encryption_of_discrete_log::StatementAccessors,
        },
    },
    AdditivelyHomomorphicEncryptionKey,
};

// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear
pub mod decommitment_proof_verification_round;
pub mod encryption_of_secret_key_share_round;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SecretKeyShareEncryptionAndProof<
    GroupElementValue,
    RangeProofCommitmentValue,
    CiphertextValue,
    EncDLProof,
> {
    pub(in crate::dkg) public_key_share: GroupElementValue,
    pub(in crate::dkg) encrypted_secret_key_share: CiphertextValue,
    pub(in crate::dkg) range_proof_commitment: RangeProofCommitmentValue,
    pub(in crate::dkg) encryption_of_secret_key_share_proof: EncDLProof,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >
    SecretKeyShareEncryptionAndProof<
        GroupElement::Value,
        range::CommitmentSchemeCommitmentSpaceValue<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RangeProof,
        >,
        ahe::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        encryption_of_discrete_log::EnhancedProof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            UnboundedEncDLWitness,
            RangeProof,
            ProtocolContext,
        >,
    >
where
    encryption_of_discrete_log::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: schnorr::Language<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
            WitnessSpaceGroupElement = encryption_of_discrete_log::WitnessSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            StatementSpaceGroupElement = encryption_of_discrete_log::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
            PublicParameters = encryption_of_discrete_log::PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        > + EnhanceableLanguage<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDLWitness,
        >,
{
    pub fn new(
        encryption_of_secret_share: enhanced::StatementSpaceGroupElement<
            { schnorr::proof::SOUND_PROOFS_REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedEncDLWitness,
            encryption_of_discrete_log::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >,
        encryption_of_secret_key_share_proof: encryption_of_discrete_log::EnhancedProof<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            UnboundedEncDLWitness,
            RangeProof,
            ProtocolContext,
        >,
    ) -> Self {
        let encrypted_secret_key_share = (&encryption_of_secret_share
            .language_statement()
            .encrypted_discrete_log())
            .value();

        let public_key_share = (&encryption_of_secret_share
            .language_statement()
            .base_by_discrete_log())
            .value();

        let range_proof_commitment = (encryption_of_secret_share.range_proof_commitment()).value();

        Self {
            public_key_share,
            encrypted_secret_key_share,
            range_proof_commitment,
            encryption_of_secret_key_share_proof,
        }
    }
}
