// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use std::marker::PhantomData;

use commitment::Commitment;
use enhanced_maurer::{encryption_of_discrete_log, EnhanceableLanguage};
use group::{PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use maurer::knowledge_of_discrete_log;
use proof::{range, AggregatableRangeProof};
use serde::{Deserialize, Serialize};

use crate::{
    dkg::{
        centralized_party, centralized_party::commitment_round::commit_public_key_share,
        decentralized_party,
    },
    ProtocolPublicParameters, CENTRALIZED_PARTY_ID,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Output<GroupElementValue, CiphertextSpaceValue> {
    pub public_key_share: GroupElementValue,
    pub public_key: GroupElementValue,
    pub encrypted_secret_key_share: CiphertextSpaceValue,
    pub centralized_party_public_key_share: GroupElementValue,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
    pub protocol_context: ProtocolContext,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub commitment_to_centralized_party_secret_key_share: Commitment,

    pub _unbounded_witness_choice: PhantomData<UnboundedEncDLWitness>,
    pub _range_proof_choice: PhantomData<RangeProof>,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        UnboundedEncDLWitness,
        ProtocolContext,
    >
where
    encryption_of_discrete_log::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: maurer::Language<
            { maurer::SOUND_PROOFS_REPETITIONS },
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
            { maurer::SOUND_PROOFS_REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDLWitness,
        >,
{
    /// This function implements Protocol 4, steps 4 and 5 of the
    /// 2PC-MPC: Emulating Two Party ECDSA in Large-Scale MPC paper.
    /// src: https://eprint.iacr.org/2024/253
    pub fn verify_decommitment_and_proof_of_centralized_party_public_key_share(
        self,
        decommitment_and_proof: centralized_party::PublicKeyShareDecommitmentAndProof<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        >,
        secret_key_share_encryption_and_proof: decentralized_party::SecretKeyShareEncryptionAndProof<
            GroupElement::Value,
            range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RangeProof,
            >,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            encryption_of_discrete_log::Proof<
                RANGE_CLAIMS_PER_SCALAR,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
                RangeProof,
                UnboundedEncDLWitness,
                ProtocolContext,
            >,
        >,
    ) -> crate::Result<
        Output<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
    > {
        // = X_B
        let public_key_share = GroupElement::new(
            secret_key_share_encryption_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        // = X_A
        let centralized_party_public_key_share = GroupElement::new(
            decommitment_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        // === Check commitment X_A ===
        // Used in emulating idealized F^{L_DL}_{com-zk}
        // Protocol 4, step 4a
        let reconstructed_commitment = commit_public_key_share(
            CENTRALIZED_PARTY_ID,
            &centralized_party_public_key_share,
            &decommitment_and_proof.commitment_randomness,
        )?;
        if reconstructed_commitment != self.commitment_to_centralized_party_secret_key_share {
            return Err(crate::Error::WrongDecommitment);
        }

        // === Verify knowledge of x_A proof ===
        // Used in emulating idealized F^{L_DL}_{com-zk}
        // Protocol 4, step 4a
        let language_public_parameters =
        knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
            self.scalar_group_public_parameters.clone(),
            self.group_public_parameters.clone(),
            GroupElement::generator_value_from_public_parameters(&self.group_public_parameters),
        );        
        decommitment_and_proof.proof.verify(
            &self.protocol_context,
            &language_public_parameters,
            vec![centralized_party_public_key_share.clone()],
        )?;

        // === Compute X := X_A + X_B ===
        // Protocol 4, step 5b
        let public_key = centralized_party_public_key_share.clone() + &public_key_share;

        // === Output (and record) ===
        // Protocol 4, step 5b
        Ok(Output {
            public_key_share: secret_key_share_encryption_and_proof.public_key_share,
            public_key: public_key.value(),
            encrypted_secret_key_share: secret_key_share_encryption_and_proof
                .encrypted_secret_key_share,
            centralized_party_public_key_share: decommitment_and_proof.public_key_share,
        })
    }

    pub fn new<
        const NUM_RANGE_CLAIMS: usize,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
    >(
        protocol_public_parameters: ProtocolPublicParameters<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            UnboundedEncDHWitness,
            UnboundedDComEvalWitness,
        >,
        commitment_to_centralized_party_secret_key_share: Commitment,
        protocol_context: ProtocolContext,
    ) -> Self {
        Party {
            protocol_context,
            scalar_group_public_parameters: protocol_public_parameters
                .scalar_group_public_parameters,
            group_public_parameters: protocol_public_parameters.group_public_parameters,
            encryption_scheme_public_parameters: protocol_public_parameters
                .encryption_scheme_public_parameters,
            commitment_to_centralized_party_secret_key_share,
            _unbounded_witness_choice: PhantomData,
            _range_proof_choice: PhantomData,
        }
    }
}
