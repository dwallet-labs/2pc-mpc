// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::marker::PhantomData;
use commitment::Commitment;

use enhanced_maurer::{encryption_of_discrete_log, EnhanceableLanguage};
use group::{GroupElement as _, PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use maurer::knowledge_of_discrete_log;
use proof::{AggregatableRangeProof, range};
use serde::Serialize;
use homomorphic_encryption::GroupsPublicParametersAccessors;
use crate::{CENTRALIZED_PARTY_ID, dkg::centralized_party};
use crate::dkg::centralized_party::commitment_round::commit_public_key_share;
use crate::dkg::decentralized_party;

#[derive(Clone)]
pub struct Output<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> {
    pub public_key_share: GroupElement,
    pub public_key: GroupElement,
    pub encrypted_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub centralized_party_public_key_share: GroupElement,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
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
        UnboundedEncDLWitness,
        RangeProof,
        ProtocolContext,
    > where
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
                UnboundedEncDLWitness,
                RangeProof,
                ProtocolContext,
            >,
        >,
    ) -> crate::Result<
        Output<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>,
    > {
        let public_key_share = GroupElement::new(secret_key_share_encryption_and_proof.public_key_share, &self.group_public_parameters)?;
        let encrypted_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(secret_key_share_encryption_and_proof.encrypted_secret_key_share, self.encryption_scheme_public_parameters.ciphertext_space_public_parameters())?;

        let centralized_party_public_key_share = GroupElement::new(
            decommitment_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        let reconstructed_commitment = commit_public_key_share(
            CENTRALIZED_PARTY_ID,
            &centralized_party_public_key_share,
            &decommitment_and_proof.commitment_randomness,
        )?;

        if reconstructed_commitment != self.commitment_to_centralized_party_secret_key_share {
            return Err(crate::Error::WrongDecommitment);
        }

        let language_public_parameters =
            knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                GroupElement::generator_value_from_public_parameters(&self.group_public_parameters)
            );

        decommitment_and_proof.proof.verify(
            &self.protocol_context,
            &language_public_parameters,
            vec![centralized_party_public_key_share.clone()],
        )?;

        let public_key = centralized_party_public_key_share.clone() + &public_key_share;

        Ok(Output {
            public_key_share,
            public_key,
            encrypted_secret_key_share,
            centralized_party_public_key_share,
        })
    }
}
