// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use commitment::GroupsPublicParametersAccessors as _;
use crypto_bigint::rand_core::CryptoRngCore;
use enhanced_maurer::{encryption_of_discrete_log, EnhanceableLanguage};
use group::{ComputationalSecuritySizedNumber, GroupElement, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{knowledge_of_discrete_log, SOUND_PROOFS_REPETITIONS};
use proof::{AggregatableRangeProof, range, range::PublicParametersAccessors};
use serde::{Deserialize, Serialize};

use crate::{dkg::decentralized_party, ProtocolPublicParameters};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Output<GroupElementValue, ScalarValue, CiphertextSpaceValue> {
    pub(crate) secret_key_share: ScalarValue,
    pub(crate) public_key_share: GroupElementValue,
    pub public_key: GroupElementValue,
    pub encrypted_decentralized_party_secret_key_share: CiphertextSpaceValue,
    pub(in crate::dkg) decentralized_party_public_key_share: GroupElementValue,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyShareDecommitmentAndProof<GroupElementValue, DLProof> {
    pub(in crate::dkg) proof: DLProof,
    pub(in crate::dkg) public_key_share: GroupElementValue,
    pub(in crate::dkg) commitment_randomness: ComputationalSecuritySizedNumber,
}

/// `State` is a serializable state to use in case the `Party` struct cannot be saved in
/// memory.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct State<GroupElementValue, ScalarValue, DLProof> {
    proof: DLProof,
    secret_key_share: ScalarValue,
    public_key_share: GroupElementValue,
    commitment_randomness: ComputationalSecuritySizedNumber,
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
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(super) unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub(super) protocol_context: ProtocolContext,
    pub(super) secret_key_share: GroupElement::Scalar,
    pub(super) public_key_share: GroupElement,
    pub(super) knowledge_of_discrete_log_proof:
        knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
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
            SOUND_PROOFS_REPETITIONS,
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
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDLWitness,
        >,
{
    /// This function implements steps 3 and 5 of Protocol 4 (DKG):
    /// Verifies zk-proof for $X_B$ and computes $X := X_A + X_B$.
    /// [Source](https://eprint.iacr.org/archive/2024/253/20240217:153208)
    pub fn decommit_proof_public_key_share(
        self,
        decentralized_party_secret_key_share_encryption_and_proof: decentralized_party::SecretKeyShareEncryptionAndProof<
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
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        PublicKeyShareDecommitmentAndProof<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        >,
        Output<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    )> {
        // = enc(x_B).
        let encrypted_decentralized_party_secret_key_share =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                decentralized_party_secret_key_share_encryption_and_proof
                    .encrypted_secret_key_share,
                self.encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        // = X_B.
        let decentralized_party_public_key_share = GroupElement::new(
            decentralized_party_secret_key_share_encryption_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        let range_proof_commitment = range::CommitmentSchemeCommitmentSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RangeProof,
        >::new(
            decentralized_party_secret_key_share_encryption_and_proof.range_proof_commitment,
            self.range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .commitment_space_public_parameters(),
        )?;

        let statement = (
            range_proof_commitment,
            (
                encrypted_decentralized_party_secret_key_share.clone(),
                decentralized_party_public_key_share.clone(),
            )
                .into(),
        )
            .into();

        // Construct L_EncDL parameters
        // Used in emulating the idealized $F^{L_EncDL}_{agg-zk}$ component
        // Protocol 4, step 3a.
        let encryption_of_discrete_log_language_public_parameters =
            encryption_of_discrete_log::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                self.encryption_scheme_public_parameters,
                GroupElement::generator_value_from_public_parameters(&self.group_public_parameters), /* = G (Protocol 4, step 2b) */
            );
        let encryption_of_discrete_log_enhanced_language_public_parameters =
            enhanced_maurer::PublicParameters::new::<
                RangeProof,
                UnboundedEncDLWitness,
                encryption_of_discrete_log::Language<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
            >(
                self.unbounded_encdl_witness_public_parameters,
                self.range_proof_public_parameters.clone(),
                encryption_of_discrete_log_language_public_parameters,
            )?;

        // === Verify X_B proof ===
        // Protocol 4, step 3a.
        // TODO: also we need to verify that the public key was DKG'ed right - Protocol 4, step 3b.
        decentralized_party_secret_key_share_encryption_and_proof
            .encryption_of_secret_key_share_proof
            .verify(
                &self.protocol_context,
                &encryption_of_discrete_log_enhanced_language_public_parameters,
                vec![statement],
                rng,
            )?;

        // === Construct X_A proof object ===
        // Used to emulate idealized $F^{L_DL}_{com-zk}$
        // Protocol 4, step 3c
        let public_key_share = self.public_key_share.value();
        let public_key_share_decommitment_proof = PublicKeyShareDecommitmentAndProof::<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        > {
            proof: self.knowledge_of_discrete_log_proof,
            public_key_share,
            commitment_randomness: self.commitment_randomness,
        };

        // === Compute X := X_A + X_B ===
        // Protocol 4, step 5a
        let public_key = self.public_key_share.clone() + &decentralized_party_public_key_share;

        // === Output (and record) ===
        // Protocol 4, step 5a
        let output = Output {
            secret_key_share: self.secret_key_share.value(),
            public_key_share,
            public_key: public_key.value(),
            encrypted_decentralized_party_secret_key_share:
                decentralized_party_secret_key_share_encryption_and_proof.encrypted_secret_key_share,
            decentralized_party_public_key_share:
                decentralized_party_secret_key_share_encryption_and_proof.public_key_share,
        };
        Ok((public_key_share_decommitment_proof, output))
    }

    pub fn to_state(
        self,
    ) -> State<
        GroupElement::Value,
        group::Value<GroupElement::Scalar>,
        knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
    > {
        State {
            secret_key_share: self.secret_key_share.value(),
            public_key_share: self.public_key_share.value(),
            proof: self.knowledge_of_discrete_log_proof,
            commitment_randomness: self.commitment_randomness,
        }
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
        state: State<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        >,
        protocol_context: ProtocolContext,
    ) -> crate::Result<Self> {
        let scalar_group_public_parameters =
            protocol_public_parameters.scalar_group_public_parameters;

        let group_public_parameters = protocol_public_parameters.group_public_parameters;

        let secret_key_share =
            GroupElement::Scalar::new(state.secret_key_share, &scalar_group_public_parameters)?;
        let public_key_share = GroupElement::new(state.public_key_share, &group_public_parameters)?;

        Ok(Party {
            protocol_context,
            scalar_group_public_parameters,
            group_public_parameters,
            encryption_scheme_public_parameters: protocol_public_parameters
                .encryption_scheme_public_parameters,
            unbounded_encdl_witness_public_parameters: protocol_public_parameters
                .unbounded_encdl_witness_public_parameters,
            range_proof_public_parameters: protocol_public_parameters
                .range_proof_enc_dl_public_parameters,
            secret_key_share,
            public_key_share,
            knowledge_of_discrete_log_proof: state.proof,
            commitment_randomness: state.commitment_randomness,
        })
    }
}
