// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use commitment::{pedersen, Pedersen};
use crypto_bigint::rand_core::CryptoRngCore;
use group::{GroupElement as _, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{knowledge_of_decommitment, SOUND_PROOFS_REPETITIONS};
use proof::AggregatableRangeProof;
use serde::{Deserialize, Serialize};

use crate::{dkg, presign::centralized_party::proof_verification_round, ProtocolPublicParameters};

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
    UnboundedEncDHWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
    pub(in crate::presign) protocol_context: ProtocolContext,
    pub(in crate::presign) scalar_group_public_parameters:
        group::PublicParameters<GroupElement::Scalar>,
    pub(in crate::presign) group_public_parameters: GroupElement::PublicParameters,
    pub(in crate::presign) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(in crate::presign) unbounded_encdl_witness_public_parameters:
        UnboundedEncDLWitness::PublicParameters,
    pub(in crate::presign) unbounded_encdh_witness_public_parameters:
        UnboundedEncDHWitness::PublicParameters,
    pub(in crate::presign) range_proof_public_parameters:
        RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub(in crate::presign) encrypted_decentralized_party_secret_key_share:
        EncryptionKey::CiphertextSpaceGroupElement,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureNonceSharesCommitmentsAndBatchedProof<
    const SCALAR_LIMBS: usize,
    GroupElementValue,
    DcomProof,
> {
    pub(in crate::presign) commitments: Vec<GroupElementValue>,
    pub(in crate::presign) proof: DcomProof,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
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
        UnboundedEncDHWitness,
        ProtocolContext,
    >
{
    /// This function implements step 1 of Protocol 5 (Presign)
    /// src: https://eprint.iacr.org/archive/2024/253/20240217:153208
    ///
    /// Note: this function operates on batches; the annotations are written as
    /// if the batch size equals 1.
    pub fn sample_commit_and_prove_signature_nonce_share(
        self,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        SignatureNonceSharesCommitmentsAndBatchedProof<
            SCALAR_LIMBS,
            GroupElement::Value,
            maurer::Proof<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_decommitment::Language<
                    SOUND_PROOFS_REPETITIONS,
                    SCALAR_LIMBS,
                    Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
                >,
                ProtocolContext,
            >,
        >,
        proof_verification_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            UnboundedEncDHWitness,
            ProtocolContext,
        >,
    )> {
        // === Sample k_A ===
        // Protocol 5, step 1a
        let signature_nonce_shares = GroupElement::Scalar::sample_batch(
            &self.scalar_group_public_parameters,
            batch_size,
            rng,
        )?;

        // === Sample ρ_1 ===
        // Protocol 5, step 1a
        let commitment_randomnesses = GroupElement::Scalar::sample_batch(
            &self.scalar_group_public_parameters,
            batch_size,
            rng,
        )?;

        // Create (k_A, ρ_1) tuple
        let signature_nonce_shares_and_commitment_randomnesses: Vec<_> = signature_nonce_shares
            .into_iter()
            .zip(commitment_randomnesses)
            .map(|(nonce_share, commitment_randomness)| [nonce_share, commitment_randomness].into())
            .collect();

        // Construct L_DCom parameters
        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
            )?;
        let language_public_parameters = knowledge_of_decommitment::PublicParameters::new::<
            SOUND_PROOFS_REPETITIONS,
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >(commitment_scheme_public_parameters.clone());

        // === Create proof and commitment to k_A ===
        // Protocol 5, steps 1b and 1a, respectively
        let (proof, commitments) = maurer::Proof::<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_decommitment::Language<
                SOUND_PROOFS_REPETITIONS,
                SCALAR_LIMBS,
                Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
            >,
            ProtocolContext,
        >::prove(
            &self.protocol_context,
            &language_public_parameters,
            signature_nonce_shares_and_commitment_randomnesses
                .clone()
                .into_iter()
                .map(|(nonce_share, commitment_randomness)| {
                    ([nonce_share].into(), commitment_randomness).into()
                })
                .collect(),
            rng,
        )?;

        let party = proof_verification_round::Party {
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            unbounded_encdl_witness_public_parameters: self
                .unbounded_encdl_witness_public_parameters,
            unbounded_encdh_witness_public_parameters: self
                .unbounded_encdh_witness_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            protocol_context: self.protocol_context,
            signature_nonce_shares_and_commitment_randomnesses,
            encrypted_decentralized_party_secret_key_share: self
                .encrypted_decentralized_party_secret_key_share,
        };

        let commitments = GroupElement::batch_normalize(commitments);

        let signature_nonce_shares_commitments_and_batched_proof =
            SignatureNonceSharesCommitmentsAndBatchedProof { commitments, proof };

        Ok((signature_nonce_shares_commitments_and_batched_proof, party))
    }

    pub fn new<
        const NUM_RANGE_CLAIMS: usize,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
    >(
        protocol_context: ProtocolContext,
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
        dkg_output: dkg::centralized_party::Output<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    ) -> crate::Result<Self> {
        let encryption_scheme_public_parameters =
            protocol_public_parameters.encryption_scheme_public_parameters;

        let encrypted_decentralized_party_secret_key_share =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                dkg_output.encrypted_decentralized_party_secret_key_share,
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
            )?;

        Ok(Self {
            protocol_context,
            scalar_group_public_parameters: protocol_public_parameters
                .scalar_group_public_parameters,
            group_public_parameters: protocol_public_parameters.group_public_parameters,
            encryption_scheme_public_parameters,
            unbounded_encdl_witness_public_parameters: protocol_public_parameters
                .unbounded_encdl_witness_public_parameters,
            unbounded_encdh_witness_public_parameters: protocol_public_parameters
                .unbounded_encdh_witness_public_parameters,
            range_proof_public_parameters: protocol_public_parameters
                .range_proof_enc_dl_public_parameters,
            encrypted_decentralized_party_secret_key_share,
        })
    }
}
