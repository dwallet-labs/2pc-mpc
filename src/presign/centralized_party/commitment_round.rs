// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use commitment::{pedersen, Pedersen};
use crypto_bigint::rand_core::CryptoRngCore;
use group::{PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use maurer::{knowledge_of_decommitment, SOUND_PROOFS_REPETITIONS};
use proof::AggregatableRangeProof;
use serde::{Deserialize, Serialize};

use crate::presign::centralized_party::proof_verification_round;

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
    pub protocol_context: ProtocolContext,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    pub unbounded_encdh_witness_public_parameters: UnboundedEncDHWitness::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub encrypted_decentralized_party_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
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
        let signature_nonce_shares = GroupElement::Scalar::sample_batch(
            &self.scalar_group_public_parameters,
            batch_size,
            rng,
        )?;

        let commitment_randomnesses = GroupElement::Scalar::sample_batch(
            &self.scalar_group_public_parameters,
            batch_size,
            rng,
        )?;

        let signature_nonce_shares_and_commitment_randomnesses: Vec<_> = signature_nonce_shares
            .into_iter()
            .zip(commitment_randomnesses.into_iter())
            .map(|(nonce_share, commitment_randomness)| [nonce_share, commitment_randomness].into())
            .collect();

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

        // TODO: batch normalize
        let commitments = commitments
            .into_iter()
            .map(|element| element.value())
            .collect();

        let signature_nonce_shares_commitments_and_batched_proof =
            SignatureNonceSharesCommitmentsAndBatchedProof { commitments, proof };

        Ok((signature_nonce_shares_commitments_and_batched_proof, party))
    }
}
