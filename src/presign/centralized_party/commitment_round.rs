// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::iter;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    group,
    group::{GroupElement as _, GroupElement, PrimeGroupElement, Samplable},
    presign::centralized_party::proof_verification_round,
    proofs,
    proofs::{
        range,
        schnorr::{
            knowledge_of_decommitment, knowledge_of_decommitment::LanguageCommitmentScheme,
            language::enhanced,
        },
    },
    AdditivelyHomomorphicEncryptionKey,
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
    // TODO: should we get this like that? is it the same for both the centralized & decentralized
    // party (and all their parties?)
    pub protocol_context: ProtocolContext,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    pub first_range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub second_range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIM_LIMBS,
        >,
        CommitmentScheme: LanguageCommitmentScheme<SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        CommitmentScheme,
        ProtocolContext,
    >
where
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
    pub fn sample_commit_and_prove_secret_key_share(
        self,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        Vec<CommitmentScheme::CommitmentSpaceGroupElement>,
        proof_verification_round::Party<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            CommitmentScheme,
            ProtocolContext,
        >,
    )> {
        // TODO: is nonce the right name?
        // TODO: batch
        let signature_nonce_shares: group::Result<Vec<_>> = iter::repeat_with(|| {
            GroupElement::Scalar::sample(rng, &self.scalar_group_public_parameters)
        })
        .take(batch_size)
        .collect();

        let commitment_randomnesses: group::Result<Vec<_>> = iter::repeat_with(|| {
            GroupElement::Scalar::sample(rng, &self.scalar_group_public_parameters)
        })
        .take(batch_size)
        .collect();

        let signature_nonce_shares_and_commitment_randomnesses: Vec<_> = signature_nonce_shares?
            .into_iter()
            .zip(commitment_randomnesses?.into_iter())
            .map(|(nonce_share, commitment_randmoness)| [nonce_share, commitment_randmoness].into())
            .collect();

        let language_public_parameters = knowledge_of_decommitment::PublicParameters::new::<
            { knowledge_of_decommitment::ZERO_KNOWLEDGE_REPITITIONS },
            SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            CommitmentScheme,
        >(
            self.scalar_group_public_parameters.clone(),
            self.group_public_parameters.clone(),
            self.commitment_scheme_public_parameters.clone(),
        );

        let (knowledge_of_decommitment_proof, commitments) = knowledge_of_decommitment::Proof::<
            { knowledge_of_decommitment::ZERO_KNOWLEDGE_REPITITIONS },
            SCALAR_LIMBS,
            GroupElement::Scalar,
            GroupElement,
            CommitmentScheme,
            ProtocolContext,
        >::prove(
            None,
            &self.protocol_context,
            &language_public_parameters,
            signature_nonce_shares_and_commitment_randomnesses.clone(),
            rng,
        )?;

        let signature_nonce_shares_and_commitment_randomnesses =
            signature_nonce_shares_and_commitment_randomnesses
                .into_iter()
                .map(|witness| {
                    let [nonce_share, commitment_randomness] = witness.into();

                    (nonce_share, commitment_randomness)
                })
                .collect();

        let party = proof_verification_round::Party {
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            commitment_scheme_public_parameters: self.commitment_scheme_public_parameters,
            first_range_proof_public_parameters: self.first_range_proof_public_parameters,
            second_range_proof_public_parameters: self.second_range_proof_public_parameters,
            protocol_context: self.protocol_context,
            signature_nonce_shares_and_commitment_randomnesses,
        };

        Ok((commitments, party))
    }
}
