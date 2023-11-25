// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::{array, iter};

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
    presign::{
        centralized_party::commitment_round::SignatureNonceSharesCommitmentsAndBatchedProof,
        decentralized_party::first_decommitment_round,
    },
    proofs,
    proofs::{
        range,
        range::CommitmentPublicParametersAccessor as _,
        schnorr::{
            encryption_of_discrete_log, knowledge_of_decommitment,
            knowledge_of_decommitment::LanguageCommitmentScheme, language::enhanced,
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
    pub range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
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
    // TODO name
    pub fn sample_and_commit_share_of_decentralize_party_secret_key_share(
        self,
        centralized_party_nonce_shares_commitments_and_batched_proof: SignatureNonceSharesCommitmentsAndBatchedProof<
            SCALAR_LIMBS,
            GroupElement,
            CommitmentScheme,
            ProtocolContext,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        Commitment,
        first_decommitment_round::Party<
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
        let batch_size = centralized_party_nonce_shares_commitments_and_batched_proof
            .commitments
            .len();

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

        centralized_party_nonce_shares_commitments_and_batched_proof
            .proof
            .verify(
                None,
                &self.protocol_context,
                &language_public_parameters,
                centralized_party_nonce_shares_commitments_and_batched_proof.commitments,
            )?;

        let shares_of_decentralized_party_signature_nonce_shares: group::Result<Vec<_>> =
            iter::repeat_with(|| {
                GroupElement::Scalar::sample(rng, &self.scalar_group_public_parameters)
            })
            .take(batch_size)
            .collect();

        let shares_of_decentralized_party_signature_nonce_shares_witnesses: Vec<
            _
        > = shares_of_decentralized_party_signature_nonce_shares?
            .clone()
            .into_iter()
            .map(|share_of_decentralized_party_signature_nonce_share| {
                let share_of_decentralized_party_signature_nonce_share: Uint<SCALAR_LIMBS> =
                    share_of_decentralized_party_signature_nonce_share.into();

                let share_of_decentralized_party_signature_nonce_share_in_range_claim_base: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR] =
                    array::from_fn(|i| {
                        Uint::<WITNESS_MASK_LIMBS>::from(
                            &((share_of_decentralized_party_signature_nonce_share >> (i * RangeProof::RANGE_CLAIM_BITS))
                                & ((Uint::<SCALAR_LIMBS>::ONE << RangeProof::RANGE_CLAIM_BITS)
                                .wrapping_sub(&Uint::<SCALAR_LIMBS>::ONE))),
                        )
                            .into()
                    });

                share_of_decentralized_party_signature_nonce_share_in_range_claim_base.into()
            })
            .collect();

        let encryption_of_share_of_decentralized_party_signature_nonce_shares_randomness: group::Result<Vec<_>> =
            iter::repeat_with(||
                EncryptionKey::RandomnessSpaceGroupElement::sample(
                    rng,
                    &self
                        .encryption_scheme_public_parameters
                        .as_ref()
                        .randomness_space_public_parameters,
                )
            )
                .take(batch_size)
                .collect();

        let encryption_of_decentralized_party_signature_nonce_shares_commitment_randomness: group::Result<Vec<_>> =
            iter::repeat_with(||
                commitments::RandomnessSpaceGroupElement::<
                    RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RangeProof::CommitmentScheme<RANGE_CLAIMS_PER_SCALAR>,
                >::sample(
                    rng,
                    &self
                        .range_proof_public_parameters
                        .commitment_public_parameters()
                        .randomness_space_public_parameters(),
                )
            )
                .take(batch_size)
                .collect();

        let witnesses: Vec<_> = shares_of_decentralized_party_signature_nonce_shares_witnesses
            .into_iter()
            .zip(
                encryption_of_decentralized_party_signature_nonce_shares_commitment_randomness
                    ?
                    .into_iter()
                    .zip(encryption_of_share_of_decentralized_party_signature_nonce_shares_randomness?.into_iter()),
            )
            .map(|(nonce_share, (commitment_randomness, encryption_randomness))| (nonce_share, commitment_randomness, encryption_randomness).into())
            .collect();

        let encryption_of_discrete_log_language_public_parameters =
            encryption_of_discrete_log::LanguagePublicParameters::<
                SCALAR_LIMBS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
            >::new::<
                SCALAR_LIMBS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIM_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
            >(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                self.range_proof_public_parameters.clone(),
                self.encryption_scheme_public_parameters.clone(),
            );

        let encryption_of_signature_nonce_share_commitment_round_party =
            encryption_of_discrete_log::ProofAggregationCommitmentRoundParty::<
                SCALAR_LIMBS,
                RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIM_LIMBS,
                WITNESS_MASK_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement::Scalar,
                GroupElement,
                EncryptionKey,
                RangeProof,
                ProtocolContext,
            > {
                party_id: self.party_id,
                threshold: self.threshold,
                number_of_parties: self.number_of_parties,
                language_public_parameters: encryption_of_discrete_log_language_public_parameters,
                protocol_context: self.protocol_context.clone(),
                witnesses,
            };

        todo!();
    }
}
