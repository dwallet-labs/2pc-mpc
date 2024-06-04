// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use std::collections::HashSet;

use commitment::{pedersen, Pedersen};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use enhanced_maurer::{
    encryption_of_discrete_log, encryption_of_tuple, language::composed_witness_upper_bound,
    EnhanceableLanguage, EnhancedLanguage, EnhancedPublicParameters,
};
use group::{GroupElement, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{knowledge_of_decommitment, SOUND_PROOFS_REPETITIONS};
use proof::AggregatableRangeProof;
use serde::Serialize;

use crate::{
    dkg,
    presign::{
        centralized_party::commitment_round::SignatureNonceSharesCommitmentsAndBatchedProof,
        decentralized_party::encrypted_masked_nonces_round,
    },
    Error, ProtocolPublicParameters,
};

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
    pub(in crate::presign) party_id: PartyID,
    pub(in crate::presign) threshold: PartyID,
    pub(in crate::presign) parties: HashSet<PartyID>,
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
    pub(in crate::presign) encrypted_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
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
    encryption_of_tuple::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: maurer::Language<
            SOUND_PROOFS_REPETITIONS,
            WitnessSpaceGroupElement = encryption_of_tuple::WitnessSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            StatementSpaceGroupElement = encryption_of_tuple::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                EncryptionKey,
            >,
            PublicParameters = encryption_of_tuple::PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        > + EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDHWitness,
        >,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
{
    /// This function implements Protocol 5, step 2a of the
    /// 2PC-MPC: Emulating Two Party ECDSA in Large-Scale MPC paper.
    /// src: https://eprint.iacr.org/2024/253
    ///
    /// Note: this function operates on batches; the annotations are written as
    /// if the batch size equals 1.
    pub fn sample_mask_and_nonce_shares_and_initialize_proof_aggregation(
        self,
        centralized_party_nonce_shares_commitments_and_batched_proof:
            SignatureNonceSharesCommitmentsAndBatchedProof<SCALAR_LIMBS, GroupElement::Value, maurer::Proof<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_decommitment::Language<
                SOUND_PROOFS_REPETITIONS,
                SCALAR_LIMBS,
                Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
            >,
            ProtocolContext,
        >,>,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        (
            enhanced_maurer::aggregation::commitment_round::Party<
                SOUND_PROOFS_REPETITIONS,
                RANGE_CLAIMS_PER_SCALAR,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedEncDHWitness,
                encryption_of_tuple::Language<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
                ProtocolContext,
            >,
            enhanced_maurer::aggregation::commitment_round::Party<
                SOUND_PROOFS_REPETITIONS,
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
                ProtocolContext,
            >,
        ),
        encrypted_masked_nonces_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDHWitness,
            ProtocolContext,
        >,
    )> {
        if self.parties.len() < self.threshold.into() {
            return Err(Error::ThresholdNotReached);
        }

        let batch_size = centralized_party_nonce_shares_commitments_and_batched_proof
            .commitments
            .len();

        // Construct L_DCOM language parameters
        // Used in emulating F^{L_DCOM}_zk
        // Protocol 5, step 2a (i)
        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
            )?;
        let l_dcom_public_parameters = knowledge_of_decommitment::PublicParameters::new::<
            SOUND_PROOFS_REPETITIONS,
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >(commitment_scheme_public_parameters.clone());

        // === Verify commitment to k_A ===
        // Protocol 5, step 2a (i)
        let centralized_party_nonce_shares_commitments =
            centralized_party_nonce_shares_commitments_and_batched_proof
                .commitments
                .into_iter()
                .map(|value| GroupElement::new(value, &self.group_public_parameters))
                .collect::<group::Result<Vec<_>>>()?;
        centralized_party_nonce_shares_commitments_and_batched_proof
            .proof
            .verify(
                &self.protocol_context,
                &l_dcom_public_parameters,
                centralized_party_nonce_shares_commitments.clone(),
            )?;

        // ==================================
        // Steps involving the EncDH language
        // ==================================

        // === Sample γ_i's ===
        // Protocol 5, 2a (iii)
        let masks_shares = GroupElement::Scalar::sample_batch(
            &self.scalar_group_public_parameters,
            batch_size,
            rng,
        )?;
        let mask_shares_witnesses = masks_shares
            .clone()
            .into_iter()
            .map(|share_of_decentralized_party_signature_nonce_share| {
                let share_of_decentralized_party_signature_nonce_share_value: Uint<SCALAR_LIMBS> =
                    share_of_decentralized_party_signature_nonce_share.into();

                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
                        &share_of_decentralized_party_signature_nonce_share_value,
                    )
                    .into(),
                    self.encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        // === Sample η^i_{mask_1}'s ===
        // Protocol 5, 2a (iii)
        let masks_encryption_randomness = EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
            self.encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            batch_size,
            rng,
        )?;

        // === Sample η^i_{mask_2}'s ===
        // Protocol 5, 2a (iii)
        let masked_key_share_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                self.encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                batch_size,
                rng,
            )?;

        // Construct L_EncDH public parameters
        // Used in emulating F^{L_EncDH}_{agg-zk}
        // Protocol 5, step 2a (iv)
        let encrypted_secret_key_share_upper_bound = composed_witness_upper_bound::<
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >()?;
        let enc_dh_public_parameters = encryption_of_tuple::PublicParameters::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >::new::<SCALAR_LIMBS, GroupElement, EncryptionKey>(
            self.scalar_group_public_parameters.clone(),
            self.encryption_scheme_public_parameters.clone(),

            // = ct_key = AHE.Enc(x_B) (see Protocol 4, step 2e/f)
            self.encrypted_secret_key_share.value(),
            encrypted_secret_key_share_upper_bound,
        );
        let enc_dh_public_parameters = EnhancedPublicParameters::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedEncDHWitness,
            encryption_of_tuple::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >::new::<
            RangeProof,
            UnboundedEncDHWitness,
            encryption_of_tuple::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >(
            self.unbounded_encdh_witness_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            enc_dh_public_parameters,
        )?;

        // Create (γ_i, η^i_{mask_1}, η^i_{mask_2}) tuples
        let witnesses = mask_shares_witnesses
            .clone()
            .into_iter()
            .zip(
                masks_encryption_randomness
                    .clone()
                    .into_iter()
                    .zip(masked_key_share_encryption_randomness),
            )
            .map(
                |(
                    mask_share,
                    (
                        mask_share_encryption_randomness,
                        masked_secret_key_share_encryption_randomness,
                    ),
                )| {
                    (
                        mask_share,
                        mask_share_encryption_randomness,
                        masked_secret_key_share_encryption_randomness,
                    )
                        .into()
                },
            )
            .collect();
        // TODO: use izip! instead:
        // https://stackoverflow.com/questions/29669287/how-can-i-zip-more-than-two-iterators

        // Map (γ_i, η^i_{mask_1}, η^i_{mask_2}) tuples to tuples of the form
        // - [commitment message]    cm_i = decomposed γ_i
        // - [commitment randomness] cr_i = fresh random sampled value
        // - [unbounded witness]     uw_i = (η^i_{mask_1}, η^i_{mask_2})
        let witnesses = EnhancedLanguage::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedEncDHWitness,
            encryption_of_tuple::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >::generate_witnesses(witnesses, &enc_dh_public_parameters, rng)?;

        // === Prepare ct^i_1, ct^i_2 computation ===
        // Protocol 5, step 2a (iii) A/B
        //
        // By calling `commit_statements_and_statement_mask` on this party,
        // ct^i_1 and ct^i_2 are created.
        //
        // sources:
        // --------
        // maurer::aggregation::commitment_round::commit_statements_and_statement_mask.
        // ct^i_1, ct^i_2 = enhanced_maurer::Language::homomorphose(witnesses, &enc_dl_public_parameters).
        let key_share_masking_commitment_round_party =
            enhanced_maurer::aggregation::commitment_round::Party::<
                SOUND_PROOFS_REPETITIONS,
                RANGE_CLAIMS_PER_SCALAR,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedEncDHWitness,
                encryption_of_tuple::Language<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    GroupElement,
                    EncryptionKey,
                >,
                ProtocolContext,
            >::new_session(
                self.party_id,
                self.parties.clone(),
                enc_dh_public_parameters,
                self.protocol_context.clone(),
                witnesses,
                rng,
            )?;

        // ==================================
        // Steps involving the EncDL language
        // ==================================

        // === Sample k_i ===
        // Protocol 5, step 2a (ii)
        let shares_of_signature_nonce_shares_witnesses = masks_shares
            .clone()
            .into_iter()
            .map(|share_of_signature_nonce_share| {
                let share_of_signature_nonce_share_value: Uint<SCALAR_LIMBS> =
                    share_of_signature_nonce_share.into();

                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
                        &share_of_signature_nonce_share_value,
                    )
                    .into(),
                    self.encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        // === Sample η^i_{mask_3}'s ===
        // Protocol 5, step 2a (ii)
        let shares_of_signature_nonce_shares_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                &self
                    .encryption_scheme_public_parameters
                    .as_ref()
                    .randomness_space_public_parameters,
                batch_size,
                rng,
            )?;

        // Construct L_EncDL public parameters
        // Used in emulating F^{L_EncDL}_{agg-zk}
        // Protocol 5, step 2a (v)
        let enc_dl_public_parameters =
            encryption_of_discrete_log::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                self.encryption_scheme_public_parameters.clone(),

                // = G (Protocol 5, step 2a (ii))
                GroupElement::generator_value_from_public_parameters(&self.group_public_parameters),
            );
        let enc_dl_public_parameters = EnhancedPublicParameters::<
            SOUND_PROOFS_REPETITIONS,
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
        >::new::<
            RangeProof,
            UnboundedEncDLWitness,
            encryption_of_discrete_log::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >(
            self.unbounded_encdl_witness_public_parameters.clone(),
            self.range_proof_public_parameters.clone(),
            enc_dl_public_parameters,
        )?;

        // Create (k_i, η^i_{mask_3}) tuples
        let witnesses: Vec<_> = shares_of_signature_nonce_shares_witnesses
            .clone()
            .into_iter()
            .zip(shares_of_signature_nonce_shares_encryption_randomness.clone())
            .map(|(nonce_share, encryption_randomness)| (nonce_share, encryption_randomness).into())
            .collect();

        // Map (k_i, η^i_{mask_3}) tuples to tuples of the form
        // - [commitment message]    cm_i = decomposed k_i
        // - [commitment randomness] cr_i = fresh random sampled value
        // - [unbounded witness]     uw_i = η^i_{mask_3}
        //
        let witnesses = EnhancedLanguage::<
            SOUND_PROOFS_REPETITIONS,
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
        >::generate_witnesses(witnesses, &enc_dl_public_parameters, rng)?;

        // === Prepare ct^i_3 computation ===
        // Protocol 5, step 2a (iii) C
        //
        // By calling `commit_statements_and_statement_mask` on this party,
        // ct^i_3 is created.
        //
        // sources:
        // --------
        // maurer::aggregation::commitment_round::commit_statements_and_statement_mask.
        // ct^i_3 = enhanced_maurer::Language::homomorphose(witnesses, &enc_dl_public_parameters).
        let nonce_sharing_commitment_round_party =
            enhanced_maurer::aggregation::commitment_round::Party::<
                SOUND_PROOFS_REPETITIONS,
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
                ProtocolContext,
            >::new_session(
                self.party_id,
                self.parties.clone(),
                enc_dl_public_parameters,
                self.protocol_context.clone(),
                witnesses,
                rng,
            )?;

        let party = encrypted_masked_nonces_round::Party {
            party_id: self.party_id,
            parties: self.parties,
            protocol_context: self.protocol_context,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            unbounded_encdh_witness_public_parameters: self
                .unbounded_encdh_witness_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            shares_of_signature_nonce_shares_witnesses,
            shares_of_signature_nonce_shares_encryption_randomness,
        };

        Ok((
            (
                key_share_masking_commitment_round_party,
                nonce_sharing_commitment_round_party,
            ),
            party,
        ))
    }

    pub fn new<
        const NUM_RANGE_CLAIMS: usize,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
    >(
        party_id: PartyID,
        threshold: PartyID,
        parties: HashSet<PartyID>,
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
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    ) -> crate::Result<Self> {
        let encryption_scheme_public_parameters =
            protocol_public_parameters.encryption_scheme_public_parameters;

        let encrypted_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            dkg_output.encrypted_secret_key_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        Ok(Self {
            party_id,
            threshold,
            parties,
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
            encrypted_secret_key_share,
        })
    }
}
