// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashSet;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use enhanced_maurer::{
    encryption_of_discrete_log, encryption_of_tuple, encryption_of_tuple::StatementAccessors,
    language::composed_witness_upper_bound, EnhanceableLanguage, EnhancedLanguage,
    EnhancedPublicParameters,
};
use group::{GroupElement as _, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::SOUND_PROOFS_REPETITIONS;
use proof::AggregatableRangeProof;
use serde::Serialize;

use crate::{Error, Result};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedEncDHWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
    pub(super) party_id: PartyID,
    pub parties: HashSet<PartyID>,
    // TODO: should we get this like that?
    pub(super) protocol_context: ProtocolContext,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub(super) unbounded_encdh_witness_public_parameters: UnboundedEncDHWitness::PublicParameters,
    pub(super) range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
    pub(super) shares_of_signature_nonce_shares_witnesses:
        Vec<EncryptionKey::PlaintextSpaceGroupElement>,
    pub(super) shares_of_signature_nonce_shares_encryption_randomness:
        Vec<EncryptionKey::RandomnessSpaceGroupElement>,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
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
        UnboundedEncDHWitness,
        ProtocolContext,
    >
where
    // TODO: I'd love to solve this huge restriction, which seems completely useless to me and is
    // required because Rust.
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
    pub fn initialize_proof_aggregation(
        self,
        masks_and_encrypted_masked_key_share: Vec<
            encryption_of_tuple::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                EncryptionKey,
            >,
        >,
        encrypted_nonce_shares_and_public_shares: Vec<
            encryption_of_discrete_log::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        Vec<
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
        >,
    > {
        // TODO: do we need to make sure the vectors are same size?
        let batch_size = encrypted_nonce_shares_and_public_shares.len();

        let encrypted_masks: Vec<_> = masks_and_encrypted_masked_key_share
            .iter()
            .map(|statement| statement.encrypted_multiplicand().clone())
            .collect();

        // TODO: we're not sampling new encryption randomness here for the encryption of the nonce
        // share, this is intended, just making sure.

        let masked_nonce_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
                &self
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                batch_size,
                rng,
            )?;

        encrypted_masks
            .into_iter()
            .zip(
                self.shares_of_signature_nonce_shares_witnesses
                    .into_iter()
                    .zip(
                        self.shares_of_signature_nonce_shares_encryption_randomness
                            .into_iter()
                            .zip(masked_nonce_encryption_randomness.clone().into_iter()),
                    ),
            )
            .map(
                |(
                    encrypted_mask,
                    (nonce, (nonces_encryption_randomness, masked_nonces_encryption_randomness)),
                )| {
                    let encrypted_mask_upper_bound = composed_witness_upper_bound::<
                        RANGE_CLAIMS_PER_SCALAR,
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                        RangeProof,
                    >()?;

                    let language_public_parameters = encryption_of_tuple::PublicParameters::<
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        SCALAR_LIMBS,
                        GroupElement,
                        EncryptionKey,
                    >::new::<SCALAR_LIMBS, GroupElement, EncryptionKey>(
                        self.scalar_group_public_parameters.clone(),
                        self.encryption_scheme_public_parameters.clone(),
                        encrypted_mask.value(),
                        encrypted_mask_upper_bound,
                    );

                    let language_public_parameters = EnhancedPublicParameters::<
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
                        language_public_parameters,
                    )?;

                    EnhancedLanguage::<
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
                    >::generate_witness(
                        (
                            nonce,
                            nonces_encryption_randomness,
                            masked_nonces_encryption_randomness,
                        )
                            .into(),
                        &language_public_parameters,
                        rng,
                    )
                    .map_err(Error::from)
                    .and_then(|witness| {
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
                            language_public_parameters,
                            self.protocol_context.clone(),
                            vec![witness],
                            rng,
                        )
                        .map_err(Error::from)
                    })
                },
            )
            .collect()
    }
}
