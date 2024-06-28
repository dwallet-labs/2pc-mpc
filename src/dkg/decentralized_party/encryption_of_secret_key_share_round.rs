// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use core::marker::PhantomData;
use std::collections::HashSet;

use commitment::Commitment;
use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use enhanced_maurer::{
    encryption_of_discrete_log, EnhanceableLanguage, EnhancedLanguage,
    language::EnhancedPublicParameters,
};
use group::{GroupElement as _, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::SOUND_PROOFS_REPETITIONS;
use proof::AggregatableRangeProof;
use serde::Serialize;

use crate::{
    dkg::decentralized_party::decommitment_proof_verification_round, Error,
    ProtocolPublicParameters,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
/// Party for the decentralized encryption of secret key share round.
/// This party is responsible for sampling the secret key share, preparing the computation of the
/// commitment to the secret key share and its zero-knowledge proof.
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
    party_id: PartyID,
    threshold: PartyID,
    parties: HashSet<PartyID>,
    protocol_context: ProtocolContext,
    group_public_parameters: GroupElement::PublicParameters,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
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
    /// This function implements step 2 of Protocol 4 (DKG):
    /// Samples $x_i$ and prepares computation of $ct_i$ & its zk-proof.
    /// Reruns the commitment to the secret key share and the `Party` for decommitment proof
    /// verification round.
    /// [Source](https://eprint.iacr.org/archive/2024/253/20240217:153208)
    pub fn sample_secret_key_share_and_initialize_proof_aggregation(
        self,
        commitment_to_centralized_party_secret_key_share: Commitment,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        // todo(scaly): what is it here? how is it this generic?
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
        decommitment_proof_verification_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            ProtocolContext,
        >,
    )> {
        if self.parties.len() < self.threshold.into() {
            return Err(Error::ThresholdNotReached);
        }

        // === Sample $x_i$ ====
        // Protocol 4, step 2b
        let share_of_decentralized_party_secret_key_share =
            GroupElement::Scalar::sample(&self.scalar_group_public_parameters, rng)?;

        let share_of_decentralized_party_secret_key_share_value: Uint<SCALAR_LIMBS> =
            share_of_decentralized_party_secret_key_share.into();

        // === Sample $ρ_i$ ===
        // Protocol 4, step 2d
        let encryption_randomness = EncryptionKey::RandomnessSpaceGroupElement::sample(
            &self
                .encryption_scheme_public_parameters
                .as_ref()
                .randomness_space_public_parameters,
            rng,
        )?;

        // Construct `L_EncDL` parameters
        // Used in emulating the idealized $F^{L_EncDL}_{agg-zk}$ component
        // Protocol 4, steps 2e and 2f.
        let language_public_parameters =
            encryption_of_discrete_log::PublicParameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
                self.encryption_scheme_public_parameters.clone(),
                GroupElement::generator_value_from_public_parameters(&self.group_public_parameters),
            );
        let language_public_parameters = EnhancedPublicParameters::<
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
            language_public_parameters,
        )?;

        // === Map (x_i, ρ_i) ====
        // map (x_i, ρ_i) to the triple
        // * [commitment_message]    cm_i = x_i
        // * [commitment_randomness] cr_i = randomly sampled value
        // * [unbounded_witness]     uw_i = ρ_i
        //
        // There is no direct mapping of this step to protocol 4;
        // they are used to emulate the idealized $F^{L_{EncDL}}_{agg-zk}$ component.
        let share_of_decentralized_party_secret_key_share_witness = EnhancedLanguage::<
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
        >::generate_witness(
            (
                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
                        &share_of_decentralized_party_secret_key_share_value,
                    )
                    .into(),
                    self.encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )?,
                encryption_randomness,
            )
                .into(),
            &language_public_parameters,
            rng,
        )?;

        // === Prepare ct_i computation ===
        // Protocol 4, step 2d
        //
        // By calling `commit_statements_and_statement_mask` on this party,
        // ct_i is created.
        //
        // sources:
        // --------
        // maurer::aggregation::commitment_round::commit_statements_and_statement_mask.
        // ct_i = enhanced_maurer::Language::homomorphose(witnesses, &enc_dl_public_parameters).
        // Note in this case Language is encryption_of_discrete_log::Language.
        let encryption_of_secret_share_commitment_round_party =
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
                language_public_parameters,
                // todo(scaly): doc what is protocol context.
                self.protocol_context.clone(),
                vec![share_of_decentralized_party_secret_key_share_witness],
                rng,
            )?;

        // Prepare decommitment proof verification round.
        let decommitment_round_party = decommitment_proof_verification_round::Party::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            ProtocolContext,
        > {
            protocol_context: self.protocol_context,
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            commitment_to_centralized_party_secret_key_share,
            _unbounded_witness_choice: PhantomData,
            _range_proof_choice: PhantomData,
        };

        Ok((
            encryption_of_secret_share_commitment_round_party,
            decommitment_round_party,
        ))
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
        party_id: PartyID,
        threshold: PartyID,
        parties: HashSet<PartyID>,
        protocol_context: ProtocolContext,
    ) -> Self {
        Party {
            party_id,
            threshold,
            parties,
            protocol_context,
            scalar_group_public_parameters: protocol_public_parameters
                .scalar_group_public_parameters,
            group_public_parameters: protocol_public_parameters.group_public_parameters,
            encryption_scheme_public_parameters: protocol_public_parameters
                .encryption_scheme_public_parameters,
            unbounded_encdl_witness_public_parameters: protocol_public_parameters
                .unbounded_encdl_witness_public_parameters,
            range_proof_public_parameters: protocol_public_parameters
                .range_proof_enc_dl_public_parameters,
        }
    }
}
