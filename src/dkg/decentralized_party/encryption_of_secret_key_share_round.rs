// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use core::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe,
    ahe::GroupsPublicParametersAccessors,
    commitments,
    commitments::GroupsPublicParametersAccessors as _,
    dkg::decentralized_party::decommitment_proof_verification_round,
    group,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, GroupElement as _,
        KnownOrderScalar, NumbersGroupElement, PrimeGroupElement, Samplable,
    },
    proofs,
    proofs::{
        range, schnorr,
        schnorr::{
            aggregation::CommitmentRoundParty,
            encryption_of_discrete_log, enhanced,
            enhanced::{EnhanceableLanguage, EnhancedLanguage, EnhancedPublicParameters},
            language,
        },
    },
    AdditivelyHomomorphicEncryptionKey, Commitment, PartyID,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub party_id: PartyID,
    pub threshold: PartyID,
    pub number_of_parties: PartyID,
    pub protocol_context: ProtocolContext,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        RangeProof: proofs::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
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
    >
where
    encryption_of_discrete_log::Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >: schnorr::Language<
            { encryption_of_discrete_log::REPETITIONS },
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
            { encryption_of_discrete_log::REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDLWitness,
        >,
{
    pub fn sample_secret_key_share_and_initialize_proof_aggregation(
        self,
        commitment_to_centralized_party_secret_key_share: Commitment,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        range::CommitmentRoundParty<
            { encryption_of_discrete_log::REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedEncDLWitness,
            RangeProof,
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
            ProtocolContext,
        >,
    )> {
        // todo: this assumes we are proving the maximum of the bits for every part?
        // maybe we want to allow in the interface of the range proof to prove smaller chunks or
        // smth if not, maybe we want to assure SCALAR_LIMBS % RANGE_CLAIM_BITS == 0 or
        // SCALAR_LIMBS < RANGE_CLAIM_BITS. in any case this check is incorrect.
        // TODO: what check should I do here
        // if RangeProof::RANGE_CLAIM_BITS != 0
        //     || (SCALAR_LIMBS / RangeProof::RANGE_CLAIM_BITS)
        //         + ((SCALAR_LIMBS % RangeProof::RANGE_CLAIM_BITS) % 2)
        //         != RANGE_CLAIMS_PER_SCALAR
        // {
        //     return Err(crate::Error::InvalidParameters);
        // }

        let encryption_randomness = EncryptionKey::RandomnessSpaceGroupElement::sample(
            &self
                .encryption_scheme_public_parameters
                .as_ref()
                .randomness_space_public_parameters,
            rng,
        )?;

        let share_of_decentralized_party_secret_key_share =
            GroupElement::Scalar::sample(&self.scalar_group_public_parameters, rng)?;

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
            );

        let language_public_parameters = EnhancedPublicParameters::<
            { encryption_of_discrete_log::REPETITIONS },
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
        );

        let share_of_decentralized_party_secret_key_share_value: Uint<SCALAR_LIMBS> =
            share_of_decentralized_party_secret_key_share.into();

        let share_of_decentralized_party_secret_key_share_witness = EnhancedLanguage::<
            { encryption_of_discrete_log::REPETITIONS },
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

        let encryption_of_secret_share_commitment_round_party = RangeProof::new_enhanced_session::<
            { encryption_of_discrete_log::REPETITIONS },
            RANGE_CLAIMS_PER_SCALAR,
            UnboundedEncDLWitness,
            encryption_of_discrete_log::Language<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
            ProtocolContext,
        >(
            self.party_id,
            self.threshold,
            self.number_of_parties,
            language_public_parameters,
            self.protocol_context.clone(),
            vec![share_of_decentralized_party_secret_key_share_witness],
        );

        let decommitment_round_party = decommitment_proof_verification_round::Party::<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            ProtocolContext,
        > {
            party_id: self.party_id,
            threshold: self.threshold,
            number_of_parties: self.number_of_parties,
            protocol_context: self.protocol_context,
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            commitment_to_centralized_party_secret_key_share,
            share_of_decentralized_party_secret_key_share,
            _encryption_key_choice: PhantomData,
        };

        Ok((
            encryption_of_secret_share_commitment_round_party,
            decommitment_round_party,
        ))
    }
}
