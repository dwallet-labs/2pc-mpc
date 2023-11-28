// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use core::array;

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
    proofs,
    proofs::{
        range,
        range::CommitmentPublicParametersAccessor as _,
        schnorr::{
            encryption_of_discrete_log,
            language::{enhanced, enhanced::DecomposableWitness},
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
    // TODO: consistent naming with presign
    pub fn sample_and_commit_share_of_decentralize_party_secret_key_share(
        self,
        commitment_to_centralized_party_secret_key_share: Commitment,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        Commitment,
        decommitment_round::Party<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
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
            rng,
            &self
                .encryption_scheme_public_parameters
                .as_ref()
                .randomness_space_public_parameters,
        )?;

        let range_proof_commitment_randomness = commitments::RandomnessSpaceGroupElement::<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof::CommitmentScheme<RANGE_CLAIMS_PER_SCALAR>,
        >::sample(
            rng,
            &self
                .range_proof_public_parameters
                .commitment_public_parameters()
                .randomness_space_public_parameters(),
        )?;

        let share_of_decentralized_party_secret_key_share =
            GroupElement::Scalar::sample(rng, &self.scalar_group_public_parameters)?;

        let share_of_decentralize_party_secret_key_share_witness =
            share_of_decentralized_party_secret_key_share
                .decompose_into_constrained_witness(RangeProof::RANGE_CLAIM_BITS);

        // TODO: convert this to the language witness...
        // TODO: construct this language public parameters from components

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

        let encryption_of_secret_share_commitment_round_party =
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
                witnesses: vec![(
                    share_of_decentralize_party_secret_key_share_witness,
                    range_proof_commitment_randomness,
                    encryption_randomness,
                )
                    .into()],
            };

        let (
            encryption_of_secret_share_commitment,
            encryption_of_secret_share_decommitment_round_party,
        ) = encryption_of_secret_share_commitment_round_party
            .commit_statements_and_statement_mask(rng)?;

        let decommitment_round_party = decommitment_round::Party::<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            ProtocolContext,
        > {
            party_id: self.party_id,
            threshold: self.threshold,
            number_of_parties: self.number_of_parties,
            protocol_context: self.protocol_context,
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            commitment_to_centralized_party_secret_key_share,
            encryption_of_secret_share_decommitment_round_party,
            share_of_decentralized_party_secret_key_share,
        };

        Ok((
            encryption_of_secret_share_commitment,
            decommitment_round_party,
        ))
    }
}
