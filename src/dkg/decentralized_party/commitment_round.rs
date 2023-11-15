// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe,
    dkg::decentralized_party::decommitment_round,
    group,
    group::{GroupElement as _, PrimeGroupElement, Samplable},
    proofs,
    proofs::{
        range,
        schnorr::{encryption_of_discrete_log, language::enhanced},
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
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
    >,
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
    pub group_public_parameters: GroupElement::PublicParameters,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    // TODO: should we get this like that?
    pub protocol_context: ProtocolContext,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters,
    // TODO: do I want to get it here as a member, or create it myself?
    // perhaps I should not take the other public parameters that are derived from it if so, or
    // else there could be conflicts - like if the two passed public parameters are not the same in
    // the langauge and outside it.
    pub encryption_of_discrete_log_language_public_parameters:
        encryption_of_discrete_log::LanguagePublicParameters<
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
        >,
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
            RANGE_CLAIMS_PER_SCALAR,
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
    fn sample_and_commit_share_of_decentralize_party_secret_key_share(
        self,
        party_id: PartyID,
        threshold_paillier_associate_bi_prime: Uint<
            { ahe::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >,
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
        // if RangeProof::RANGE_CLAIM_BITS != 0
        //     || (SCALAR_LIMBS / RangeProof::RANGE_CLAIM_BITS)
        //         + ((SCALAR_LIMBS % RangeProof::RANGE_CLAIM_BITS) % 2)
        //         != RANGE_CLAIMS_PER_SCALAR
        // {
        //     return Err(crate::Error::InvalidParameters);
        // }
        //
        // let share_of_decentralize_party_secret_key_share =
        //     GroupElement::Scalar::sample(rng, &self.scalar_group_public_parameters)?;
        //
        // let share_of_decentralize_party_secret_key_share_uint: Uint<SCALAR_LIMBS> =
        //     share_of_decentralize_party_secret_key_share.value().into();
        // let share_of_decentralize_party_secret_key_share_in_range_claim_base: [Uint<
        //     RANGE_CLAIM_LIMBS,
        // >;
        //     RANGE_CLAIMS_PER_SCALAR] = if RANGE_CLAIM_LIMBS >= SCALAR_LIMBS {
        //     [(&share_of_decentralize_party_secret_key_share_uint).into()]
        // } else {
        //     todo!()
        // };
        //
        // // TODO: convert this to the language witness...
        // // TODO: construct this language public parameters from components
        //
        // let encryption_of_secret_share_commitment_round_party =
        //     encryption_of_discrete_log::ProofAggregationCommitmentRoundParty::<
        //         SCALAR_LIMBS,
        //         RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        //         RANGE_CLAIMS_PER_SCALAR,
        //         RANGE_CLAIM_LIMBS,
        //         WITNESS_MASK_LIMBS,
        //         PLAINTEXT_SPACE_SCALAR_LIMBS,
        //         GroupElement::Scalar,
        //         GroupElement,
        //         EncryptionKey,
        //         RangeProof,
        //         ProtocolContext,
        //     > { party_id: self.party_id, threshold: self.threshold, number_of_parties:
        //     > self.number_of_parties, language_public_parameters: self
        //     > .encryption_of_discrete_log_language_public_parameters, protocol_context:
        //     > self.protocol_context, witnesses:
        //     > vec![share_of_decentralize_party_secret_key_share],
        //     };
        //
        // // let encryption_of_secret_key_share_commitment_round_party =
        // //     aggregation::commitment_round::Party::<
        // //         EncryptionOfSecretKeyShareLanguage,
        // //         PhantomData<()>,
        // //     > { party_id, language_public_parameters, protocol_context: PhantomData,witnesses:
        // //     > vec![share_of_decentralize_party_secret_key_share],
        // //     };
        todo!()
    }
}
