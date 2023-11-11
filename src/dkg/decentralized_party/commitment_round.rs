// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::Serialize;

use crate::{
    ahe,
    dkg::decentralized_party::decommitment_round,
    group,
    group::PrimeGroupElement,
    proofs,
    proofs::{
        range,
        schnorr::language::{enhanced, enhanced::RangeProof},
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
{
    pub group_public_parameters: GroupElement::PublicParameters,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    // TODO: should we get this like that?
    pub protocol_context: ProtocolContext,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters,
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
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    fn sample_and_commit_share_of_decentralize_party_secret_key_share(
        party_id: PartyID,
        threshold_paillier_associate_bi_prime: Uint<
            { ahe::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >,
        commitment_to_centralized_party_secret_key_share: Commitment,
        rng: &mut impl CryptoRngCore,
    ) -> (
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
    ) {
        // let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        //
        // let secp256k1_group_public_parameters =
        //     secp256k1::group_element::PublicParameters::default();
        //
        // let bulletproofs_public_parameters =
        //     range::bulletproofs::PublicParameters::<{ super::RANGE_CLAIMS_PER_SCALAR
        // }>::default();
        //
        // // TODO: should we validate this here, or assume the modulus was validated already?
        // let paillier_public_parameters =
        //     ahe::paillier::PublicParameters::new(threshold_paillier_associate_bi_prime).unwrap();
        //
        // // TODO: think how we can generalize this with `new()` for `PublicParameters` (of
        // encryption // of discrete log).
        //
        // let constrained_witness_public_parameters =
        //     power_of_two_moduli::PublicParameters::<{ super::WITNESS_MASK_LIMBS }> {
        //         sampling_bit_size: RANGE_CLAIM_BITS
        //             + ComputationalSecuritySizedNumber::BITS
        //             + StatisticalSecuritySizedNumber::BITS,
        //     };
        //
        // let witness_space_public_parameters = (
        //     self_product::PublicParameters::<
        //         { super::RANGE_CLAIMS_PER_SCALAR },
        //         power_of_two_moduli::PublicParameters<{ super::WITNESS_MASK_LIMBS }>,
        //     >::new(constrained_witness_public_parameters),
        //     bulletproofs_public_parameters
        //         .as_ref()
        //         .as_ref()
        //         .randomness_space_public_parameters
        //         .clone(),
        //     paillier_public_parameters
        //         .as_ref()
        //         .randomness_space_public_parameters
        //         .clone(),
        // )
        //     .into();
        //
        // let statement_space_public_parameters = (
        //     bulletproofs_public_parameters
        //         .as_ref()
        //         .as_ref()
        //         .commitment_space_public_parameters
        //         .clone(),
        //     (
        //         paillier_public_parameters
        //             .as_ref()
        //             .ciphertext_space_public_parameters
        //             .clone(),
        //         secp256k1_group_public_parameters.clone(),
        //     )
        //         .into(),
        // )
        //     .into();
        //
        // let groups_public_parameters = GroupsPublicParameters {
        //     witness_space_public_parameters,
        //     statement_space_public_parameters,
        // };
        //
        // let language_public_parameters = encryption_of_discrete_log::PublicParameters {
        //     groups_public_parameters,
        //     commitment_scheme_public_parameters: bulletproofs_public_parameters.as_ref().clone(),
        //     encryption_scheme_public_parameters: paillier_public_parameters,
        //     scalar_group_public_parameters: secp256k1_scalar_public_parameters,
        //     generator: secp256k1_group_public_parameters.generator,
        // };
        //
        // let share_of_decentralize_party_secret_key_share =
        //     secp256k1::Scalar::sample(rng, &secp256k1_scalar_public_parameters).unwrap();
        //
        // let encryption_of_secret_key_share_commitment_round_party =
        //     aggregation::commitment_round::Party::<
        //         super::EncryptionOfSecretKeyShareLanguage,
        //         PhantomData<()>,
        //     > { party_id, language_public_parameters, protocol_context: PhantomData, witnesses:
        //     > vec![share_of_decentralize_party_secret_key_share],
        //     };
        todo!()
    }
}
