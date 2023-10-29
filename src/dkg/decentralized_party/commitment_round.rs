// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::Uint;
use rand_core::OsRng;

use crate::{
    ahe,
    dkg::decentralized_party::decommitment_round,
    group::{
        additive_group_of_integers_modulu_n::power_of_two_moduli, secp256k1, self_product,
        Samplable,
    },
    proofs::{
        range,
        range::bulletproofs::RANGE_CLAIM_BITS,
        schnorr::{aggregation, encryption_of_discrete_log, language::GroupsPublicParameters},
    },
    Commitment, ComputationalSecuritySizedNumber, PartyID, StatisticalSecuritySizedNumber,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party {}

impl Party {
    fn sample_and_commit_share_of_decentralize_party_secret_key_share(
        party_id: PartyID,
        threshold_paillier_associate_bi_prime: Uint<
            { ahe::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >,
        commitment_to_centralized_party_secret_key_share: Commitment,
        rng: &mut OsRng,
    ) -> (Commitment, decommitment_round::Party) {
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
