// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crate::group::CyclicGroupElement;

pub mod centralized_party;
pub mod decentralized_party;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::marker::PhantomData;
    use std::collections::HashMap;

    use crypto_bigint::U256;
    use rand_core::OsRng;
    use tiresias::LargeBiPrimeSizedNumber;

    use super::*;
    use crate::{
        ahe,
        ahe::{
            paillier,
            paillier::tests::{N, SECRET_KEY},
            AdditivelyHomomorphicDecryptionKey,
        },
        dkg::centralized_party,
        group::{ristretto, secp256k1, CyclicGroupElement},
        proofs::{
            range::{bulletproofs, RangeProof},
            schnorr::language::enhanced::tests::{RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS},
        },
    };

    #[test]
    fn dkg_succeeds() {
        let number_of_parties = 3;
        let threshold = 2;

        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let paillier_decryption_key =
            ahe::paillier::DecryptionKey::new(&paillier_public_parameters, SECRET_KEY).unwrap();

        let centralized_party_commitment_round_party = centralized_party::commitment_round::Party::<
            { secp256k1::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            RANGE_CLAIMS_PER_SCALAR,
            { bulletproofs::RANGE_CLAIM_LIMBS },
            { WITNESS_MASK_LIMBS },
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
            bulletproofs::RangeProof,
            PhantomData<()>,
        > {
            protocol_context: PhantomData::<()>,
            scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
            group_public_parameters: secp256k1_group_public_parameters.clone(),
            encryption_scheme_public_parameters: paillier_public_parameters.clone(),
            range_proof_public_parameters: bulletproofs_public_parameters.clone(),
        };

        let (
            commitment_to_centralized_party_secret_key_share,
            centralized_party_decommitment_round_party,
        ) = centralized_party_commitment_round_party
            .sample_commit_and_prove_secret_key_share(&mut OsRng)
            .unwrap();

        let decentralized_party_commitment_round_parties: HashMap<_, _> = (1..=number_of_parties)
            .map(|party_id| {
                let party_id: u16 = party_id.try_into().unwrap();
                (
                    party_id,
                    decentralized_party::commitment_round::Party::<
                        { secp256k1::SCALAR_LIMBS },
                        { ristretto::SCALAR_LIMBS },
                        RANGE_CLAIMS_PER_SCALAR,
                        { bulletproofs::RANGE_CLAIM_LIMBS },
                        { WITNESS_MASK_LIMBS },
                        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        secp256k1::GroupElement,
                        paillier::EncryptionKey,
                        bulletproofs::RangeProof,
                        PhantomData<()>,
                    > {
                        party_id,
                        threshold,
                        number_of_parties,
                        protocol_context: PhantomData::<()>,
                        scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
                        group_public_parameters: secp256k1_group_public_parameters.clone(),
                        encryption_scheme_public_parameters: paillier_public_parameters.clone(),
                        range_proof_public_parameters: bulletproofs_public_parameters.clone(),
                    },
                )
            })
            .collect();

        let decentralized_party_commitments_and_decommitment_round_parties: HashMap<_, _> =
            decentralized_party_commitment_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    (
                        party_id,
                        party
                            .sample_and_commit_share_of_decentralize_party_secret_key_share(
                                commitment_to_centralized_party_secret_key_share,
                                &mut OsRng,
                            )
                            .unwrap(),
                    )
                })
                .collect();

        let commitments: HashMap<_, _> =
            decentralized_party_commitments_and_decommitment_round_parties
                .iter()
                .map(|(party_id, (commitment, _))| (*party_id, *commitment))
                .collect();

        let decentralized_party_decommitments_and_proof_share_round_parties: HashMap<_, _> =
            decentralized_party_commitments_and_decommitment_round_parties
                .into_iter()
                .map(|(party_id, (_, party))| {
                    (
                        party_id,
                        party
                            .decommit_share_of_decentralize_party_public_key_share(
                                commitments.clone(),
                            )
                            .unwrap(),
                    )
                })
                .collect();

        let decommitments: HashMap<_, _> =
            decentralized_party_decommitments_and_proof_share_round_parties
                .iter()
                .map(|(party_id, (decommitment, _))| (*party_id, decommitment.clone()))
                .collect();

        let decentralized_party_proof_shares_and_proof_aggregation_round_parties: HashMap<_, _> =
            decentralized_party_decommitments_and_proof_share_round_parties
                .into_iter()
                .map(|(party_id, (_, party))| {
                    (
                        party_id,
                        party.generate_proof_share(decommitments.clone()).unwrap(),
                    )
                })
                .collect();

        let proof_shares: HashMap<_, _> =
            decentralized_party_proof_shares_and_proof_aggregation_round_parties
                .iter()
                .map(|(party_id, (proof_share, _))| (*party_id, proof_share.clone()))
                .collect();

        let decentralized_party_secret_key_share_encryption_and_proofs_and_decommitment_proof_verification_round_parties: HashMap<_, _> =
            decentralized_party_proof_shares_and_proof_aggregation_round_parties
                .into_iter()
                .map(|(party_id, (_, party))| {
                    (
                        party_id,
                        party.aggregate_proof_shares(proof_shares.clone()).unwrap(),
                    )
                })
                .collect();

        let secret_key_share_encryption_and_proofs: Vec<_> =
            decentralized_party_secret_key_share_encryption_and_proofs_and_decommitment_proof_verification_round_parties
                .iter()
                .map(|(_, (proof_share, _))| proof_share.clone())
                .collect();

        let secret_key_share_encryption_and_proof = secret_key_share_encryption_and_proofs
            .first()
            .unwrap()
            .clone();

        assert!(secret_key_share_encryption_and_proofs
            .into_iter()
            .all(|enc_proof| enc_proof == secret_key_share_encryption_and_proof));

        let (
            centralized_party_public_key_share_decommitment_and_proof,
            centralized_party_dkg_output,
        ) = centralized_party_decommitment_round_party
            .decommit_proof_public_key_share(secret_key_share_encryption_and_proof)
            .unwrap();

        assert_eq!(
            centralized_party_dkg_output.decentralized_party_public_key_share
                + &centralized_party_dkg_output.public_key_share,
            centralized_party_dkg_output.public_key
        );

        let generator = centralized_party_dkg_output.public_key_share.generator();

        assert_eq!(
            centralized_party_dkg_output.secret_key_share * &generator,
            centralized_party_dkg_output.public_key_share
        );

        let decentralized_party_dkg_outputs: HashMap<_, _> =
            decentralized_party_secret_key_share_encryption_and_proofs_and_decommitment_proof_verification_round_parties
                .into_iter()
                .map(|(party_id, (_, party))| {
                    (
                        party_id,
                        party.verify_decommitment_and_proof_of_centralized_party_public_key_share(centralized_party_public_key_share_decommitment_and_proof.clone()).unwrap(),
                    )
                })
                .collect();

        assert!(decentralized_party_dkg_outputs
            .into_iter()
            .all(|(_, dkg_output)| {
                let decentralized_party_secret_key_share_decryption: LargeBiPrimeSizedNumber =
                    paillier_decryption_key
                        .decrypt(&dkg_output.encryption_of_secret_key_share)
                        .into();

                let decentralized_party_secret_key_share: secp256k1::Scalar =
                    decentralized_party_secret_key_share_decryption.into();

                (dkg_output.encryption_of_secret_key_share
                    == centralized_party_dkg_output
                        .encryption_of_decentralized_party_secret_key_share)
                    && (decentralized_party_secret_key_share * &generator
                        == dkg_output.public_key_share)
                    && (dkg_output.centralized_party_public_key_share
                        + &dkg_output.public_key_share
                        == dkg_output.public_key)
            }));
    }
}
