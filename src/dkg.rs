// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod centralized_party;
pub mod decentralized_party;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::marker::PhantomData;
    use std::{
        collections::{HashMap, HashSet},
        time::Duration,
    };

    use criterion::measurement::{Measurement, WallTime};
    use group::{ristretto, secp256k1, CyclicGroupElement, GroupElement, PartyID};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
    };
    use proof::{aggregation::test_helpers::aggregates, range::bulletproofs};
    use rand::seq::IteratorRandom;
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::{
        test_exports::{N, SECRET_KEY},
        LargeBiPrimeSizedNumber,
    };

    use super::*;
    use crate::{
        dkg::decentralized_party::SecretKeyShareEncryptionAndProof, tests::RANGE_CLAIMS_PER_SCALAR,
    };

    #[rstest]
    #[case(2, 2)]
    #[case(2, 4)]
    #[case(6, 9)]
    fn generates_distributed_key(#[case] number_of_parties: PartyID, #[case] threshold: PartyID) {
        generates_distributed_key_internal(number_of_parties, threshold);
    }

    #[allow(dead_code)]
    pub fn generates_distributed_key_internal(
        number_of_parties: PartyID,
        threshold: PartyID,
    ) -> (
        centralized_party::Output<
            secp256k1::group_element::Value,
            secp256k1::Scalar,
            tiresias::CiphertextSpaceValue,
        >,
        decentralized_party::Output<
            secp256k1::group_element::Value,
            tiresias::CiphertextSpaceValue,
        >,
    ) {
        let measurement = WallTime;
        let mut centralized_party_total_time = Duration::ZERO;
        let mut decentralized_party_total_time = Duration::ZERO;

        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let paillier_decryption_key =
            tiresias::DecryptionKey::new(SECRET_KEY, &paillier_public_parameters).unwrap();

        let centralized_party_commitment_round_party = centralized_party::commitment_round::Party::<
            { secp256k1::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            bulletproofs::RangeProof,
            tiresias::RandomnessSpaceGroupElement,
            PhantomData<()>,
        > {
            protocol_context: PhantomData::<()>,
            scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
            group_public_parameters: secp256k1_group_public_parameters.clone(),
            encryption_scheme_public_parameters: paillier_public_parameters.clone(),
            range_proof_public_parameters: bulletproofs_public_parameters.clone(),
            unbounded_encdl_witness_public_parameters: paillier_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        };

        let now = measurement.start();
        let (
            commitment_to_centralized_party_secret_key_share,
            centralized_party_decommitment_round_party,
        ) = centralized_party_commitment_round_party
            .sample_commit_and_prove_secret_key_share(&mut OsRng)
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let mut parties = HashSet::new();
        (1..=number_of_parties)
            .choose_multiple(&mut OsRng, threshold.into())
            .into_iter()
            .for_each(|party_id| {
                parties.insert(party_id);
            });
        let evaluation_party_id = *parties.iter().next().unwrap();

        let decentralized_party_encryption_of_secret_key_share_parties: HashMap<_, _> = parties
            .clone()
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    decentralized_party::encryption_of_secret_key_share_round::Party::<
                        { secp256k1::SCALAR_LIMBS },
                        { ristretto::SCALAR_LIMBS },
                        { RANGE_CLAIMS_PER_SCALAR },
                        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        secp256k1::GroupElement,
                        tiresias::EncryptionKey,
                        bulletproofs::RangeProof,
                        tiresias::RandomnessSpaceGroupElement,
                        PhantomData<()>,
                    > {
                        party_id,
                        parties: parties.clone(),
                        protocol_context: PhantomData::<()>,
                        scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
                        group_public_parameters: secp256k1_group_public_parameters.clone(),
                        encryption_scheme_public_parameters: paillier_public_parameters.clone(),
                        unbounded_encdl_witness_public_parameters: paillier_public_parameters
                            .randomness_space_public_parameters()
                            .clone(),
                        range_proof_public_parameters: bulletproofs_public_parameters.clone(),
                    },
                )
            })
            .collect();

        let (
            decentralized_party_encryption_of_secret_key_share_commitment_round_parties,
            decentralized_party_decommitment_proof_verification_round_parties,
        ): (HashMap<_, _>, HashMap<_, _>) =
            decentralized_party_encryption_of_secret_key_share_parties
                .into_iter()
                .map(|(party_id, party)| {
                    let now = measurement.start();
                    let (
                        encryption_of_secret_key_share_commitment_round_party,
                        decommitment_proof_verification_round_party,
                    ) = party
                        .sample_secret_key_share_and_initialize_proof_aggregation(
                            commitment_to_centralized_party_secret_key_share,
                            &mut OsRng,
                        )
                        .unwrap();
                    if party_id == evaluation_party_id {
                        decentralized_party_total_time =
                            measurement.add(&decentralized_party_total_time, &measurement.end(now));
                    };

                    (
                        (
                            party_id,
                            encryption_of_secret_key_share_commitment_round_party,
                        ),
                        (party_id, decommitment_proof_verification_round_party),
                    )
                })
                .unzip();

        let (
            ..,
            encryption_of_decentralized_party_secret_share_time,
            (
                encryption_of_decentralized_party_secret_share_proof,
                encryption_of_decentralized_party_secret_share,
            ),
        ) = aggregates(decentralized_party_encryption_of_secret_key_share_commitment_round_parties);

        let encryption_of_decentralized_party_secret_share =
            *encryption_of_decentralized_party_secret_share
                .first()
                .unwrap();

        let secret_key_share_encryption_and_proof = SecretKeyShareEncryptionAndProof::new(
            encryption_of_decentralized_party_secret_share,
            encryption_of_decentralized_party_secret_share_proof,
        );

        let now = measurement.start();
        let (
            centralized_party_public_key_share_decommitment_and_proof,
            centralized_party_dkg_output,
        ) = centralized_party_decommitment_round_party
            .decommit_proof_public_key_share(
                secret_key_share_encryption_and_proof.clone(),
                &mut OsRng,
            )
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let decentralized_party_public_key_share = secp256k1::GroupElement::new(
            centralized_party_dkg_output.decentralized_party_public_key_share,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let secret_key_share = secp256k1::Scalar::new(
            centralized_party_dkg_output.secret_key_share,
            &secp256k1_scalar_public_parameters,
        )
        .unwrap();

        let public_key_share = secp256k1::GroupElement::new(
            centralized_party_dkg_output.public_key_share,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let public_key = secp256k1::GroupElement::new(
            centralized_party_dkg_output.public_key,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        assert_eq!(
            decentralized_party_public_key_share + public_key_share,
            public_key
        );

        let generator = public_key_share.generator();

        assert_eq!(secret_key_share * generator, public_key_share);

        let decentralized_party_dkg_outputs: HashMap<_, _> =
            decentralized_party_decommitment_proof_verification_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    let now = measurement.start();
                    let res = party
                        .verify_decommitment_and_proof_of_centralized_party_public_key_share(
                            centralized_party_public_key_share_decommitment_and_proof.clone(),
                            secret_key_share_encryption_and_proof.clone(),
                        )
                        .unwrap();
                    if party_id == evaluation_party_id {
                        decentralized_party_total_time =
                            measurement.add(&decentralized_party_total_time, &measurement.end(now));
                    };

                    (party_id, res)
                })
                .collect();

        let decentralized_party_dkg_output =
            decentralized_party_dkg_outputs.get(&1).unwrap().clone();

        assert!(decentralized_party_dkg_outputs
            .clone()
            .into_iter()
            .all(|(_, output)| decentralized_party_dkg_output == output));

        assert!(decentralized_party_dkg_outputs
            .into_iter()
            .all(|(_, dkg_output)| {
                let encrypted_secret_key_share = tiresias::CiphertextSpaceGroupElement::new(
                    dkg_output.encrypted_secret_key_share,
                    paillier_public_parameters.ciphertext_space_public_parameters(),
                )
                .unwrap();

                let decentralized_party_secret_key_share_decryption: LargeBiPrimeSizedNumber =
                    paillier_decryption_key
                        .decrypt(&encrypted_secret_key_share, &paillier_public_parameters)
                        .unwrap()
                        .into();

                let decentralized_party_secret_key_share: secp256k1::Scalar =
                    decentralized_party_secret_key_share_decryption.into();

                let public_key_share = secp256k1::GroupElement::new(
                    dkg_output.public_key_share,
                    &secp256k1_group_public_parameters,
                )
                .unwrap();

                let centralized_party_public_key_share = secp256k1::GroupElement::new(
                    dkg_output.centralized_party_public_key_share,
                    &secp256k1_group_public_parameters,
                )
                .unwrap();

                (dkg_output.encrypted_secret_key_share
                    == centralized_party_dkg_output.encrypted_decentralized_party_secret_key_share)
                    && ((decentralized_party_secret_key_share * generator).value()
                        == dkg_output.public_key_share)
                    && dkg_output.centralized_party_public_key_share
                        == centralized_party_dkg_output.public_key_share
                    && ((centralized_party_public_key_share + public_key_share).value()
                        == dkg_output.public_key)
            }));

        decentralized_party_total_time = measurement.add(
            &decentralized_party_total_time,
            &encryption_of_decentralized_party_secret_share_time,
        );

        println!(
            "\nProtocol, Number of Parties, Threshold, Centralized Party Total Time (ms), Decentralized Party Total Time (ms)",
        );

        println!(
            "DKG, {number_of_parties}, {threshold}, {:?}, {:?}",
            centralized_party_total_time.as_millis(),
            decentralized_party_total_time.as_millis()
        );

        (centralized_party_dkg_output, decentralized_party_dkg_output)
    }
}
