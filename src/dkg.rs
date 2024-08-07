// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod centralized_party;
pub mod decentralized_party;

#[cfg(all(
    any(test, feature = "benchmarking"),
    feature = "secp256k1",
    feature = "paillier",
    feature = "bulletproofs",
))]
pub(crate) mod tests {
    use core::marker::PhantomData;
    use std::{
        collections::{HashMap, HashSet},
        time::Duration,
    };

    use criterion::measurement::{Measurement, WallTime};
    use group::{CyclicGroupElement, GroupElement, PartyID, secp256k1};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
    };
    use proof::aggregation::test_helpers::aggregates;
    use rand::seq::IteratorRandom;
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::{
        LargeBiPrimeSizedNumber,
        test_exports::{N, SECRET_KEY},
    };

    use crate::{
        dkg::decentralized_party::SecretKeyShareEncryptionAndProof, ProtocolPublicParameters,
    };

    use super::*;

    #[rstest]
    #[case(2, 2)]
    #[case(2, 4)]
    #[case(6, 9)]
    fn generates_distributed_key(#[case] threshold: PartyID, #[case] number_of_parties: PartyID) {
        generates_distributed_key_internal(threshold, number_of_parties);
    }

    pub fn generates_distributed_key_internal(
        threshold: PartyID,
        number_of_parties: PartyID,
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

        let protocol_public_parameters = ProtocolPublicParameters::new(N);

        let centralized_party_commitment_round = centralized_party::commitment_round::Party::new(
            protocol_public_parameters.clone(),
            PhantomData,
        );

        let now = measurement.start();
        // DKG Protocol A's first message.
        let (
            commitment_to_centralized_party_secret_key_share,
            centralized_party_decommitment_round,
        ) = centralized_party_commitment_round
            .sample_commit_and_prove_secret_key_share(&mut OsRng)
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        // Create N decentralized parties - $b1, b2, ..., bN$.
        let mut parties = HashSet::new();
        (1..=number_of_parties)
            .choose_multiple(&mut OsRng, threshold.into())
            .iter()
            .for_each(|&party_id| {
                parties.insert(party_id);
            });
        let &evaluation_party_id = parties.iter().next().unwrap();

        // Create the decentralized parties encryption of the secret key share round.
        let decentralized_parties_encryption_of_secret_key_share: HashMap<_, _> = parties
            .iter()
            .map(|&party_id| {
                (
                    party_id,
                    decentralized_party::encryption_of_secret_key_share_round::Party::new(
                        protocol_public_parameters.clone(),
                        party_id,
                        threshold,
                        parties.clone(),
                        PhantomData::<()>,
                    ),
                )
            })
            .collect();

        let (
            decentralized_parties_encryption_of_secret_key_share_commitment_round,
            decentralized_parties_decommitment_proof_verification_round,
        ): (HashMap<_, _>, HashMap<_, _>) = decentralized_parties_encryption_of_secret_key_share
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

        // Each $Bi$ sends a prove message $(prove, sid, pid_i, X_i, ct_i; x_i, \rho_i)$ to
        // $F_{LEncDL}^{agg-zk}$. Each $B_i$ receives the aggregated proof
        // $(proof, sid, X_B, ctkey)$ from $F_{LEncDL}^{agg-zk}$.
        // Protocol 4 step 2e and 2f.
        let (
            ..,
            encryption_of_decentralized_party_secret_share_time,
            (
                encryption_of_decentralized_party_secret_share_proof,
                encryption_of_decentralized_party_secret_share,
            ),
            // todo(scaly) why is this here? shouldn't it be tested in another test?
            // todo(scaly): where exactly the the secret key is created?
        ) = aggregates(decentralized_parties_encryption_of_secret_key_share_commitment_round);

        let encryption_of_decentralized_party_secret_share =
            *encryption_of_decentralized_party_secret_share
                .first()
                .unwrap();

        let secret_key_share_encryption_and_proof = SecretKeyShareEncryptionAndProof::new(
            encryption_of_decentralized_party_secret_share,
            encryption_of_decentralized_party_secret_share_proof,
        );

        let now = measurement.start();
        // Protocol 4 step 3
        let (
            centralized_party_public_key_share_decommitment_and_proof,
            centralized_party_dkg_output,
        ) = centralized_party_decommitment_round
            .decommit_proof_public_key_share(
                secret_key_share_encryption_and_proof.clone(),
                &mut OsRng,
            )
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let decentralized_party_public_key_share = secp256k1::GroupElement::new(
            centralized_party_dkg_output.decentralized_party_public_key_share,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let cp_secret_key_share = secp256k1::Scalar::new(
            centralized_party_dkg_output.secret_key_share,
            &protocol_public_parameters.scalar_group_public_parameters,
        )
        .unwrap();

        let cp_public_key_share = secp256k1::GroupElement::new(
            centralized_party_dkg_output.public_key_share,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let public_key = secp256k1::GroupElement::new(
            centralized_party_dkg_output.public_key,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        // Make sure $X = X_A + X_B$
        assert_eq!(
            decentralized_party_public_key_share + cp_public_key_share,
            public_key
        );

        let generator = cp_public_key_share.generator();
        assert_eq!(cp_secret_key_share * generator, cp_public_key_share);

        // Protocol 4 step 4 and 5.
        let decentralized_party_dkg_outputs: HashMap<_, _> =
            decentralized_parties_decommitment_proof_verification_round
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

        let decentralized_party_dkg_output = decentralized_party_dkg_outputs
            .values()
            .next()
            .unwrap()
            .clone();

        assert!(decentralized_party_dkg_outputs
            .clone()
            .into_iter()
            .all(|(_, output)| decentralized_party_dkg_output == output));

        assert!(decentralized_party_dkg_outputs
            .into_iter()
            .all(|(_, dkg_output)| {
                let encrypted_secret_key_share = tiresias::CiphertextSpaceGroupElement::new(
                    dkg_output.encrypted_secret_key_share,
                    protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters(),
                )
                .unwrap();

                // Create the Paillier decryption key.
                // Note that this key is used to decrypt plaintext encrypted with `N` and `g` from
                // the Paillier public key (transferred though the public parameters).
                let paillier_decryption_key = tiresias::DecryptionKey::new(
                    SECRET_KEY,
                    &protocol_public_parameters.encryption_scheme_public_parameters,
                )
                .unwrap();

                let decentralized_party_secret_key_share_decryption: LargeBiPrimeSizedNumber =
                    paillier_decryption_key
                        .decrypt(
                            &encrypted_secret_key_share,
                            &protocol_public_parameters.encryption_scheme_public_parameters,
                        )
                        .unwrap()
                        .into();

                let decentralized_party_secret_key_share: secp256k1::Scalar =
                    decentralized_party_secret_key_share_decryption.into();

                let decentralized_part_public_key_share = secp256k1::GroupElement::new(
                    dkg_output.public_key_share,
                    &protocol_public_parameters.group_public_parameters,
                )
                .unwrap();

                let centralized_party_public_key_share = secp256k1::GroupElement::new(
                    dkg_output.centralized_party_public_key_share,
                    &protocol_public_parameters.group_public_parameters,
                )
                .unwrap();

                (dkg_output.encrypted_secret_key_share
                    == centralized_party_dkg_output.encrypted_decentralized_party_secret_key_share)
                    && ((decentralized_party_secret_key_share * generator).value()
                        == dkg_output.public_key_share)
                    && dkg_output.centralized_party_public_key_share
                        == centralized_party_dkg_output.public_key_share
                    && ((centralized_party_public_key_share + decentralized_part_public_key_share).value()
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
