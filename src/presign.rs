// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

pub mod centralized_party;
pub mod decentralized_party;

#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
pub(crate) mod tests {
    use core::marker::PhantomData;
    use std::{
        collections::{HashMap, HashSet},
        time::Duration,
    };

    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::U256;
    use enhanced_maurer::{
        encryption_of_discrete_log::StatementAccessors,
        language::EnhancedLanguageStatementAccessors,
    };
    use group::{ristretto, secp256k1, self_product, GroupElement as _, PartyID, Samplable};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };
    use proof::{
        aggregation::test_helpers::{
            aggregates, aggregates_multiple, commitment_round, decommitment_round,
        },
        range::bulletproofs,
    };
    use rand::prelude::IteratorRandom;
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
    #[case(2, 2, 1)]
    #[case(2, 4, 4)]
    #[case(6, 9, 2)]
    fn generates_presignatures(
        #[case] number_of_parties: PartyID,
        #[case] threshold: PartyID,
        #[case] batch_size: usize,
    ) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            tiresias::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let decentralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let plaintext = tiresias::PlaintextSpaceGroupElement::new(
            LargeBiPrimeSizedNumber::from(&U256::from(decentralized_party_secret_key_share)),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, encrypted_decentralized_party_secret_key_share) = paillier_encryption_key
            .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
            .unwrap();

        generates_presignatures_internal(
            number_of_parties,
            threshold,
            batch_size,
            encrypted_decentralized_party_secret_key_share,
        );
    }

    #[allow(dead_code)]
    pub fn generates_presignatures_internal(
        number_of_parties: u16,
        threshold: u16,
        batch_size: usize,
        encrypted_decentralized_party_secret_key_share: tiresias::CiphertextSpaceGroupElement,
    ) -> (
        Vec<
            centralized_party::Presign<
                secp256k1::group_element::Value,
                secp256k1::Scalar,
                tiresias::CiphertextSpaceValue,
            >,
        >,
        Vec<tiresias::CiphertextSpaceGroupElement>,
        Vec<
            decentralized_party::Presign<
                secp256k1::group_element::Value,
                tiresias::CiphertextSpaceValue,
            >,
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

        let unbounded_encdl_witness_public_parameters = paillier_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let unbounded_encdh_witness_public_parameters = self_product::PublicParameters::new(
            paillier_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let centralized_party_commitment_round_party = centralized_party::commitment_round::Party::<
            { secp256k1::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            bulletproofs::RangeProof,
            tiresias::RandomnessSpaceGroupElement,
            self_product::GroupElement<2, tiresias::RandomnessSpaceGroupElement>,
            PhantomData<()>,
        > {
            protocol_context: PhantomData::<()>,
            scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
            group_public_parameters: secp256k1_group_public_parameters.clone(),
            encryption_scheme_public_parameters: paillier_public_parameters.clone(),
            unbounded_encdl_witness_public_parameters: unbounded_encdl_witness_public_parameters
                .clone(),
            unbounded_encdh_witness_public_parameters: unbounded_encdh_witness_public_parameters
                .clone(),
            range_proof_public_parameters: bulletproofs_public_parameters.clone(),
            encrypted_decentralized_party_secret_key_share,
        };

        let now = measurement.start();
        let (
            centralized_party_nonce_shares_commitments_and_batched_proof,
            centralized_party_proof_verification_round_party,
        ) = centralized_party_commitment_round_party
            .sample_commit_and_prove_signature_nonce_share(batch_size, &mut OsRng)
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

        let decentralized_party_encrypted_masked_key_share_and_public_nonce_shares_parties: HashMap<_, _> = parties.clone().into_iter()
            .map(|party_id| {
                (
                    party_id,
                    decentralized_party::encrypted_masked_key_share_and_public_nonce_shares_round::Party::<
                        { secp256k1::SCALAR_LIMBS },
                        { ristretto::SCALAR_LIMBS },
                        { RANGE_CLAIMS_PER_SCALAR },
                        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        secp256k1::GroupElement,
                        tiresias::EncryptionKey,
                        bulletproofs::RangeProof,
                        tiresias::RandomnessSpaceGroupElement,
                        self_product::GroupElement<2, tiresias::RandomnessSpaceGroupElement>,
                        PhantomData<()>,
                    > {
                        party_id,
                        parties: parties.clone(),
                        protocol_context: PhantomData::<()>,
                        scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
                        group_public_parameters: secp256k1_group_public_parameters.clone(),
                        encryption_scheme_public_parameters: paillier_public_parameters.clone(),
                        unbounded_encdl_witness_public_parameters: unbounded_encdl_witness_public_parameters.clone(),
                        unbounded_encdh_witness_public_parameters: unbounded_encdh_witness_public_parameters.clone(),
                        range_proof_public_parameters: bulletproofs_public_parameters.clone(),
                        encrypted_secret_key_share: encrypted_decentralized_party_secret_key_share,
                    },
                )
            })
            .collect();

        let (aggregation_parties, decentralized_party_encrypted_masked_nonce_shares_round_parties): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = decentralized_party_encrypted_masked_key_share_and_public_nonce_shares_parties
            .into_iter()
            .map(|(party_id, party)| {
                let now = measurement.start();
                let (
                    (
                        decentralized_party_encrypted_masked_key_share_commitment_round_party,
                        decentralized_party_public_nonce_shares_commitment_round_party,
                    ),
                    decentralized_party_encrypted_masked_nonce_shares_round_party,
                ) = party
                    .sample_mask_and_nonce_shares_and_initialize_proof_aggregation(
                        centralized_party_nonce_shares_commitments_and_batched_proof.clone(),
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
                        (
                            decentralized_party_encrypted_masked_key_share_commitment_round_party,
                            decentralized_party_public_nonce_shares_commitment_round_party,
                        ),
                    ),
                    (
                        party_id,
                        decentralized_party_encrypted_masked_nonce_shares_round_party,
                    ),
                )
            })
            .unzip();

        let (
            decentralized_party_encrypted_masked_key_share_commitment_round_parties,
            decentralized_party_public_nonce_shares_commitment_round_parties,
        ) = aggregation_parties
            .into_iter()
            .map(
                |(
                    party_id,
                    (
                        decentralized_party_encrypted_masked_key_share_commitment_round_party,
                        decentralized_party_public_nonce_shares_commitment_round_party,
                    ),
                )| {
                    (
                        (
                            party_id,
                            decentralized_party_encrypted_masked_key_share_commitment_round_party,
                        ),
                        (
                            party_id,
                            decentralized_party_public_nonce_shares_commitment_round_party,
                        ),
                    )
                },
            )
            .unzip();

        let (
            ..,
            masks_and_encrypted_masked_key_share_time,
            (masks_and_encrypted_masked_key_share_proof, masks_and_encrypted_masked_key_share),
        ) = aggregates(decentralized_party_encrypted_masked_key_share_commitment_round_parties);

        let (
            ..,
            encrypted_nonce_shares_and_public_shares_time,
            (
                encrypted_nonce_shares_and_public_shares_proof,
                encrypted_nonce_shares_and_public_shares,
            ),
        ) = aggregates(decentralized_party_public_nonce_shares_commitment_round_parties);

        let output = decentralized_party::Output::new(
            masks_and_encrypted_masked_key_share.clone(),
            masks_and_encrypted_masked_key_share_proof,
            encrypted_nonce_shares_and_public_shares.clone(),
            encrypted_nonce_shares_and_public_shares_proof,
        )
        .unwrap();

        let now = measurement.start();
        let centralized_party_presigns = centralized_party_proof_verification_round_party
            .verify_presign_output(output, &mut OsRng)
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let masks_and_encrypted_masked_key_share: Vec<_> = masks_and_encrypted_masked_key_share
            .into_iter()
            .map(|mask_and_encrypted_masked_key_share| {
                *mask_and_encrypted_masked_key_share.language_statement()
            })
            .collect();

        let encrypted_nonce_shares_and_public_shares: Vec<_> =
            encrypted_nonce_shares_and_public_shares
                .into_iter()
                .map(|encrypted_nonce_share_and_public_share| {
                    *encrypted_nonce_share_and_public_share.language_statement()
                })
                .collect();

        let encrypted_nonce_shares = encrypted_nonce_shares_and_public_shares
            .clone()
            .into_iter()
            .map(|statement| *statement.encrypted_discrete_log())
            .collect();

        let decentralized_party_encrypted_masked_nonce_shares_commitment_round_parties: HashMap<
            _,
            Vec<_>,
        > = decentralized_party_encrypted_masked_nonce_shares_round_parties
            .into_iter()
            .map(|(party_id, party)| {
                let now = measurement.start();
                let res = party
                    .initialize_proof_aggregation(
                        masks_and_encrypted_masked_key_share.clone(),
                        encrypted_nonce_shares_and_public_shares.clone(),
                        &mut OsRng,
                    )
                    .unwrap();

                if party_id == evaluation_party_id {
                    decentralized_party_total_time =
                        measurement.add(&decentralized_party_total_time, &measurement.end(now));
                };

                (party_id, res)
            })
            .collect();

        let (.., encrypted_masked_nonce_shares_time, res) = aggregates_multiple(
            decentralized_party_encrypted_masked_nonce_shares_commitment_round_parties,
        );

        let (_, encrypted_masked_nonce_shares): (Vec<_>, Vec<_>) = res.into_iter().unzip();

        let encrypted_masked_nonce_shares: Vec<_> = encrypted_masked_nonce_shares
            .into_iter()
            .flatten()
            .map(|encrypted_masked_nonce_share| *encrypted_masked_nonce_share.language_statement())
            .collect();

        // Above we use `aggregates` which does not return the messages, so we have to do a
        // hot-patch just for the test. In a real use-case we'd run the
        // aggregation protocol and save the statements from the decommitments, then pass these here
        // instead.
        // TODO: test properly
        let individual_encrypted_nonce_shares_and_public_shares = parties
            .clone()
            .into_iter()
            .map(|party_id| (party_id, encrypted_nonce_shares_and_public_shares.clone()))
            .collect();

        let individual_encrypted_masked_nonce_shares = parties
            .clone()
            .into_iter()
            .map(|party_id| (party_id, encrypted_masked_nonce_shares.clone()))
            .collect();

        let decentralized_party_presigns = decentralized_party::Presign::new_batch::<
            { secp256k1::SCALAR_LIMBS },
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            PhantomData<()>,
        >(
            parties,
            centralized_party_nonce_shares_commitments_and_batched_proof,
            masks_and_encrypted_masked_key_share,
            individual_encrypted_nonce_shares_and_public_shares,
            encrypted_nonce_shares_and_public_shares,
            individual_encrypted_masked_nonce_shares,
            encrypted_masked_nonce_shares,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        assert!(centralized_party_presigns
            .clone()
            .into_iter()
            .zip(decentralized_party_presigns.clone().into_iter())
            .all(|(centralized_party_presign, decentralized_party_presign)| {
                centralized_party_presign.decentralized_party_nonce_public_share
                    == decentralized_party_presign.nonce_public_share
                    && centralized_party_presign.encrypted_mask
                        == decentralized_party_presign.encrypted_mask
                    && centralized_party_presign.encrypted_masked_key_share
                        == decentralized_party_presign.encrypted_masked_key_share
            }));

        decentralized_party_total_time = measurement.add(
            &decentralized_party_total_time,
            &encrypted_masked_nonce_shares_time,
        );
        decentralized_party_total_time = measurement.add(
            &decentralized_party_total_time,
            &encrypted_nonce_shares_and_public_shares_time,
        );
        decentralized_party_total_time = measurement.add(
            &decentralized_party_total_time,
            &masks_and_encrypted_masked_key_share_time,
        );

        println!("\nProtocol, Number of Parties, Threshold, Batch Size, Centralized Party Total Time (ms), Decentralized Party Total Time (ms)", );

        println!(
            "Presign, {number_of_parties}, {threshold}, {batch_size}, {:?}, {:?}",
            centralized_party_total_time.as_millis(),
            decentralized_party_total_time.as_millis()
        );

        (
            centralized_party_presigns,
            encrypted_nonce_shares,
            decentralized_party_presigns,
        )
    }
}
