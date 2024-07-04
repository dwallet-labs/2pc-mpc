// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

pub mod centralized_party;
pub mod decentralized_party;

#[cfg(all(
    any(test, feature = "benchmarking"),
    feature = "secp256k1",
    feature = "paillier",
    feature = "bulletproofs",
))]
#[allow(unused_imports)]
pub(crate) mod tests {
    use core::marker::PhantomData;
    use std::{
        collections::{HashMap, HashSet},
        iter,
        time::Duration,
    };

    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::{U256, Uint};
    use enhanced_maurer::{
        encryption_of_discrete_log::StatementAccessors,
        language::EnhancedLanguageStatementAccessors,
    };
    use group::{GroupElement as _, PartyID, ristretto, Samplable, secp256k1, self_product};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };
    use proof::{
        aggregation::test_helpers::{
            aggregates, aggregates_multiple_with_decommitments,
            aggregates_with_decommitments,
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
        dkg::decentralized_party::SecretKeyShareEncryptionAndProof,
        secp256k1::bulletproofs::RANGE_CLAIMS_PER_SCALAR, Error, ProtocolPublicParameters,
    };

    #[rstest]
    #[case(2, 2, 1, false)]
    #[case(2, 2, 1, true)]
    #[case(2, 4, 4, false)]
    #[case(2, 4, 4, true)]
    #[case(6, 9, 2, false)]
    #[case(6, 9, 2, true)]
    fn generates_presignatures(
        #[case] threshold: PartyID,
        #[case] number_of_parties: PartyID,
        #[case] batch_size: usize,
        #[case] mismatch_encrypted_masks: bool,
    ) {
        let protocol_public_parameters = ProtocolPublicParameters::new(N);

        let paillier_encryption_key = tiresias::EncryptionKey::new(
            &protocol_public_parameters.encryption_scheme_public_parameters,
        )
        .unwrap();

        let decentralized_party_secret_key_share = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let plaintext = tiresias::PlaintextSpaceGroupElement::new(
            LargeBiPrimeSizedNumber::from(&U256::from(decentralized_party_secret_key_share)),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, encrypted_decentralized_party_secret_key_share) = paillier_encryption_key
            .encrypt(
                &plaintext,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        generates_presignatures_internal(
            threshold,
            number_of_parties,
            batch_size,
            encrypted_decentralized_party_secret_key_share,
            mismatch_encrypted_masks,
        );
    }

    #[allow(dead_code)]
    pub fn generates_presignatures_internal(
        threshold: u16,
        number_of_parties: u16,
        batch_size: usize,
        encrypted_decentralized_party_secret_key_share: tiresias::CiphertextSpaceGroupElement,
        mismatch_encrypted_masks: bool,
    ) -> Option<(
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
    )> {
        let measurement = WallTime;
        let mut centralized_party_total_time = Duration::ZERO;
        let mut decentralized_party_total_time = Duration::ZERO;

        let protocol_public_parameters = ProtocolPublicParameters::new(N);

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
            scalar_group_public_parameters: protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            group_public_parameters: protocol_public_parameters.group_public_parameters.clone(),
            encryption_scheme_public_parameters: protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            unbounded_encdl_witness_public_parameters: protocol_public_parameters
                .unbounded_encdl_witness_public_parameters
                .clone(),
            unbounded_encdh_witness_public_parameters: protocol_public_parameters
                .unbounded_encdh_witness_public_parameters
                .clone(),
            range_proof_public_parameters: protocol_public_parameters
                .range_proof_enc_dl_public_parameters
                .clone(),
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
                        threshold,
                        parties: parties.clone(),
                        protocol_context: PhantomData::<()>,
                        scalar_group_public_parameters: protocol_public_parameters.scalar_group_public_parameters.clone(),
                        group_public_parameters: protocol_public_parameters.group_public_parameters.clone(),
                        encryption_scheme_public_parameters: protocol_public_parameters.encryption_scheme_public_parameters.clone(),
                        unbounded_encdl_witness_public_parameters: protocol_public_parameters.unbounded_encdl_witness_public_parameters.clone(),
                        unbounded_encdh_witness_public_parameters: protocol_public_parameters.unbounded_encdh_witness_public_parameters.clone(),
                        range_proof_public_parameters: protocol_public_parameters.range_proof_enc_dl_public_parameters.clone(),
                        encrypted_secret_key_share: encrypted_decentralized_party_secret_key_share,
                    },
                )
            })
            .collect();

        let (
            aggregation_parties,
            mut decentralized_party_encrypted_masked_nonce_shares_round_parties,
        ): (HashMap<_, _>, HashMap<_, _>) =
            decentralized_party_encrypted_masked_key_share_and_public_nonce_shares_parties
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
            encrypted_nonce_shares_and_public_shares_decommitments,
            ..,
            encrypted_nonce_shares_and_public_shares_time,
            (
                encrypted_nonce_shares_and_public_shares_proof,
                encrypted_nonce_shares_and_public_shares,
            ),
        ) = aggregates_with_decommitments(
            decentralized_party_public_nonce_shares_commitment_round_parties,
        );

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

        let number_of_malicious_parties = if parties.len() == 2 { 1 } else { 2 };
        let mut mismatching_encrypted_masks_parties = parties
            .clone()
            .into_iter()
            .choose_multiple(&mut OsRng, number_of_malicious_parties);
        mismatching_encrypted_masks_parties.sort();

        if mismatch_encrypted_masks {
            // Replace the witnesses so that the two aggregation protocols would not correspond on
            // the same statements.
            mismatching_encrypted_masks_parties
                .iter()
                .for_each(|&party_id| {
                    decentralized_party_encrypted_masked_nonce_shares_round_parties
                        .get_mut(&party_id)
                        .unwrap()
                        .shares_of_signature_nonce_shares_witnesses = iter::repeat(
                        tiresias::PlaintextSpaceGroupElement::new(
                            Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::ZERO,
                            protocol_public_parameters
                                .encryption_scheme_public_parameters
                                .plaintext_space_public_parameters(),
                        )
                        .unwrap(),
                    )
                    .take(batch_size)
                    .collect();
                });
        }

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

        let (
            encrypted_masked_nonce_shares_decommitments,
            ..,
            encrypted_masked_nonce_shares_time,
            res,
        ) = aggregates_multiple_with_decommitments(
            decentralized_party_encrypted_masked_nonce_shares_commitment_round_parties,
        );

        let (_, encrypted_masked_nonce_shares): (Vec<_>, Vec<_>) = res.into_iter().unzip();

        let encrypted_masked_nonce_shares: Vec<_> = encrypted_masked_nonce_shares
            .into_iter()
            .flatten()
            .map(|encrypted_masked_nonce_share| *encrypted_masked_nonce_share.language_statement())
            .collect();

        let individual_encrypted_nonce_shares_and_public_shares =
            encrypted_nonce_shares_and_public_shares_decommitments
                .into_iter()
                .map(|(party_id, decommitments)| {
                    (
                        party_id,
                        decommitments
                            .into_iter()
                            .flat_map(|(maurer_decommitment, _)| {
                                maurer_decommitment.statements.into_iter().map(|statement| {
                                    let (_, language_statement) = statement.into();

                                    language_statement
                                })
                            })
                            .collect(),
                    )
                })
                .collect();

        let individual_encrypted_masked_nonce_shares = encrypted_masked_nonce_shares_decommitments
            .into_iter()
            .map(|(party_id, decommitments)| {
                (
                    party_id,
                    decommitments
                        .into_iter()
                        .flat_map(|(maurer_decommitment, _)| {
                            maurer_decommitment.statements.into_iter().map(|statement| {
                                let (_, language_statement) = statement.into();

                                language_statement
                            })
                        })
                        .collect(),
                )
            })
            .collect();

        let res = decentralized_party::Presign::new_batch::<
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
            &protocol_public_parameters.group_public_parameters,
        );

        if mismatch_encrypted_masks {
            assert!(
                matches!(
                    res.err().unwrap(),
                    Error::MismatchingEncrypedMasks(malicious_parties) if malicious_parties == mismatching_encrypted_masks_parties
                ),
                "Parties who maliciously attempted to use different signature nonce shares in the two presign aggregation rounds must be identified"
            );

            return None;
        }

        let decentralized_party_presigns = res.unwrap();

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

        Some((
            centralized_party_presigns,
            encrypted_nonce_shares,
            decentralized_party_presigns,
        ))
    }
}
