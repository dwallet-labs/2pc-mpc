// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

pub mod centralized_party;
pub mod decentralized_party;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::{array, marker::PhantomData};
    use std::collections::HashMap;

    use crypto_bigint::U256;
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::LargeBiPrimeSizedNumber;

    use super::*;
    use crate::{
        ahe,
        ahe::{
            paillier,
            paillier::tests::{N, SECRET_KEY},
            AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
            GroupsPublicParametersAccessors,
        },
        commitments::pedersen,
        group::{
            ristretto, secp256k1, self_product, CyclicGroupElement, GroupElement as _, Samplable,
        },
        proofs::{
            range::{bulletproofs, RangeProof},
            schnorr::{
                aggregation::tests::{aggregates_internal, aggregates_internal_multiple},
                enhanced::{tests::RANGE_CLAIMS_PER_SCALAR, EnhancedLanguageStatementAccessors},
            },
        },
    };

    // TODO: rstest with cases for batch size
    #[rstest]
    #[case(1)]
    #[case(2)]
    fn generates_presignatures(#[case] batch_size: usize) {
        let number_of_parties = 4;
        let threshold = 2;

        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();

        let paillier_public_parameters = ahe::paillier::PublicParameters::new(N).unwrap();

        let paillier_decryption_key =
            ahe::paillier::DecryptionKey::new(&paillier_public_parameters, SECRET_KEY).unwrap();

        let paillier_encryption_key: ahe::paillier::EncryptionKey = paillier_decryption_key.into();

        let unbounded_encdl_witness_public_parameters = paillier_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let unbounded_encdh_witness_public_parameters = self_product::PublicParameters::new(
            paillier_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let centralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let centralized_party_public_key_share = centralized_party_secret_key_share * &generator;

        let decentralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let decentralized_party_public_key_share =
            decentralized_party_secret_key_share * &generator;

        let public_key = centralized_party_public_key_share + decentralized_party_public_key_share;

        let plaintext = paillier::PlaintextSpaceGroupElement::new(
            LargeBiPrimeSizedNumber::from(&U256::from(decentralized_party_secret_key_share)),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, encrypted_decentralized_party_secret_key_share) = paillier_encryption_key
            .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
            .unwrap();

        let message_generators = array::from_fn(|_| {
            let generator =
                secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap()
                    * generator;

            generator.value()
        });

        let randomness_generator =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap()
                * generator;

        // TODO: this is not safe; we need a proper way to derive generators
        let commitment_scheme_public_parameters = pedersen::PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
            message_generators,
            randomness_generator.value(),
        );

        let centralized_party_commitment_round_party = centralized_party::commitment_round::Party::<
            { secp256k1::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
            paillier::RandomnessSpaceGroupElement,
            self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
            bulletproofs::RangeProof,
            PhantomData<()>,
        > {
            protocol_context: PhantomData::<()>,
            scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
            group_public_parameters: secp256k1_group_public_parameters.clone(),
            encryption_scheme_public_parameters: paillier_public_parameters.clone(),
            commitment_scheme_public_parameters: commitment_scheme_public_parameters.clone(),
            unbounded_encdl_witness_public_parameters: unbounded_encdl_witness_public_parameters
                .clone(),
            unbounded_encdh_witness_public_parameters: unbounded_encdh_witness_public_parameters
                .clone(),
            range_proof_public_parameters: bulletproofs_public_parameters.clone(),
            encrypted_decentralized_party_secret_key_share:
                encrypted_decentralized_party_secret_key_share.clone(),
        };

        let (
            commitment_and_proof_to_centralized_party_nonce_share,
            centralized_party_proof_verification_round_party,
        ) = centralized_party_commitment_round_party
            .sample_commit_and_prove_signature_nonce_share(batch_size, &mut OsRng)
            .unwrap();

        let decentralized_party_encrypted_masked_key_share_and_public_nonce_shares_parties: HashMap<_, _> = (1
            ..=number_of_parties)
            .map(|party_id| {
                let party_id: u16 = party_id.try_into().unwrap();
                (
                    party_id,
                    decentralized_party::encrypted_masked_key_share_and_public_nonce_shares_round::Party::<
                        { secp256k1::SCALAR_LIMBS },
                        { ristretto::SCALAR_LIMBS },
                        { RANGE_CLAIMS_PER_SCALAR },
                        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        secp256k1::GroupElement,
                        paillier::EncryptionKey,
                        paillier::RandomnessSpaceGroupElement,
                        self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
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
                        commitment_scheme_public_parameters: commitment_scheme_public_parameters.clone(),
                        unbounded_encdl_witness_public_parameters: unbounded_encdl_witness_public_parameters.clone(),
                        unbounded_encdh_witness_public_parameters: unbounded_encdh_witness_public_parameters.clone(),
                        range_proof_public_parameters: bulletproofs_public_parameters.clone(),
                        public_key_share: decentralized_party_public_key_share.clone(),
                        public_key: public_key.clone(),
                        encrypted_secret_key_share: encrypted_decentralized_party_secret_key_share.clone(),
                        centralized_party_public_key_share: centralized_party_public_key_share.clone(),
                    },
                )
            })
            .collect();

        let (parties, decentralized_party_encrypted_masked_nonces_round_parties): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = decentralized_party_encrypted_masked_key_share_and_public_nonce_shares_parties
            .into_iter()
            .map(|(party_id, party)| {
                let (
                    (
                        decentralized_party_encrypted_masked_key_share_commitment_round_party,
                        decentralized_party_public_nonce_shares_commitment_round_party,
                    ),
                    decentralized_party_encrypted_masked_nonces_round_party,
                ) = party
                    .sample_mask_and_nonce_shares_and_initialize_proof_aggregation(
                        commitment_and_proof_to_centralized_party_nonce_share.clone(),
                        &mut OsRng,
                    )
                    .unwrap();
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
                        decentralized_party_encrypted_masked_nonces_round_party,
                    ),
                )
            })
            .unzip();

        let (
            decentralized_party_encrypted_masked_key_share_commitment_round_parties,
            decentralized_party_public_nonce_shares_commitment_round_parties,
        ) = parties
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

        let (masks_and_encrypted_masked_key_share_proof, masks_and_encrypted_masked_key_share) =
            aggregates_internal(
                decentralized_party_encrypted_masked_key_share_commitment_round_parties,
            );

        let (
            encrypted_nonce_shares_and_public_shares_proof,
            encrypted_nonce_shares_and_public_shares,
        ) = aggregates_internal(decentralized_party_public_nonce_shares_commitment_round_parties);

        let output = decentralized_party::Output::new(
            masks_and_encrypted_masked_key_share.clone(),
            masks_and_encrypted_masked_key_share_proof,
            encrypted_nonce_shares_and_public_shares.clone(),
            encrypted_nonce_shares_and_public_shares_proof,
        );

        let centralized_party_presigns = centralized_party_proof_verification_round_party
            .verify_presign_output(output, &mut OsRng)
            .unwrap();

        let masks_and_encrypted_masked_key_share: Vec<_> = masks_and_encrypted_masked_key_share
            .into_iter()
            .map(|mask_and_encrypted_masked_key_share| {
                mask_and_encrypted_masked_key_share
                    .language_statement()
                    .clone()
            })
            .collect();

        let encrypted_nonce_shares_and_public_shares: Vec<_> =
            encrypted_nonce_shares_and_public_shares
                .into_iter()
                .map(|encrypted_nonce_share_and_public_share| {
                    encrypted_nonce_share_and_public_share
                        .language_statement()
                        .clone()
                })
                .collect();

        let decentralized_party_encrypted_masked_nonces_commitment_round_parties: HashMap<
            _,
            Vec<_>,
        > = decentralized_party_encrypted_masked_nonces_round_parties
            .into_iter()
            .map(|(party_id, party)| {
                (
                    party_id,
                    party
                        .initialize_proof_aggregation(
                            masks_and_encrypted_masked_key_share.clone(),
                            encrypted_nonce_shares_and_public_shares.clone(),
                            &mut OsRng,
                        )
                        .unwrap(),
                )
            })
            .collect();

        let (_, encrypted_masked_nonces): (Vec<_>, Vec<_>) = aggregates_internal_multiple(
            decentralized_party_encrypted_masked_nonces_commitment_round_parties,
        )
        .into_iter()
        .unzip();

        let encrypted_masked_nonces: Vec<_> = encrypted_masked_nonces
            .into_iter()
            .flatten()
            .map(|encrypted_masked_nonce| encrypted_masked_nonce.language_statement().clone())
            .collect();

        let decentralized_party_presigns: Vec<_> = masks_and_encrypted_masked_key_share
            .into_iter()
            .zip(
                encrypted_nonce_shares_and_public_shares
                    .into_iter()
                    .zip(encrypted_masked_nonces.into_iter()),
            )
            .map(
                |(
                    mask_and_encrypted_masked_key_share,
                    (encrypted_nonce_share_and_public_share, encrypted_masked_nonce),
                )| {
                    decentralized_party::Presign::new::<
                        { secp256k1::SCALAR_LIMBS },
                        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        secp256k1::GroupElement,
                        paillier::EncryptionKey,
                    >(
                        mask_and_encrypted_masked_key_share,
                        encrypted_nonce_share_and_public_share,
                        encrypted_masked_nonce,
                    )
                },
            )
            .collect();

        assert!(centralized_party_presigns
            .into_iter()
            .zip(decentralized_party_presigns.into_iter())
            .all(|(centralized_party_presign, decentralized_party_presign)| {
                centralized_party_presign.decentralized_party_nonce_public_share
                    == decentralized_party_presign.nonce_public_share
                    && centralized_party_presign.encrypted_mask
                        == decentralized_party_presign.encrypted_mask
                    && centralized_party_presign.encrypted_masked_key_share
                        == decentralized_party_presign.encrypted_masked_key_share
            }));
    }
}

// TODO: bench
