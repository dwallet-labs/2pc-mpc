// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod centralized_party;
pub mod decentralized_party;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::{array, marker::PhantomData};
    use std::collections::HashMap;

    use crypto_bigint::U256;
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

    use super::*;
    use crate::{
        homomorphic_encryption,
        homomorphic_encryption::{
            paillier::{
                tests::{N, SECRET_KEY},
                EncryptionKey as PaillierEncryptionKey,
            },
            AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
            GroupsPublicParametersAccessors,
        },
        commitment::pedersen,
        group::{
            paillier, paillier::CIPHERTEXT_SPACE_SCALAR_LIMBS, ristretto, secp256k1, self_product,
            CyclicGroupElement, GroupElement as _, Samplable,
        },
        proofs::{
            range::{bulletproofs, RangeProof},
            maurer::{
                aggregation::tests::{aggregates_internal, aggregates_internal_multiple},
                enhanced::{tests::RANGE_CLAIMS_PER_SCALAR, EnhancedLanguageStatementAccessors},
                language::encryption_of_discrete_log::StatementAccessors,
            },
        },
    };

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn generates_presignatures(#[case] batch_size: usize) {
        let number_of_parties = 4;
        let threshold = 2;

        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters = homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            homomorphic_encryption::paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let centralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let decentralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let decentralized_party_public_key_share =
            decentralized_party_secret_key_share * &generator;

        let plaintext = paillier::PlaintextSpaceGroupElement::new(
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
            centralized_party_secret_key_share,
            decentralized_party_public_key_share,
            encrypted_decentralized_party_secret_key_share,
        );
    }

    pub fn generates_presignatures_internal(
        number_of_parties: u16,
        threshold: u16,
        batch_size: usize,
        centralized_party_secret_key_share: secp256k1::Scalar,
        decentralized_party_public_key_share: secp256k1::GroupElement,
        encrypted_decentralized_party_secret_key_share: paillier::CiphertextSpaceGroupElement,
    ) -> (
        Vec<
            centralized_party::Presign<
                secp256k1::group_element::Value,
                secp256k1::Scalar,
                paillier::CiphertextSpaceValue,
            >,
        >,
        Vec<paillier::CiphertextSpaceGroupElement>,
        Vec<
            decentralized_party::Presign<
                secp256k1::group_element::Value,
                paillier::CiphertextSpaceValue,
            >,
        >,
    ) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            bulletproofs::PublicParameters::<{ RANGE_CLAIMS_PER_SCALAR }>::default();

        let paillier_public_parameters = homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            homomorphic_encryption::paillier::EncryptionKey::new(&paillier_public_parameters).unwrap();

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

        let centralized_party_public_key_share = centralized_party_secret_key_share * &generator;

        let public_key = centralized_party_public_key_share + decentralized_party_public_key_share;

        let centralized_party_commitment_round_party = centralized_party::commitment_round::Party::<
            { secp256k1::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            PaillierEncryptionKey,
            paillier::RandomnessSpaceGroupElement,
            self_product::GroupElement<2, paillier::RandomnessSpaceGroupElement>,
            bulletproofs::RangeProof,
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
            encrypted_decentralized_party_secret_key_share:
                encrypted_decentralized_party_secret_key_share.clone(),
        };

        let (
            commitments_and_proof_to_centralized_party_nonce_shares,
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
                        PaillierEncryptionKey,
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
                        unbounded_encdl_witness_public_parameters: unbounded_encdl_witness_public_parameters.clone(),
                        unbounded_encdh_witness_public_parameters: unbounded_encdh_witness_public_parameters.clone(),
                        range_proof_public_parameters: bulletproofs_public_parameters.clone(),
                        encrypted_secret_key_share: encrypted_decentralized_party_secret_key_share.clone(),
                    },
                )
            })
            .collect();

        let (parties, decentralized_party_encrypted_masked_nonce_shares_round_parties): (
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
                    decentralized_party_encrypted_masked_nonce_shares_round_party,
                ) = party
                    .sample_mask_and_nonce_shares_and_initialize_proof_aggregation(
                        commitments_and_proof_to_centralized_party_nonce_shares.clone(),
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
                        decentralized_party_encrypted_masked_nonce_shares_round_party,
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

        let encrypted_nonce_shares = encrypted_nonce_shares_and_public_shares
            .clone()
            .into_iter()
            .map(|statement| statement.encrypted_discrete_log().clone())
            .collect();

        let decentralized_party_encrypted_masked_nonce_shares_commitment_round_parties: HashMap<
            _,
            Vec<_>,
        > = decentralized_party_encrypted_masked_nonce_shares_round_parties
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

        let (_, encrypted_masked_nonce_shares): (Vec<_>, Vec<_>) = aggregates_internal_multiple(
            decentralized_party_encrypted_masked_nonce_shares_commitment_round_parties,
        )
        .into_iter()
        .unzip();

        let encrypted_masked_nonce_shares: Vec<_> = encrypted_masked_nonce_shares
            .into_iter()
            .flatten()
            .map(|encrypted_masked_nonce_share| {
                encrypted_masked_nonce_share.language_statement().clone()
            })
            .collect();

        let decentralized_party_presigns: Vec<_> =
            commitments_and_proof_to_centralized_party_nonce_shares
                .commitments
                .into_iter()
                .zip(
                    masks_and_encrypted_masked_key_share.into_iter().zip(
                        encrypted_nonce_shares_and_public_shares
                            .into_iter()
                            .zip(encrypted_masked_nonce_shares.into_iter()),
                    ),
                )
                .map(
                    |(
                        centralized_party_nonce_share_commitment,
                        (
                            mask_and_encrypted_masked_key_share,
                            (encrypted_nonce_share_and_public_share, encrypted_masked_nonce_share),
                        ),
                    )| {
                        decentralized_party::Presign::new::<
                            { secp256k1::SCALAR_LIMBS },
                            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                            secp256k1::GroupElement,
                            PaillierEncryptionKey,
                        >(
                            centralized_party_nonce_share_commitment,
                            mask_and_encrypted_masked_key_share,
                            encrypted_nonce_share_and_public_share,
                            encrypted_masked_nonce_share,
                        )
                    },
                )
                .collect();

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

        (
            centralized_party_presigns,
            encrypted_nonce_shares,
            decentralized_party_presigns,
        )
    }
}

// TODO: bench
