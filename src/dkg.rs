// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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
            AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
        },
        dkg::{centralized_party, decentralized_party::SecretKeyShareEncryptionAndProof},
        group::{ristretto, secp256k1, CyclicGroupElement},
        proofs::{
            range::{bulletproofs, RangeProof},
            schnorr::{
                aggregation::tests::aggregates_internal,
                enhanced::{tests::RANGE_CLAIMS_PER_SCALAR, EnhancedLanguageStatementAccessors},
            },
        },
    };

    #[test]
    fn generates_distributed_key() {
        let number_of_parties = 4;
        let threshold = 2;
    }

    pub fn generates_distributed_key_internal(
        number_of_parties: u16,
        threshold: u16,
    ) -> (
        centralized_party::Output<
            { secp256k1::SCALAR_LIMBS },
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >,
        decentralized_party::Output<
            { secp256k1::SCALAR_LIMBS },
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
        >,
    ) {
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
            { RANGE_CLAIMS_PER_SCALAR },
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
            paillier::RandomnessSpaceGroupElement,
            bulletproofs::RangeProof,
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

        let (
            commitment_to_centralized_party_secret_key_share,
            centralized_party_decommitment_round_party,
        ) = centralized_party_commitment_round_party
            .sample_commit_and_prove_secret_key_share(&mut OsRng)
            .unwrap();

        let decentralized_party_encryption_of_secret_key_share_parties: HashMap<_, _> = (1
            ..=number_of_parties)
            .map(|party_id| {
                let party_id: u16 = party_id.try_into().unwrap();
                (
                    party_id,
                    decentralized_party::encryption_of_secret_key_share_round::Party::<
                        { secp256k1::SCALAR_LIMBS },
                        { ristretto::SCALAR_LIMBS },
                        { RANGE_CLAIMS_PER_SCALAR },
                        { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        secp256k1::GroupElement,
                        paillier::EncryptionKey,
                        paillier::RandomnessSpaceGroupElement,
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
                    let (
                        encryption_of_secret_key_share_commitment_round_party,
                        decommitment_proof_verification_round_party,
                    ) = party
                        .sample_secret_key_share_and_initialize_proof_aggregation(
                            commitment_to_centralized_party_secret_key_share,
                            &mut OsRng,
                        )
                        .unwrap();
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
            encryption_of_decentralized_party_secret_share_proof,
            encryption_of_decentralized_party_secret_share,
        ) = aggregates_internal(
            decentralized_party_encryption_of_secret_key_share_commitment_round_parties,
        );

        let encryption_of_decentralized_party_secret_share =
            encryption_of_decentralized_party_secret_share
                .first()
                .unwrap()
                .clone();

        let secret_key_share_encryption_and_proof = SecretKeyShareEncryptionAndProof::new(
            encryption_of_decentralized_party_secret_share,
            encryption_of_decentralized_party_secret_share_proof,
        );

        let (
            centralized_party_public_key_share_decommitment_and_proof,
            centralized_party_dkg_output,
        ) = centralized_party_decommitment_round_party
            .decommit_proof_public_key_share(secret_key_share_encryption_and_proof, &mut OsRng)
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
            decentralized_party_decommitment_proof_verification_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    (
                        party_id,
                        party
                            .verify_decommitment_and_proof_of_centralized_party_public_key_share(
                                centralized_party_public_key_share_decommitment_and_proof.clone(),
                                encryption_of_decentralized_party_secret_share
                                    .language_statement()
                                    .clone(),
                            )
                            .unwrap(),
                    )
                })
                .collect();

        // TODO: check all are same.
        let decentralized_party_dkg_output =
            decentralized_party_dkg_outputs.get(&1).unwrap().clone();

        assert!(decentralized_party_dkg_outputs
            .into_iter()
            .all(|(_, dkg_output)| {
                let decentralized_party_secret_key_share_decryption: LargeBiPrimeSizedNumber =
                    paillier_decryption_key
                        .decrypt(&dkg_output.encrypted_secret_key_share)
                        .into();

                let decentralized_party_secret_key_share: secp256k1::Scalar =
                    decentralized_party_secret_key_share_decryption.into();

                (dkg_output.encrypted_secret_key_share
                    == centralized_party_dkg_output.encrypted_decentralized_party_secret_key_share)
                    && (decentralized_party_secret_key_share * &generator
                        == dkg_output.public_key_share)
                    && (dkg_output.centralized_party_public_key_share
                        + &dkg_output.public_key_share
                        == dkg_output.public_key)
            }));

        (centralized_party_dkg_output, decentralized_party_dkg_output)
    }
}

// TODO: bench
