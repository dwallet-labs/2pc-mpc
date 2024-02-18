// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;

pub mod centralized_party;
pub mod decentralized_party;

/// The dimension of the Committed Affine Evaluation language used in the signing protocol.
pub const DIMENSION: usize = 2;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use core::{array, iter, marker::PhantomData};
    use std::{collections::HashMap, time::Duration};

    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::{CheckedMul, NonZero, RandomMod, Uint, Wrapping, U256};
    use ecdsa::{
        elliptic_curve::{ops::Reduce, Scalar, ScalarPrimitive},
        hazmat::{bits2field, DigestPrimitive},
        signature::{digest::Digest, Verifier},
        Signature, VerifyingKey,
    };
    use k256::{elliptic_curve::scalar::IsHigh, sha2::digest::FixedOutput};
    use rand_core::OsRng;
    use tiresias::{
        deal_trusted_decryption_key_shares, secret_sharing::shamir::Polynomial,
        AdjustedLagrangeCoefficientSizedNumber, DecryptionKeyShare, LargeBiPrimeSizedNumber,
        PaillierModulusSizedNumber, SecretKeyShareSizedNumber,
    };

    use super::*;
    use crate::{
        commitment::{pedersen, HomomorphicCommitmentScheme, Pedersen},
        dkg::tests::generates_distributed_key_internal,
        group::{
            direct_product, ristretto, secp256k1, self_product, AffineXCoordinate,
            CyclicGroupElement, GroupElement as _, Invert, KnownOrderGroupElement, Samplable,
        },
        homomorphic_encryption,
        homomorphic_encryption::{
            paillier,
            paillier::{
                tests::{N, SECRET_KEY},
                PrecomputedValues,
            },
            AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
            GroupsPublicParametersAccessors,
        },
        presign::tests::generates_presignatures_internal,
        proofs::{
            maurer::{
                aggregation::tests::aggregates_internal,
                committed_linear_evaluation::tests::{NUM_RANGE_CLAIMS, RANGE_CLAIMS_PER_MASK},
                enhanced::{tests::RANGE_CLAIMS_PER_SCALAR, EnhancedLanguageStatementAccessors},
            },
            range::{bulletproofs, RangeProof},
        },
        sign::tests::paillier::tests::BASE,
        traits::Reduce as _,
        PartyID, StatisticalSecuritySizedNumber,
    };

    pub fn signs_internal(
        number_of_parties: u16,
        threshold: u16,
        centralized_party_secret_key_share: secp256k1::Scalar,
        centralized_party_public_key_share: secp256k1::GroupElement,
        decentralized_party_secret_key_share: secp256k1::Scalar,
        decentralized_party_public_key_share: secp256k1::GroupElement,
        centralized_party_nonce_share: secp256k1::Scalar,
        centralized_party_nonce_share_commitment: secp256k1::GroupElement,
        decentralized_party_nonce_share: secp256k1::Scalar,
        decentralized_party_nonce_public_share: secp256k1::GroupElement,
        nonce_share_commitment_randomness: secp256k1::Scalar,
        encrypted_mask: paillier::CiphertextSpaceGroupElement,
        encrypted_masked_key_share: paillier::CiphertextSpaceGroupElement,
        encrypted_masked_nonce_share: paillier::CiphertextSpaceGroupElement,
    ) {
        let measurement = WallTime;
        let mut centralized_party_total_time = Duration::ZERO;
        let mut decentralized_party_decryption_share_time = Duration::ZERO;
        let mut decentralized_party_threshold_decryption_time = Duration::ZERO;

        let (
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            generator,
            bulletproofs_public_parameters,
            paillier_public_parameters,
            paillier_encryption_key,
            unbounded_dcom_eval_witness_public_parameters,
        ) = setup();

        assert_eq!(
            decentralized_party_secret_key_share * &generator,
            decentralized_party_public_key_share
        );

        let secret_key = centralized_party_secret_key_share + decentralized_party_secret_key_share;

        let public_key = centralized_party_public_key_share + decentralized_party_public_key_share;

        let centralized_party_sign_round_party = centralized_party::Party::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { RANGE_CLAIMS_PER_MASK },
            { ristretto::SCALAR_LIMBS },
            { NUM_RANGE_CLAIMS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                paillier::RandomnessSpaceGroupElement,
            >,
            bulletproofs::RangeProof,
            PhantomData<()>,
        > {
            protocol_context: PhantomData::<()>,
            scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
            group_public_parameters: secp256k1_group_public_parameters.clone(),
            encryption_scheme_public_parameters: paillier_public_parameters.clone(),
            unbounded_dcom_eval_witness_public_parameters:
                unbounded_dcom_eval_witness_public_parameters.clone(),
            range_proof_public_parameters: bulletproofs_public_parameters.clone(),
            secret_key_share: centralized_party_secret_key_share,
            public_key_share: centralized_party_public_key_share,
            nonce_share_commitment_randomness,
            nonce_share: centralized_party_nonce_share,
            decentralized_party_nonce_public_share,
            encrypted_mask,
            encrypted_masked_key_share,
        };

        let message = "singing!";

        // TODO: this sha256, should we use sha2?
        let m = bits2field::<k256::Secp256k1>(
            &<k256::Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(message.as_bytes())
                .finalize_fixed(),
        )
        .unwrap();

        let m = secp256k1::Scalar(<Scalar<k256::Secp256k1> as Reduce<U256>>::reduce_bytes(&m));

        let now = measurement.start();
        let public_nonce_encrypted_partial_signature_and_proof = centralized_party_sign_round_party
            .evaluate_encrypted_partial_signature(m, &mut OsRng)
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let (
            encryption_key,
            decryption_key_shares,
            precomputed_values,
            base,
            public_verification_keys,
            absolute_adjusted_lagrange_coefficients,
        ) = deal_trusted_decryption_key_shares(threshold, number_of_parties);

        let decentralized_party_sign_round_parties =
            decryption_key_shares
                .into_iter()
                .map(|(party_id, decryption_key_share)| {
                    (
                        party_id,
                        decentralized_party::Party::<
                            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                            { secp256k1::SCALAR_LIMBS },
                            { RANGE_CLAIMS_PER_SCALAR },
                            { RANGE_CLAIMS_PER_MASK },
                            { ristretto::SCALAR_LIMBS },
                            { NUM_RANGE_CLAIMS },
                            secp256k1::GroupElement,
                            paillier::EncryptionKey,
                            paillier::DecryptionKeyShare,
                            direct_product::GroupElement<
                                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                                paillier::RandomnessSpaceGroupElement,
                            >,
                            bulletproofs::RangeProof,
                            PhantomData<()>,
                        > {
                            decryption_key_share: paillier::DecryptionKeyShare(
                                decryption_key_share,
                            ),
                            protocol_context: PhantomData::<()>,
                            scalar_group_public_parameters: secp256k1_scalar_public_parameters
                                .clone(),
                            group_public_parameters: secp256k1_group_public_parameters.clone(),
                            encryption_scheme_public_parameters: paillier_public_parameters.clone(),
                            unbounded_dcom_eval_witness_public_parameters:
                                unbounded_dcom_eval_witness_public_parameters.clone(),
                            range_proof_public_parameters: bulletproofs_public_parameters.clone(),
                            public_key_share: decentralized_party_public_key_share,
                            nonce_public_share: decentralized_party_nonce_public_share,
                            encrypted_mask,
                            encrypted_masked_key_share,
                            encrypted_masked_nonce_share,
                            centralized_party_public_key_share,
                            centralized_party_nonce_share_commitment,
                        },
                    )
                });

        let (partial_signature_decryption_shares, masked_nonce_decryption_shares): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = decentralized_party_sign_round_parties
            .into_iter()
            .map(|(party_id, party)| {
                let now = measurement.start();
                let (partial_signature_decryption_share, masked_nonce_decryption_share) = party
                    .partially_decrypt_encrypted_signature_parts(
                        m,
                        public_nonce_encrypted_partial_signature_and_proof.clone(),
                        &mut OsRng,
                    )
                    .unwrap();
                if party_id == 1 {
                    decentralized_party_decryption_share_time = measurement.end(now);
                };

                (
                    (party_id, partial_signature_decryption_share),
                    (party_id, masked_nonce_decryption_share),
                )
            })
            .unzip();

        let precomputed_values = PrecomputedValues {
            threshold,
            number_of_parties,
            precomputed_values,
            base,
            public_verification_keys,
            absolute_adjusted_lagrange_coefficients,
        };

        let now = measurement.start();
        let signature_s = decentralized_party::Party::<
            { paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { RANGE_CLAIMS_PER_MASK },
            { ristretto::SCALAR_LIMBS },
            { NUM_RANGE_CLAIMS },
            secp256k1::GroupElement,
            paillier::EncryptionKey,
            paillier::DecryptionKeyShare,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                paillier::RandomnessSpaceGroupElement,
            >,
            bulletproofs::RangeProof,
            PhantomData<()>,
        >::decrypt_signature(
            paillier_encryption_key,
            precomputed_values,
            secp256k1_scalar_public_parameters,
            partial_signature_decryption_shares,
            masked_nonce_decryption_shares,
        )
        .unwrap();
        decentralized_party_threshold_decryption_time = measurement.end(now);

        println!(
            "\nProtocol, Number of Parties, Threshold, Batch Size, Centralized Party Total Time (ms), Decentralized Party Decryption Share Time (ms), Decentralized Party Threshold Decryption Time (ms)",
        );

        // TODO: batch
        println!(
            "Sign, {number_of_parties}, {threshold}, 1, {:?}, {:?}, {:?}",
            centralized_party_total_time.as_millis(),
            decentralized_party_decryption_share_time.as_millis(),
            decentralized_party_threshold_decryption_time.as_millis()
        );

        assert_eq!(
            decentralized_party_nonce_share * &generator,
            decentralized_party_nonce_public_share
        );

        let public_nonce = centralized_party_nonce_share.invert().unwrap()
            * &decentralized_party_nonce_public_share; // $R = k_A^-1*k_B*G$

        assert_eq!(
            public_nonce,
            secp256k1::GroupElement::new(
                public_nonce_encrypted_partial_signature_and_proof.public_nonce,
                &secp256k1_group_public_parameters,
            )
            .unwrap()
        );

        let nonce_x_coordinate = public_nonce.x(); // $r$

        let nonce =
            centralized_party_nonce_share * decentralized_party_nonce_share.invert().unwrap();

        assert_eq!(
            nonce * ((nonce_x_coordinate * secret_key) + m), /* $ s = (k_A * k_B^-1) * (rx
                                                              * + m) $ */
            signature_s
        );

        let signature = Signature::from_scalars(nonce_x_coordinate.0, signature_s.0).unwrap();

        // Attend to maliablity. TODO: is this what Bitcoin does? all blockchains? should we even?
        let signature = if signature_s.0.is_high().into() {
            signature.normalize_s().unwrap()
        } else {
            signature
        };

        let verifying_key =
            VerifyingKey::<k256::Secp256k1>::from_affine(public_key.value().into()).unwrap();

        let res = <VerifyingKey<k256::Secp256k1> as Verifier<Signature<k256::Secp256k1>>>::verify(
            &verifying_key,
            message.as_bytes(),
            &signature,
        );

        assert!(res.is_ok(), "generated signatures should be valid");
    }

    #[test]
    fn signs() {
        let number_of_parties = 4;
        let threshold = 3;

        let (
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            generator,
            bulletproofs_public_parameters,
            paillier_public_parameters,
            paillier_encryption_key,
            unbounded_dcom_eval_witness_public_parameters,
        ) = setup();

        let commitment_scheme_public_parameters = pedersen::PublicParameters::default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        let commitment_scheme = Pedersen::<
            1,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >::new(&commitment_scheme_public_parameters)
        .unwrap();

        let centralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let centralized_party_public_key_share = centralized_party_secret_key_share * &generator;

        let decentralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let decentralized_party_public_key_share =
            decentralized_party_secret_key_share * &generator;

        let nonce_share_commitment_randomness =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let centralized_party_nonce_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let centralized_party_nonce_share_commitment = commitment_scheme.commit(
            &[centralized_party_nonce_share].into(),
            &nonce_share_commitment_randomness,
        );

        let centralized_party_nonce_public_share =
            centralized_party_nonce_share.invert().unwrap() * &generator;

        let decentralized_party_nonce_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let decentralized_party_nonce_public_share = decentralized_party_nonce_share * &generator;

        let mask =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let (_, encrypted_mask) = paillier_encryption_key
            .encrypt(
                &paillier::PlaintextSpaceGroupElement::new(
                    Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(
                        mask.value(),
                    )),
                    paillier_public_parameters.plaintext_space_public_parameters(),
                )
                .unwrap(),
                &paillier_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        let masked_key_share = mask * decentralized_party_secret_key_share;

        let (_, encrypted_masked_key_share) = paillier_encryption_key
            .encrypt(
                &paillier::PlaintextSpaceGroupElement::new(
                    Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(
                        masked_key_share.value(),
                    )),
                    paillier_public_parameters.plaintext_space_public_parameters(),
                )
                .unwrap(),
                &paillier_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        let masked_nonce_share = mask * decentralized_party_nonce_share;

        let (_, encrypted_masked_nonce_share) = paillier_encryption_key
            .encrypt(
                &paillier::PlaintextSpaceGroupElement::new(
                    Uint::<{ paillier::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(
                        masked_nonce_share.value(),
                    )),
                    paillier_public_parameters.plaintext_space_public_parameters(),
                )
                .unwrap(),
                &paillier_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        signs_internal(
            number_of_parties,
            threshold,
            centralized_party_secret_key_share,
            centralized_party_public_key_share,
            decentralized_party_secret_key_share,
            decentralized_party_public_key_share,
            centralized_party_nonce_share,
            centralized_party_nonce_share_commitment,
            decentralized_party_nonce_share,
            decentralized_party_nonce_public_share,
            nonce_share_commitment_randomness,
            encrypted_mask,
            encrypted_masked_key_share,
            encrypted_masked_nonce_share,
        );
    }

    #[test]
    fn dkg_presign_signs() {
        dkg_presign_signs_internal(4, 2)
    }

    pub fn dkg_presign_signs_internal(number_of_parties: PartyID, threshold: PartyID) {
        let (
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            generator,
            bulletproofs_public_parameters,
            paillier_public_parameters,
            paillier_encryption_key,
            unbounded_dcom_eval_witness_public_parameters,
        ) = setup();

        let (centralized_party_dkg_output, decentralized_party_dkg_output) =
            generates_distributed_key_internal(number_of_parties, threshold);

        let (centralized_party_presign, encrypted_nonce, decentralized_party_presign) =
            generates_presignatures_internal(
                number_of_parties,
                threshold,
                1,
                centralized_party_dkg_output.secret_key_share,
                decentralized_party_dkg_output.public_key_share,
                decentralized_party_dkg_output.encrypted_secret_key_share,
            );

        let centralized_party_presign = centralized_party_presign.first().unwrap().clone();
        let decentralized_party_presign = decentralized_party_presign.first().unwrap().clone();

        let centralized_party_nonce_share_commitment = secp256k1::GroupElement::new(
            decentralized_party_presign.centralized_party_nonce_share_commitment,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let decentralized_party_nonce_public_share = secp256k1::GroupElement::new(
            decentralized_party_presign.nonce_public_share,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let encrypted_mask = paillier::CiphertextSpaceGroupElement::new(
            centralized_party_presign.encrypted_mask,
            paillier_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let encrypted_masked_key_share = paillier::CiphertextSpaceGroupElement::new(
            centralized_party_presign.encrypted_masked_key_share,
            paillier_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let encrypted_masked_nonce_share = paillier::CiphertextSpaceGroupElement::new(
            decentralized_party_presign.encrypted_masked_nonce_share,
            paillier_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let paillier_decryption_key = homomorphic_encryption::paillier::DecryptionKey::new(
            &paillier_public_parameters,
            SECRET_KEY,
        )
        .unwrap();

        let group_order =
            secp256k1::Scalar::order_from_public_parameters(&secp256k1_scalar_public_parameters);

        let group_order = Option::<_>::from(NonZero::new(group_order)).unwrap();

        let decentralized_party_secret_key_share = paillier_decryption_key
            .decrypt(&decentralized_party_dkg_output.encrypted_secret_key_share);

        let decentralized_party_secret_key_share = secp256k1::Scalar::new(
            decentralized_party_secret_key_share
                .value()
                .reduce(&group_order)
                .into(),
            &secp256k1_scalar_public_parameters,
        )
        .unwrap();

        let decentralized_party_nonce_share =
            paillier_decryption_key.decrypt(encrypted_nonce.first().unwrap());

        let decentralized_party_nonce_share = secp256k1::Scalar::new(
            decentralized_party_nonce_share
                .value()
                .reduce(&group_order)
                .into(),
            &secp256k1_scalar_public_parameters,
        )
        .unwrap();

        signs_internal(
            number_of_parties,
            threshold,
            centralized_party_dkg_output.secret_key_share,
            centralized_party_dkg_output.public_key_share,
            decentralized_party_secret_key_share,
            decentralized_party_dkg_output.public_key_share,
            centralized_party_presign.nonce_share,
            centralized_party_nonce_share_commitment,
            decentralized_party_nonce_share,
            decentralized_party_nonce_public_share,
            centralized_party_presign.commitment_randomness,
            encrypted_mask,
            encrypted_masked_key_share,
            encrypted_masked_nonce_share,
        );
    }

    fn setup() -> (
        secp256k1::scalar::PublicParameters,
        secp256k1::group_element::PublicParameters,
        secp256k1::GroupElement,
        bulletproofs::PublicParameters<{ NUM_RANGE_CLAIMS }>,
        paillier::PublicParameters,
        paillier::EncryptionKey,
        direct_product::PublicParameters<
            self_product::PublicParameters<2, secp256k1::scalar::PublicParameters>,
            paillier::RandomnessSpacePublicParameters,
        >,
    ) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            bulletproofs::PublicParameters::<{ NUM_RANGE_CLAIMS }>::default();

        let paillier_public_parameters =
            homomorphic_encryption::paillier::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            homomorphic_encryption::paillier::EncryptionKey::new(&paillier_public_parameters)
                .unwrap();

        let unbounded_dcom_eval_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(secp256k1_scalar_public_parameters.clone()),
            paillier_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        (
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            generator,
            bulletproofs_public_parameters,
            paillier_public_parameters,
            paillier_encryption_key,
            unbounded_dcom_eval_witness_public_parameters,
        )
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        // TODO: for loops
        super::tests::dkg_presign_signs_internal(8, 2);
        super::tests::dkg_presign_signs_internal(16, 8);
        super::tests::dkg_presign_signs_internal(32, 16);
        super::tests::dkg_presign_signs_internal(32, 64);
        super::tests::dkg_presign_signs_internal(64, 128);
        super::tests::dkg_presign_signs_internal(256, 128);
    }
}
