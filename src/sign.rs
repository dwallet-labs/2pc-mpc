// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::Error;
use group::{AffineXCoordinate, GroupElement, Invert, PrimeGroupElement};
use std::ops::Neg;

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;

pub mod centralized_party;
pub mod decentralized_party;

/// The dimension of the Committed Affine Evaluation language used in the signing protocol.
pub const DIMENSION: usize = 2;

fn verify_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS>,
>(
    r: GroupElement::Scalar,
    s: GroupElement::Scalar,
    m: GroupElement::Scalar,
    public_key: GroupElement,
) -> crate::Result<()> {
    // Attend to malleability by not accepting non-normalized signatures.
    if s.neg().value() < s.value() {
        return Err(Error::SignatureVerification);
    };

    let generator = public_key.generator();
    let inverted_s: GroupElement::Scalar =
        Option::from(s.invert()).ok_or(Error::SignatureVerification)?;
    if (((m * inverted_s) * generator) + ((r * inverted_s) * public_key)).x() != r {
        return Err(Error::SignatureVerification);
    }

    Ok(())
}

#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
pub(crate) mod tests {
    use commitment::{pedersen, Pedersen};
    use core::marker::PhantomData;
    use std::ops::Neg;
    use std::{collections::HashMap, time::Duration};

    use super::*;
    use crate::{
        dkg::tests::generates_distributed_key_internal,
        presign::tests::generates_presignatures_internal, tests::RANGE_CLAIMS_PER_SCALAR,
    };
    use commitment::HomomorphicCommitmentScheme;
    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::{NonZero, Uint, U256, U64};
    use ecdsa::{
        elliptic_curve::{ops::Reduce, Scalar},
        hazmat::{bits2field, DigestPrimitive},
        signature::{digest::Digest, Verifier},
        Signature, VerifyingKey,
    };
    use group::{
        direct_product, ristretto, secp256k1, self_product, AffineXCoordinate, GroupElement as _,
        Invert, KnownOrderGroupElement, PartyID, Reduce as _, Samplable,
        StatisticalSecuritySizedNumber,
    };
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicDecryptionKeyShare,
        AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors,
    };
    use k256::{elliptic_curve::scalar::IsHigh, sha2::digest::FixedOutput};
    use proof::range::bulletproofs;
    use rand::prelude::IteratorRandom;
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::test_exports::BASE;
    use tiresias::{
        test_exports::{deal_trusted_shares, N, SECRET_KEY},
        AdjustedLagrangeCoefficientSizedNumber, DecryptionKeyShare,
    };

    pub(crate) const MASK_LIMBS: usize =
        secp256k1::SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

    // TODO: it's ok to take next power of two here right
    // TODO: no MASK_LIMBS. Instead, have some upper bound on the upper bounds
    pub(crate) const RANGE_CLAIMS_PER_MASK: usize =
        (Uint::<MASK_LIMBS>::BITS / bulletproofs::RANGE_CLAIM_BITS).next_power_of_two();

    pub(crate) const NUM_RANGE_CLAIMS: usize =
        DIMENSION * RANGE_CLAIMS_PER_SCALAR + RANGE_CLAIMS_PER_MASK;

    #[allow(clippy::too_many_arguments)]
    pub fn signs_internal(
        threshold: u16,
        number_of_parties: u16,
        centralized_party_secret_key_share: secp256k1::Scalar,
        centralized_party_public_key_share: secp256k1::GroupElement,
        decentralized_party_secret_key_share: secp256k1::Scalar,
        decentralized_party_public_key_share: secp256k1::GroupElement,
        centralized_party_nonce_share: secp256k1::Scalar,
        centralized_party_nonce_share_commitment: secp256k1::GroupElement,
        decentralized_party_nonce_share: secp256k1::Scalar,
        decentralized_party_nonce_public_share: secp256k1::GroupElement,
        nonce_share_commitment_randomness: secp256k1::Scalar,
        encrypted_mask: tiresias::CiphertextSpaceGroupElement,
        encrypted_masked_key_share: tiresias::CiphertextSpaceGroupElement,
        encrypted_masked_nonce_share: tiresias::CiphertextSpaceGroupElement,
    ) {
        let measurement = WallTime;
        let mut centralized_party_total_time = Duration::ZERO;
        let mut decentralized_party_decryption_share_time = Duration::ZERO;

        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let bulletproofs_public_parameters =
            bulletproofs::PublicParameters::<{ NUM_RANGE_CLAIMS }>::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

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

        assert_eq!(
            decentralized_party_secret_key_share * generator,
            decentralized_party_public_key_share
        );

        let secret_key = centralized_party_secret_key_share + decentralized_party_secret_key_share;

        let public_key = centralized_party_public_key_share + decentralized_party_public_key_share;

        let centralized_party_sign_round_party = centralized_party::Party::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { RANGE_CLAIMS_PER_MASK },
            { ristretto::SCALAR_LIMBS },
            { NUM_RANGE_CLAIMS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            bulletproofs::RangeProof,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
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

        let m = <Scalar<k256::Secp256k1> as Reduce<U256>>::reduce_bytes(&m);
        let m = U256::from(m).into();

        let now = measurement.start();
        let public_nonce_encrypted_partial_signature_and_proof = centralized_party_sign_round_party
            .evaluate_encrypted_partial_signature(m, &mut OsRng)
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let (decryption_key_share_public_parameters, decryption_key_shares) =
            deal_trusted_shares(threshold, number_of_parties, N, SECRET_KEY, BASE);
        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    DecryptionKeyShare::new(
                        party_id,
                        share,
                        &decryption_key_share_public_parameters,
                    )
                    .unwrap(),
                )
            })
            .collect();
        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .choose_multiple(&mut OsRng, usize::from(threshold))
            .into_iter()
            .collect();

        let decrypters: Vec<_> = decryption_key_shares.clone().into_keys().collect();

        let decentralized_party_sign_round_parties: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, decryption_key_share)| {
                (
                    party_id,
                    decentralized_party::Party::<
                        { secp256k1::SCALAR_LIMBS },
                        { ristretto::SCALAR_LIMBS },
                        { RANGE_CLAIMS_PER_SCALAR },
                        { RANGE_CLAIMS_PER_MASK },
                        { NUM_RANGE_CLAIMS },
                        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        secp256k1::GroupElement,
                        tiresias::EncryptionKey,
                        DecryptionKeyShare,
                        bulletproofs::RangeProof,
                        direct_product::GroupElement<
                            self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                            tiresias::RandomnessSpaceGroupElement,
                        >,
                        PhantomData<()>,
                    > {
                        decryption_key_share,
                        decryption_key_share_public_parameters:
                            decryption_key_share_public_parameters.clone(),
                        protocol_context: PhantomData::<()>,
                        scalar_group_public_parameters: secp256k1_scalar_public_parameters.clone(),
                        group_public_parameters: secp256k1_group_public_parameters.clone(),
                        encryption_scheme_public_parameters: paillier_public_parameters.clone(),
                        unbounded_dcom_eval_witness_public_parameters:
                            unbounded_dcom_eval_witness_public_parameters.clone(),
                        range_proof_public_parameters: bulletproofs_public_parameters.clone(),
                        nonce_public_share: decentralized_party_nonce_public_share,
                        encrypted_mask,
                        encrypted_masked_key_share,
                        encrypted_masked_nonce_share,
                        centralized_party_public_key_share,
                        centralized_party_nonce_share_commitment,
                    },
                )
            })
            .collect();

        let lagrange_coefficients: HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber> =
            decrypters
                .clone()
                .into_iter()
                .map(|j| {
                    (
                        j,
                        DecryptionKeyShare::compute_lagrange_coefficient(
                            j,
                            number_of_parties,
                            decrypters.clone(),
                            &decryption_key_share_public_parameters,
                        ),
                    )
                })
                .collect();

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

        let public_nonce = centralized_party_nonce_share.invert().unwrap()
            * decentralized_party_nonce_public_share; // $R = k_A^-1*k_B*G$

        assert_eq!(
            public_nonce,
            secp256k1::GroupElement::new(
                public_nonce_encrypted_partial_signature_and_proof.public_nonce,
                &secp256k1_group_public_parameters,
            )
            .unwrap()
        );

        let nonce_x_coordinate = public_nonce.x(); // $r$

        let now = measurement.start();
        let (returned_nonce_x_coordinate, signature_s) = decentralized_party::Party::<
            { secp256k1::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            { RANGE_CLAIMS_PER_SCALAR },
            { RANGE_CLAIMS_PER_MASK },
            { NUM_RANGE_CLAIMS },
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            DecryptionKeyShare,
            bulletproofs::RangeProof,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            PhantomData<()>,
        >::decrypt_signature(
            m,
            public_key,
            nonce_x_coordinate,
            lagrange_coefficients,
            &decryption_key_share_public_parameters,
            secp256k1_scalar_public_parameters,
            partial_signature_decryption_shares,
            masked_nonce_decryption_shares,
        )
        .unwrap();
        let decentralized_party_threshold_decryption_time = measurement.end(now);

        assert_eq!(nonce_x_coordinate, returned_nonce_x_coordinate);

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
            decentralized_party_nonce_share * generator,
            decentralized_party_nonce_public_share
        );

        let nonce =
            centralized_party_nonce_share * decentralized_party_nonce_share.invert().unwrap();

        // $ s = (k_A * k_B^-1) * (rx * + m) $
        let expected_signature_s = nonce * ((nonce_x_coordinate * secret_key) + m);

        let expected_signature_s =
            if U256::from(expected_signature_s.neg()) < U256::from(expected_signature_s.value()) {
                expected_signature_s.neg()
            } else {
                expected_signature_s
            };

        assert_eq!(expected_signature_s, signature_s);

        let signature_s: k256::Scalar = signature_s.into();

        let signature =
            Signature::from_scalars(k256::Scalar::from(nonce_x_coordinate), signature_s).unwrap();

        let verifying_key =
            VerifyingKey::<k256::Secp256k1>::from_affine(public_key.value().into()).unwrap();

        let res = <VerifyingKey<k256::Secp256k1> as Verifier<Signature<k256::Secp256k1>>>::verify(
            &verifying_key,
            message.as_bytes(),
            &signature,
        );

        assert!(res.is_ok(), "generated signatures should be valid");
    }

    #[rstest]
    #[case(2, 2)]
    #[case(2, 4)]
    #[case(6, 9)]
    fn signs(#[case] threshold: PartyID, #[case] number_of_parties: PartyID) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            tiresias::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let commitment_scheme_public_parameters = pedersen::PublicParameters::derive_default::<
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

        let centralized_party_public_key_share = centralized_party_secret_key_share * generator;

        let decentralized_party_secret_key_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let decentralized_party_public_key_share = decentralized_party_secret_key_share * generator;

        let nonce_share_commitment_randomness =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let centralized_party_nonce_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let centralized_party_nonce_share_commitment = commitment_scheme.commit(
            &[centralized_party_nonce_share].into(),
            &nonce_share_commitment_randomness,
        );

        let decentralized_party_nonce_share =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let decentralized_party_nonce_public_share = decentralized_party_nonce_share * generator;

        let mask =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let (_, encrypted_mask) = paillier_encryption_key
            .encrypt(
                &tiresias::PlaintextSpaceGroupElement::new(
                    Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(
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
                &tiresias::PlaintextSpaceGroupElement::new(
                    Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(
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
                &tiresias::PlaintextSpaceGroupElement::new(
                    Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(
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
            threshold,
            number_of_parties,
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

    #[rstest]
    #[case(2, 2, 1)]
    #[case(2, 4, 4)]
    #[case(6, 9, 1)]
    fn dkg_presign_signs(
        #[case] threshold: PartyID,
        #[case] number_of_parties: PartyID,
        #[case] batch_size: usize,
    ) {
        dkg_presign_signs_internal(threshold, number_of_parties, batch_size)
    }

    pub fn dkg_presign_signs_internal(
        threshold: PartyID,
        number_of_parties: PartyID,
        batch_size: usize,
    ) {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let (centralized_party_dkg_output, decentralized_party_dkg_output) =
            generates_distributed_key_internal(threshold, number_of_parties);

        let encrypted_secret_key_share = tiresias::CiphertextSpaceGroupElement::new(
            decentralized_party_dkg_output.encrypted_secret_key_share,
            paillier_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let (centralized_party_presign, encrypted_nonce, decentralized_party_presign) =
            generates_presignatures_internal(
                threshold,
                number_of_parties,
                batch_size,
                encrypted_secret_key_share,
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

        let encrypted_mask = tiresias::CiphertextSpaceGroupElement::new(
            centralized_party_presign.encrypted_mask,
            paillier_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let encrypted_masked_key_share = tiresias::CiphertextSpaceGroupElement::new(
            centralized_party_presign.encrypted_masked_key_share,
            paillier_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let encrypted_masked_nonce_share = tiresias::CiphertextSpaceGroupElement::new(
            decentralized_party_presign.encrypted_masked_nonce_share,
            paillier_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let paillier_decryption_key =
            tiresias::DecryptionKey::new(SECRET_KEY, &paillier_public_parameters).unwrap();

        let group_order =
            secp256k1::Scalar::order_from_public_parameters(&secp256k1_scalar_public_parameters);

        let group_order = Option::<_>::from(NonZero::new(group_order)).unwrap();

        let decentralized_party_secret_key_share = paillier_decryption_key
            .decrypt(&encrypted_secret_key_share, &paillier_public_parameters)
            .unwrap();

        let decentralized_party_secret_key_share = secp256k1::Scalar::new(
            decentralized_party_secret_key_share
                .value()
                .reduce(&group_order)
                .into(),
            &secp256k1_scalar_public_parameters,
        )
        .unwrap();

        let decentralized_party_nonce_share = paillier_decryption_key
            .decrypt(
                encrypted_nonce.first().unwrap(),
                &paillier_public_parameters,
            )
            .unwrap();

        let decentralized_party_nonce_share = secp256k1::Scalar::new(
            decentralized_party_nonce_share
                .value()
                .reduce(&group_order)
                .into(),
            &secp256k1_scalar_public_parameters,
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

        let decentralized_party_public_key_share = secp256k1::GroupElement::new(
            decentralized_party_dkg_output.public_key_share,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        signs_internal(
            threshold,
            number_of_parties,
            secret_key_share,
            public_key_share,
            decentralized_party_secret_key_share,
            decentralized_party_public_key_share,
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
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        // TODO: for loops
        super::tests::dkg_presign_signs_internal(8, 2, 1);
        super::tests::dkg_presign_signs_internal(16, 8, 1);
        super::tests::dkg_presign_signs_internal(32, 16, 1);
        super::tests::dkg_presign_signs_internal(32, 64, 1);
        super::tests::dkg_presign_signs_internal(64, 128, 1);
        super::tests::dkg_presign_signs_internal(256, 128, 1);
    }
}
