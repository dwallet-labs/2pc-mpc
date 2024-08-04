// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::ops::Neg;

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
use group::{AffineXCoordinate, GroupElement, Invert, PrimeGroupElement};

use crate::Error;

pub mod centralized_party;
pub mod decentralized_party;

/// The dimension of the Committed Affine Evaluation language used in the signing protocol.
pub const DIMENSION: usize = 2;

pub fn verify_signature<
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

#[cfg(all(
    any(test, feature = "benchmarking"),
    feature = "secp256k1",
    feature = "paillier",
    feature = "bulletproofs",
))]
#[allow(unused_imports)]
pub(crate) mod tests {
    use core::marker::PhantomData;
    use std::{collections::HashMap, iter, ops::Neg, time::Duration};

    use commitment::{pedersen, HomomorphicCommitmentScheme, Pedersen};
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
    use tiresias::{
        test_exports::{deal_trusted_shares, BASE, N, SECRET_KEY},
        AdjustedLagrangeCoefficientSizedNumber, DecryptionKeyShare, LargeBiPrimeSizedNumber,
        PaillierModulusSizedNumber,
    };

    use super::*;
    use crate::{
        dkg::tests::generates_distributed_key_internal,
        presign::tests::generates_presignatures_internal,
        secp256k1::{
            bulletproofs::{NUM_RANGE_CLAIMS, RANGE_CLAIMS_PER_MASK, RANGE_CLAIMS_PER_SCALAR},
            paillier::bulletproofs::ProtocolPublicParameters,
        },
        sign::decentralized_party::{
            identifiable_abort::{
                signature_partial_decryption_proof_round,
                signature_partial_decryption_verification_round,
            },
            signature_partial_decryption_round,
        },
    };

    fn setup_decryption_key_shares(
        threshold: u16,
        number_of_parties: u16,
    ) -> (
        tiresias::decryption_key_share::PublicParameters,
        HashMap<PartyID, DecryptionKeyShare>,
        HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber>,
    ) {
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

        (
            decryption_key_share_public_parameters,
            decryption_key_shares,
            lagrange_coefficients,
        )
    }

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
        malicious_decrypter: bool,
        designated_sending_wrong_signature: bool,
    ) {
        let measurement = WallTime;
        let mut centralized_party_total_time = Duration::ZERO;
        let mut decentralized_party_decryption_share_time = Duration::ZERO;

        let protocol_public_parameters = ProtocolPublicParameters::new(N);

        let generator = secp256k1::GroupElement::new(
            protocol_public_parameters.group_public_parameters.generator,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        assert_eq!(
            decentralized_party_secret_key_share * generator,
            decentralized_party_public_key_share
        );

        let secret_key = centralized_party_secret_key_share + decentralized_party_secret_key_share;

        let public_key = centralized_party_public_key_share + decentralized_party_public_key_share;

        let centralized_party_signature_homomorphic_evaluation_round_party =
            centralized_party::signature_homomorphic_evaluation_round::Party::<
                { secp256k1::SCALAR_LIMBS },
                { RANGE_CLAIMS_PER_SCALAR },
                { RANGE_CLAIMS_PER_MASK },
                { ristretto::SCALAR_LIMBS },
                { NUM_RANGE_CLAIMS },
                { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
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
                scalar_group_public_parameters: protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                group_public_parameters: protocol_public_parameters.group_public_parameters.clone(),
                encryption_scheme_public_parameters: protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
                unbounded_dcom_eval_witness_public_parameters: protocol_public_parameters
                    .unbounded_dcom_eval_witness_public_parameters
                    .clone(),
                range_proof_public_parameters: protocol_public_parameters
                    .range_proof_dcom_eval_public_parameters
                    .clone(),
                public_key,
                secret_key_share: centralized_party_secret_key_share,
                public_key_share: centralized_party_public_key_share,
                nonce_share_commitment_randomness,
                nonce_share: centralized_party_nonce_share,
                decentralized_party_nonce_public_share,
                encrypted_mask,
                encrypted_masked_key_share,
            };

        let message = "singing!";

        let m = bits2field::<k256::Secp256k1>(
            &<k256::Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(message.as_bytes())
                .finalize_fixed(),
        )
        .unwrap();

        let m = <Scalar<k256::Secp256k1> as Reduce<U256>>::reduce_bytes(&m);
        let m = U256::from(m).into();

        let now = measurement.start();
        let (
            public_nonce_encrypted_partial_signature_and_proof,
            signature_verification_round_party,
        ) = centralized_party_signature_homomorphic_evaluation_round_party
            .evaluate_encrypted_partial_signature_prehash(m, &mut OsRng)
            .unwrap();
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let (decryption_key_share_public_parameters, decryption_key_shares, lagrange_coefficients) =
            setup_decryption_key_shares(threshold, number_of_parties);

        let evaluation_party_id = *decryption_key_shares.keys().next().unwrap();

        let decentralized_party_sign_round_parties: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, decryption_key_share)| {
                (
                    party_id,
                    signature_partial_decryption_round::Party::<
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
                        threshold,
                        decryption_key_share,
                        decryption_key_share_public_parameters:
                            decryption_key_share_public_parameters.clone(),
                        protocol_context: PhantomData::<()>,
                        scalar_group_public_parameters: protocol_public_parameters
                            .scalar_group_public_parameters
                            .clone(),
                        group_public_parameters: protocol_public_parameters
                            .group_public_parameters
                            .clone(),
                        encryption_scheme_public_parameters: protocol_public_parameters
                            .encryption_scheme_public_parameters
                            .clone(),
                        unbounded_dcom_eval_witness_public_parameters: protocol_public_parameters
                            .unbounded_dcom_eval_witness_public_parameters
                            .clone(),
                        range_proof_public_parameters: protocol_public_parameters
                            .range_proof_dcom_eval_public_parameters
                            .clone(),
                        nonce_public_share: decentralized_party_nonce_public_share,
                        public_key,
                        encrypted_mask,
                        encrypted_masked_key_share,
                        encrypted_masked_nonce_share,
                        centralized_party_public_key_share,
                        centralized_party_nonce_share_commitment,
                    },
                )
            })
            .collect();

        let (decryption_shares, signature_threshold_decryption_round_parties): (
            Vec<_>,
            HashMap<_, _>,
        ) = decentralized_party_sign_round_parties
            .into_iter()
            .map(|(party_id, party)| {
                let now = measurement.start();
                let (
                    (partial_signature_decryption_share, masked_nonce_decryption_share),
                    signature_threshold_decryption_round_party,
                ) = party
                    .partially_decrypt_encrypted_signature_parts_prehash(
                        m,
                        public_nonce_encrypted_partial_signature_and_proof.clone(),
                        &mut OsRng,
                    )
                    .unwrap();
                if party_id == evaluation_party_id {
                    decentralized_party_decryption_share_time = measurement.end(now);
                };

                (
                    (
                        (party_id, partial_signature_decryption_share),
                        (party_id, masked_nonce_decryption_share),
                    ),
                    (party_id, signature_threshold_decryption_round_party),
                )
            })
            .unzip();

        let (mut partial_signature_decryption_shares, masked_nonce_decryption_shares): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = decryption_shares.into_iter().unzip();

        let malicious_decrypter_party_id =
            *partial_signature_decryption_shares.keys().next().unwrap();
        if malicious_decrypter {
            partial_signature_decryption_shares.insert(
                malicious_decrypter_party_id,
                PaillierModulusSizedNumber::ZERO,
            );
        }

        let public_nonce = centralized_party_nonce_share.invert().unwrap()
            * decentralized_party_nonce_public_share; // $R = k_A^-1*k_B*G$

        assert_eq!(
            public_nonce,
            secp256k1::GroupElement::new(
                public_nonce_encrypted_partial_signature_and_proof.public_nonce,
                &protocol_public_parameters.group_public_parameters,
            )
            .unwrap()
        );

        let nonce_x_coordinate = public_nonce.x(); // $r$

        let mut signature_threshold_decryption_round_parties =
            signature_threshold_decryption_round_parties.into_iter();

        // Choose some party as the amortized threshold decryption party.
        let (_, signature_threshold_decryption_round_party) =
            signature_threshold_decryption_round_parties.next().unwrap();

        let now = measurement.start();
        let res = signature_threshold_decryption_round_party.decrypt_signature(
            lagrange_coefficients,
            partial_signature_decryption_shares,
            masked_nonce_decryption_shares,
        );
        let decentralized_party_threshold_decryption_time = measurement.end(now);
        if malicious_decrypter {
            assert!(
                matches!(res.err().unwrap(), Error::SignatureVerification),
                "Designated party should report error in verification in case of a malicious decrypter"
            );

            return;
        }
        let (returned_nonce_x_coordinate, signature_s) = if designated_sending_wrong_signature {
            (nonce_x_coordinate, nonce_x_coordinate.neutral())
        } else {
            res.unwrap()
        };

        assert_eq!(nonce_x_coordinate, returned_nonce_x_coordinate);

        // now do the amortized threshold decryption logic which just verifies the signature.
        signature_threshold_decryption_round_parties.for_each(
            |(_, signature_threshold_decryption_round_party)| {
                let res = signature_threshold_decryption_round_party
                    .verify_decrypted_signature(signature_s);

                if designated_sending_wrong_signature {
                    assert!(
                        matches!(
                            res.err().unwrap(),
                            Error::MaliciousDesignatedDecryptingParty
                        ),
                        "Malicious designated decryption party which sends an invalid signature must be blamed"
                    );
                } else {
                    assert!(
                        res.is_ok(),
                        "Signature verification should pass in case of an honest designated decryption party"
                    );
                }
            },
        );

        let now = measurement.start();
        let res =
            signature_verification_round_party.verify_signature(nonce_x_coordinate, signature_s);
        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        if designated_sending_wrong_signature {
            assert!(
                matches!(res.err().unwrap(), Error::SignatureVerification),
                "An invalid signature sent by a malicious decentralized party must not be accepted"
            );
        } else {
            res.unwrap();
        }

        if designated_sending_wrong_signature || malicious_decrypter {
            return;
        }

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
        let signature_s_inner: k256::Scalar = signature_s.into();

        let signature =
            Signature::from_scalars(k256::Scalar::from(nonce_x_coordinate), signature_s_inner)
                .unwrap();

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
    #[case(2, 2, false, false)]
    #[case(2, 2, true, false)]
    #[case(2, 2, false, true)]
    #[case(2, 4, false, false)]
    #[case(2, 4, true, false)]
    #[case(2, 4, false, true)]
    #[case(6, 9, false, false)]
    fn signs(
        #[case] threshold: PartyID,
        #[case] number_of_parties: PartyID,
        #[case] malicious_decrypter: bool,
        #[case] designated_sending_wrong_signature: bool,
    ) {
        let protocol_public_parameters = crate::ProtocolPublicParameters::new(N);

        let paillier_encryption_key = tiresias::EncryptionKey::new(
            &protocol_public_parameters.encryption_scheme_public_parameters,
        )
        .unwrap();

        let generator = secp256k1::GroupElement::new(
            protocol_public_parameters.group_public_parameters.generator,
            &protocol_public_parameters.group_public_parameters,
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

        let centralized_party_secret_key_share = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let centralized_party_public_key_share = centralized_party_secret_key_share * generator;

        let decentralized_party_secret_key_share = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let decentralized_party_public_key_share = decentralized_party_secret_key_share * generator;

        let nonce_share_commitment_randomness = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let centralized_party_nonce_share = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let centralized_party_nonce_share_commitment = commitment_scheme.commit(
            &[centralized_party_nonce_share].into(),
            &nonce_share_commitment_randomness,
        );

        let decentralized_party_nonce_share = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let decentralized_party_nonce_public_share = decentralized_party_nonce_share * generator;

        let mask = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let (_, encrypted_mask) = paillier_encryption_key
            .encrypt(
                &tiresias::PlaintextSpaceGroupElement::new(
                    Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(
                        mask.value(),
                    )),
                    protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
                .unwrap(),
                &protocol_public_parameters.encryption_scheme_public_parameters,
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
                    protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
                .unwrap(),
                &protocol_public_parameters.encryption_scheme_public_parameters,
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
                    protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
                .unwrap(),
                &protocol_public_parameters.encryption_scheme_public_parameters,
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
            malicious_decrypter,
            designated_sending_wrong_signature,
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
        let protocol_public_parameters = crate::ProtocolPublicParameters::new(N);

        let (centralized_party_dkg_output, decentralized_party_dkg_output) =
            generates_distributed_key_internal(threshold, number_of_parties);

        let encrypted_secret_key_share = tiresias::CiphertextSpaceGroupElement::new(
            decentralized_party_dkg_output.encrypted_secret_key_share,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

        let (centralized_party_presign, encrypted_nonce, decentralized_party_presign) =
            generates_presignatures_internal(
                threshold,
                number_of_parties,
                batch_size,
                encrypted_secret_key_share,
                false,
            )
            .unwrap();

        let centralized_party_presign = centralized_party_presign.first().unwrap().clone();
        let decentralized_party_presign = decentralized_party_presign.first().unwrap().clone();

        let centralized_party_nonce_share_commitment = secp256k1::GroupElement::new(
            decentralized_party_presign.centralized_party_nonce_share_commitment,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let decentralized_party_nonce_public_share = secp256k1::GroupElement::new(
            decentralized_party_presign.nonce_public_share,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let encrypted_mask = tiresias::CiphertextSpaceGroupElement::new(
            centralized_party_presign.encrypted_mask,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

        let encrypted_masked_key_share = tiresias::CiphertextSpaceGroupElement::new(
            centralized_party_presign.encrypted_masked_key_share,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

        let encrypted_masked_nonce_share = tiresias::CiphertextSpaceGroupElement::new(
            decentralized_party_presign.encrypted_masked_nonce_share,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

        let paillier_decryption_key = tiresias::DecryptionKey::new(
            SECRET_KEY,
            &protocol_public_parameters.encryption_scheme_public_parameters,
        )
        .unwrap();

        let group_order = secp256k1::Scalar::order_from_public_parameters(
            &protocol_public_parameters.scalar_group_public_parameters,
        );

        let group_order = Option::<_>::from(NonZero::new(group_order)).unwrap();

        let decentralized_party_secret_key_share = paillier_decryption_key
            .decrypt(
                &encrypted_secret_key_share,
                &protocol_public_parameters.encryption_scheme_public_parameters,
            )
            .unwrap();

        let decentralized_party_secret_key_share = secp256k1::Scalar::new(
            decentralized_party_secret_key_share
                .value()
                .reduce(&group_order)
                .into(),
            &protocol_public_parameters.scalar_group_public_parameters,
        )
        .unwrap();

        let decentralized_party_nonce_share = paillier_decryption_key
            .decrypt(
                encrypted_nonce.first().unwrap(),
                &protocol_public_parameters.encryption_scheme_public_parameters,
            )
            .unwrap();

        let decentralized_party_nonce_share = secp256k1::Scalar::new(
            decentralized_party_nonce_share
                .value()
                .reduce(&group_order)
                .into(),
            &protocol_public_parameters.scalar_group_public_parameters,
        )
        .unwrap();

        let secret_key_share = secp256k1::Scalar::new(
            centralized_party_dkg_output.secret_key_share,
            &protocol_public_parameters.scalar_group_public_parameters,
        )
        .unwrap();

        let public_key_share = secp256k1::GroupElement::new(
            centralized_party_dkg_output.public_key_share,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let decentralized_party_public_key_share = secp256k1::GroupElement::new(
            decentralized_party_dkg_output.public_key_share,
            &protocol_public_parameters.group_public_parameters,
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
            false,
            false,
        );
    }

    #[rstest]
    #[case(2, 2, false)]
    #[case(2, 2, true)]
    #[case(2, 4, false)]
    #[case(2, 4, true)]
    #[case(6, 9, false)]
    #[case(6, 9, true)]
    fn sign_identifiable_abort(
        #[case] threshold: PartyID,
        #[case] number_of_parties: PartyID,
        #[case] dos: bool,
    ) {
        let (decryption_key_share_public_parameters, decryption_key_shares, lagrange_coefficients) =
            setup_decryption_key_shares(threshold, number_of_parties);

        let decrypters: Vec<_> = decryption_key_shares.keys().cloned().collect();

        let paillier_encryption_key = tiresias::EncryptionKey::new(
            &decryption_key_share_public_parameters.encryption_scheme_public_parameters,
        )
        .unwrap();

        // Use dummy values for ciphertexts, as we don't do any signature verification here, just
        // making sure decryption was done correctly.
        let (_, encrypted_partial_signature) = paillier_encryption_key
            .encrypt(
                &tiresias::PlaintextSpaceGroupElement::new(
                    Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::ZERO,
                    decryption_key_share_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
                .unwrap(),
                &decryption_key_share_public_parameters.encryption_scheme_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        let (_, encrypted_masked_nonce_share) = paillier_encryption_key
            .encrypt(
                &tiresias::PlaintextSpaceGroupElement::new(
                    Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::ONE,
                    decryption_key_share_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
                .unwrap(),
                &decryption_key_share_public_parameters.encryption_scheme_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        let (mut partial_signature_decryption_shares, masked_nonce_decryption_shares): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = decryption_key_shares
            .clone()
            .into_iter()
            .map(|(party_id, decryption_key_share)| {
                (
                    (
                        party_id,
                        decryption_key_share
                            .generate_decryption_share_semi_honest(
                                &encrypted_partial_signature,
                                &decryption_key_share_public_parameters,
                            )
                            .unwrap(),
                    ),
                    (
                        party_id,
                        decryption_key_share
                            .generate_decryption_share_semi_honest(
                                &encrypted_masked_nonce_share,
                                &decryption_key_share_public_parameters,
                            )
                            .unwrap(),
                    ),
                )
            })
            .unzip();

        let partial_decryption_proof_round_parties: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, decryption_key_share)| {
                (
                    party_id,
                    signature_partial_decryption_proof_round::Party::<
                        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
                        tiresias::EncryptionKey,
                        DecryptionKeyShare,
                    > {
                        threshold,
                        decryption_key_share,
                        decryption_key_share_public_parameters:
                            decryption_key_share_public_parameters.clone(),
                        encrypted_partial_signature,
                        encrypted_masked_nonce_share,
                    },
                )
            })
            .collect();

        let (signature_partial_decryption_proofs, partial_decryption_verification_round_parties): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = partial_decryption_proof_round_parties
            .into_iter()
            .map(|(party_id, party)| {
                let (proof, verification_party) = party
                    .prove_correct_signature_partial_decryption(&mut OsRng)
                    .unwrap();

                ((party_id, proof), (party_id, verification_party))
            })
            .unzip();

        let number_of_malicious_parties = if decrypters.len() == 2 { 1 } else { 2 };
        let mut malicious_decrypters = decrypters
            .into_iter()
            .choose_multiple(&mut OsRng, number_of_malicious_parties);
        malicious_decrypters.sort();

        if !dos {
            // Simulate malicious decrypters by having them send invalid decryption shares.
            malicious_decrypters.iter().for_each(|&party_id| {
                partial_signature_decryption_shares.insert(
                    party_id,
                    Uint::<{ tiresias::CIPHERTEXT_SPACE_SCALAR_LIMBS }>::ZERO,
                );
            });
        }

        partial_decryption_verification_round_parties
            .into_iter()
            .all(|(party_id, party)| {
                if malicious_decrypters.contains(&party_id) {
                    // No reason to check malicious party reported malicious behavior.
                    true
                } else {
                    let err = party.identify_malicious_decrypters(
                        lagrange_coefficients.clone(),
                        partial_signature_decryption_shares.clone(),
                        masked_nonce_decryption_shares.clone(),
                        signature_partial_decryption_proofs.clone(),
                        &mut OsRng,
                    );

                    if dos {
                        // Test the case where the designated party tried to DOS by saying signature
                        // was invalid, even tho it wasn't.
                        matches!(err, Error::MaliciousDesignatedDecryptingParty)
                    } else {
                        matches!(
                        err,
                        Error::Tiresias(tiresias::Error::ProtocolError(tiresias::ProtocolError::ProofVerificationError {malicious_parties})) if malicious_parties == malicious_decrypters
                    )
                    }
                }
            });
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
