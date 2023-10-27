// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::Random;
use merlin::Transcript;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    dkg::centralized_party::decommitment_round,
    group,
    group::{secp256k1, GroupElement as _, Samplable},
    proofs::{
        schnorr::{knowledge_of_discrete_log, language::GroupsPublicParameters, Proof},
        transcript_protocol::TranscriptProtocol,
    },
    Commitment, ComputationalSecuritySizedNumber,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party {}

impl Party {
    pub fn sample_commit_and_prove_secret_key_share(
        rng: &mut OsRng,
    ) -> (Commitment, decommitment_round::Party) {
        // todo: no unwrap
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let secret_key_share =
            secp256k1::Scalar::sample(rng, &secp256k1_scalar_public_parameters).unwrap();

        let language_public_parameters = knowledge_of_discrete_log::PublicParameters {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: secp256k1_scalar_public_parameters,
                statement_space_public_parameters: secp256k1_group_public_parameters.clone(),
            },
            generator: secp256k1_group_public_parameters.generator,
        };

        let (proof, public_key_share) = Proof::<
            knowledge_of_discrete_log::Language<secp256k1::Scalar, secp256k1::GroupElement>,
            PhantomData<()>,
        >::prove(
            &PhantomData,
            &language_public_parameters,
            vec![secret_key_share],
            rng,
        )
        .unwrap();

        let public_key_share = *public_key_share.first().unwrap(); // TODO: pattern match this? above

        let mut transcript = Transcript::new(b"DKG commitment round of centralized party");
        // TODO: this should be enough for the "bit" that says its party A sending.

        // TODO: is protocol context the right thing here?
        // TODO: party id? but its a DKG
        transcript
            .serialize_to_transcript_as_json(b"public key share", &public_key_share.value())
            .unwrap();

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);
        let commitment = Commitment::commit_transcript(&mut transcript, &commitment_randomness);

        let party = decommitment_round::Party {
            secret_key_share,
            public_key_share,
            proof,
            commitment_randomness,
        };

        (commitment, party)
    }
}
