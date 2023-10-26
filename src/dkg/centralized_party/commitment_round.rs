// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    dkg::centralized_party::decommitment_round,
    group,
    group::{secp256k1, GroupElement as _, Samplable},
    proofs::schnorr::{knowledge_of_discrete_log, language::GroupsPublicParameters, Proof},
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party {}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    proof: Proof<
        knowledge_of_discrete_log::Language<secp256k1::Scalar, secp256k1::GroupElement>,
        PhantomData<()>,
    >,
    public_key_share: group::Value<secp256k1::GroupElement>,
}

impl Party {
    pub fn sample_commit_and_prove_secret_key_share(
        rng: &mut OsRng,
    ) -> (decommitment_round::Party, Message) {
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

        let public_key_share = public_key_share.first().unwrap().value(); // TODO: pattern match this? above

        let message = Message {
            proof,
            public_key_share,
        };

        let party = decommitment_round::Party { secret_key_share };

        // TODO: the commitment is g^xa? doesn't this mess with the whole idea of committing to
        // public key shares?
        // same for enc-dl

        (party, message)
    }
}
