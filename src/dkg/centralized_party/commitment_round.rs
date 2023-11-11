// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{rand_core::OsRng, Random};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    dkg::centralized_party::decommitment_round,
    group,
    group::{secp256k1, GroupElement as _, PrimeGroupElement, Samplable},
    proofs::{
        schnorr::{knowledge_of_discrete_log, language::GroupsPublicParameters, Proof},
        transcript_protocol::TranscriptProtocol,
    },
    Commitment, ComputationalSecuritySizedNumber,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub group_public_parameters: GroupElement::PublicParameters,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    // TODO: should we get this like that?
    pub protocol_context: ProtocolContext,
}

impl<
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    > Party<SCALAR_LIMBS, GroupElement, ProtocolContext>
{
    pub fn sample_commit_and_prove_secret_key_share(
        self,
        rng: &mut OsRng,
    ) -> crate::Result<(
        Commitment,
        decommitment_round::Party<SCALAR_LIMBS, GroupElement, ProtocolContext>,
    )> {
        let secret_key_share =
            GroupElement::Scalar::sample(rng, &self.scalar_group_public_parameters)?;

        let language_public_parameters = knowledge_of_discrete_log::PublicParameters {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: self.scalar_group_public_parameters.clone(),
                statement_space_public_parameters: self.group_public_parameters.clone(),
            },
            generator: GroupElement::generator_from_public_parameters(
                &self.group_public_parameters,
            ),
        };

        let (proof, public_key_share) = knowledge_of_discrete_log::Proof::<
            GroupElement::Scalar,
            GroupElement,
            ProtocolContext,
        >::prove(
            0,
            &self.protocol_context,
            &language_public_parameters,
            vec![secret_key_share],
            rng,
        )?;

        let public_key_share: GroupElement = public_key_share
            .first()
            .ok_or(crate::Error::APIMismatch)?
            .clone();

        let mut transcript = Transcript::new(b"DKG commitment round of centralized party");
        // TODO: this should be enough for the "bit" that says its party A sending.

        // TODO: is protocol context the right thing here?
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

        Ok((commitment, party))
    }
}
