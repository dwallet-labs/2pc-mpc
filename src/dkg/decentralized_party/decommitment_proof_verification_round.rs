// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use crate::{
    dkg::centralized_party,
    group,
    group::PrimeGroupElement,
    proofs,
    proofs::schnorr::{knowledge_of_discrete_log, language::GroupsPublicParameters},
    AdditivelyHomomorphicEncryptionKey, Commitment, PartyID,
};

#[derive(Clone)]
pub struct Output<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> {
    pub public_key_share: GroupElement,
    pub public_key: GroupElement,
    pub encryption_of_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
    pub centralized_party_public_key_share: GroupElement,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    ProtocolContext: Clone + Serialize,
> {
    pub(super) party_id: PartyID,
    pub(super) threshold: PartyID,
    pub(super) number_of_parties: PartyID,
    pub(super) protocol_context: ProtocolContext,
    pub(super) group_public_parameters: GroupElement::PublicParameters,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) commitment_to_centralized_party_secret_key_share: Commitment,
    pub(super) share_of_decentralized_party_secret_key_share: GroupElement::Scalar,
    pub(super) public_key_share: GroupElement,
    pub(super) encryption_of_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolContext,
    >
{
    pub fn verify_decommitment_and_proof_of_centralized_party_public_key_share(
        self,
        decommitment_and_proof: centralized_party::PublicKeyShareDecommitmentAndProof<
            GroupElement::Value,
            knowledge_of_discrete_log::Proof<GroupElement::Scalar, GroupElement, ProtocolContext>,
        >,
    ) -> crate::Result<
        Output<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>,
    > {
        let centralized_party_public_key_share = GroupElement::new(
            decommitment_and_proof.public_key_share,
            &self.group_public_parameters,
        )?;

        let reconstructed_commitment = Commitment::commit_public_key_share(
            &centralized_party_public_key_share,
            &decommitment_and_proof.commitment_randomness,
        )?;
        if reconstructed_commitment != self.commitment_to_centralized_party_secret_key_share {
            return Err(crate::Error::WrongDecommitment);
        }

        let language_public_parameters =
            knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
            );

        decommitment_and_proof.proof.verify(
            None,
            &self.protocol_context,
            &language_public_parameters,
            vec![centralized_party_public_key_share.clone()],
        )?;

        let public_key =
            centralized_party_public_key_share.clone() + &self.public_key_share.clone();

        Ok(Output {
            public_key_share: self.public_key_share,
            public_key,
            encryption_of_secret_key_share: self.encryption_of_secret_key_share,
            centralized_party_public_key_share,
        })
    }
}
