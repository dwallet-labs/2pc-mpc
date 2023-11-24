// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use crypto_bigint::{rand_core::OsRng, Encoding, Random, Uint};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    dkg::centralized_party::decommitment_round,
    group,
    group::{secp256k1, GroupElement as _, GroupElement, PrimeGroupElement, Samplable},
    proofs,
    proofs::{
        range,
        schnorr::{
            encryption_of_discrete_log, knowledge_of_discrete_log,
            language::{enhanced, GroupsPublicParameters},
            Proof,
        },
        transcript_protocol::TranscriptProtocol,
    },
    AdditivelyHomomorphicEncryptionKey, Commitment, ComputationalSecuritySizedNumber,
};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIM_LIMBS: usize,
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: proofs::RangeProof<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
    >,
    ProtocolContext: Clone + Serialize,
> where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    group::ScalarValue<SCALAR_LIMBS, GroupElement>: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    // TODO: should we get this like that? is it the same for both the centralized & decentralized
    // party (and all their parties?)
    pub protocol_context: ProtocolContext,
    pub scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub group_public_parameters: GroupElement::PublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    pub range_proof_public_parameters: RangeProof::PublicParameters,
}

impl Commitment {
    pub fn commit_public_key_share<GroupElement: group::GroupElement>(
        public_key_share: &GroupElement,
        commitment_randomness: &ComputationalSecuritySizedNumber,
    ) -> crate::Result<Self> {
        let mut transcript = Transcript::new(b"DKG commitment round of centralized party");
        // TODO: this should be enough for the "bit" that says its party A sending.

        // TODO: is protocol context the right thing here?
        transcript
            .serialize_to_transcript_as_json(b"public key share", &public_key_share.value())
            .unwrap();

        Ok(Commitment::commit_transcript(
            &mut transcript,
            &commitment_randomness,
        ))
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIM_LIMBS: usize,
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
        >,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        ProtocolContext,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    group::ScalarValue<SCALAR_LIMBS, GroupElement>: From<Uint<SCALAR_LIMBS>>,
    range::CommitmentSchemeMessageSpaceValue<
        RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        RangeProof,
    >: From<enhanced::ConstrainedWitnessValue<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    pub fn sample_commit_and_prove_secret_key_share(
        self,
        rng: &mut OsRng,
    ) -> crate::Result<(
        Commitment,
        decommitment_round::Party<
            SCALAR_LIMBS,
            RANGE_PROOF_COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIM_LIMBS,
            WITNESS_MASK_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            ProtocolContext,
        >,
    )> {
        let secret_key_share =
            GroupElement::Scalar::sample(rng, &self.scalar_group_public_parameters)?;

        let language_public_parameters =
            knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
                self.scalar_group_public_parameters.clone(),
                self.group_public_parameters.clone(),
            );

        let (knowledge_of_discrete_log_proof, public_key_share) = knowledge_of_discrete_log::Proof::<
            GroupElement::Scalar,
            GroupElement,
            ProtocolContext,
        >::prove(
            None,
            &self.protocol_context,
            &language_public_parameters,
            vec![secret_key_share],
            rng,
        )?;

        let public_key_share: GroupElement = public_key_share
            .first()
            .ok_or(crate::Error::APIMismatch)?
            .clone();

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        let commitment =
            Commitment::commit_public_key_share(&public_key_share, &commitment_randomness)?;

        let party = decommitment_round::Party {
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            protocol_context: self.protocol_context,
            secret_key_share,
            public_key_share,
            knowledge_of_discrete_log_proof,
            commitment_randomness,
        };

        Ok((commitment, party))
    }
}
