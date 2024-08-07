// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use commitment::Commitment;
use crypto_bigint::{rand_core::CryptoRngCore, Random};
use group::{ComputationalSecuritySizedNumber, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use maurer::knowledge_of_discrete_log;
use merlin::Transcript;
use proof::{AggregatableRangeProof, TranscriptProtocol};
use serde::Serialize;

use crate::{
    CENTRALIZED_PARTY_ID, dkg::centralized_party::decommitment_round, Error::InternalError,
    ProtocolPublicParameters,
};

const DKG_COMMITMENT_ROUND: &str = "DKG commitment round of a centralized party";

#[cfg_attr(feature = "benchmarking", derive(Clone))]
/// This struct is used to represent the centralized party in the Commitment round of the DKG
/// protocol.
/// This is the first round of the DKG protocol, where the party samples a secret key
/// share and commits to it with a zero-knowledge proof.
pub struct Party<
    const SCALAR_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedEncDLWitness: group::GroupElement + Samplable,
    ProtocolContext: Clone + Serialize,
> {
    protocol_context: ProtocolContext,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: EncryptionKey::PublicParameters,
    unbounded_encdl_witness_public_parameters: UnboundedEncDLWitness::PublicParameters,
    range_proof_public_parameters: RangeProof::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
}

pub fn commit_public_key_share<GroupElement: group::GroupElement>(
    party_id: PartyID,
    public_key_share: &GroupElement,
    commitment_randomness: &ComputationalSecuritySizedNumber,
) -> crate::Result<Commitment> {
    let mut transcript = Transcript::new(DKG_COMMITMENT_ROUND.as_ref());

    transcript
        .serialize_to_transcript_as_json(b"public key share", &public_key_share.value())
        .unwrap();

    Ok(Commitment::commit_transcript(
        party_id,
        DKG_COMMITMENT_ROUND.to_string(),
        &mut transcript,
        commitment_randomness,
    ))
}

impl<
        const SCALAR_LIMBS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedEncDLWitness: group::GroupElement + Samplable,
        ProtocolContext: Clone + Serialize,
    >
    Party<
        SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        UnboundedEncDLWitness,
        ProtocolContext,
    >
{
    /// This function implements step 1 of Protocol 4 (DKG):
    /// Samples $x_A$, computes $X_A$ & zk-proof and commits to these values.
    /// [Source](https://eprint.iacr.org/archive/2024/253/20240217:153208)
    /// Returns a tuple with `commitment` and the centralized party for the decommitment round.
    pub fn sample_commit_and_prove_secret_key_share(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(
        Commitment,
        decommitment_round::Party<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            ProtocolContext,
        >,
    )> {
        // === Sample x_A ====
        // Protocol 4, step 1a
        let secret_key_share =
            GroupElement::Scalar::sample(&self.scalar_group_public_parameters, rng)?;

        // === Construct proof for x_A ===
        // Used in emulating the idealized $F^{L_DL}_{com-zk}$ component
        // Protocol 4, step 1b
        let language_public_parameters = knowledge_of_discrete_log::PublicParameters::new::<
            GroupElement::Scalar,
            GroupElement,
        >(
            self.scalar_group_public_parameters.clone(),
            self.group_public_parameters.clone(),
            GroupElement::generator_value_from_public_parameters(&self.group_public_parameters), /* = G (Protocol 4) */
        );
        let (knowledge_of_discrete_log_proof, public_key_share) = knowledge_of_discrete_log::Proof::<
            GroupElement::Scalar,
            GroupElement,
            ProtocolContext,
        >::prove(
            &self.protocol_context,
            &language_public_parameters,
            vec![secret_key_share],
            rng,
        )?;

        // === Derive X_A ===
        // Protocol 4, step 1a
        let public_key_share: GroupElement = public_key_share.first().ok_or(InternalError)?.clone();

        // === Commit to X_A ===
        // Used in emulating the idealized $F^{L_DL}_{com-zk}$ component
        // Protocol 4, step 1b
        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);
        let commitment = commit_public_key_share(
            CENTRALIZED_PARTY_ID,
            &public_key_share,
            &commitment_randomness,
        )?;

        // Construct the centralized party for the decommitment round.
        let party = decommitment_round::Party {
            group_public_parameters: self.group_public_parameters,
            scalar_group_public_parameters: self.scalar_group_public_parameters,
            encryption_scheme_public_parameters: self.encryption_scheme_public_parameters,
            unbounded_encdl_witness_public_parameters: self
                .unbounded_encdl_witness_public_parameters,
            range_proof_public_parameters: self.range_proof_public_parameters,
            protocol_context: self.protocol_context,
            secret_key_share,
            public_key_share,
            knowledge_of_discrete_log_proof,
            commitment_randomness,
        };

        Ok((commitment, party))
    }

    /// Construct a new instance of the centralized `Party` struct for the Commitment round.
    /// This function is used to initialize the DKG protocol.
    pub fn new<
        const NUM_RANGE_CLAIMS: usize,
        UnboundedEncDHWitness: group::GroupElement + Samplable,
        UnboundedDComEvalWitness: group::GroupElement + Samplable,
    >(
        protocol_public_parameters: ProtocolPublicParameters<
            SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedEncDLWitness,
            UnboundedEncDHWitness,
            UnboundedDComEvalWitness,
        >,
        protocol_context: ProtocolContext,
    ) -> Self {
        Party {
            protocol_context,
            scalar_group_public_parameters: protocol_public_parameters
                .scalar_group_public_parameters,
            group_public_parameters: protocol_public_parameters.group_public_parameters,
            encryption_scheme_public_parameters: protocol_public_parameters
                .encryption_scheme_public_parameters,
            unbounded_encdl_witness_public_parameters: protocol_public_parameters
                .unbounded_encdl_witness_public_parameters,
            range_proof_public_parameters: protocol_public_parameters
                .range_proof_enc_dl_public_parameters,
        }
    }
}
