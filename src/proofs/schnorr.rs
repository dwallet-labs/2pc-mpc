// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

pub mod commitment_of_discrete_log;

pub mod knowledge_of_discrete_log;

pub mod committed_linear_evaluation;
pub mod encryption_of_discrete_log;
pub mod knowledge_of_decommitment;

use std::marker::PhantomData;

use crypto_bigint::{rand_core::CryptoRngCore, ConcatMixed, U64};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::{Error, Result, TranscriptProtocol};
use crate::{
    group::{GroupElement, Samplable},
    ComputationalSecuritySizedNumber,
};

// For a batch size $N_B$, the challenge space should be $[0,N_B \cdot 2^{\kappa + 2})$.
// Setting it to be 64-bit larger than the computational security parameter $\kappa$ allows us to
// practically use any batch size (Rust does not allow a vector larger than $2^64$ elements,
// as does 64-bit architectures in which the memory won't even be addressable.)
type ChallengeSizedNumber = <ComputationalSecuritySizedNumber as ConcatMixed<U64>>::MixedOutput;

/// A Schnorr Zero-Knowledge Proof Language
/// Can be generically used to generate a batched Schnorr zero-knowledge `Proof`
/// As defined in Appendix B. Schnorr Protocols in the paper
pub trait Language<
    // The upper bound for the scalar size of the witness group
    const WITNESS_SCALAR_LIMBS: usize,
    // The upper bound for the scalar size of the associated public-value space group
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    // An element of the witness space $(\HH_\pp, +)$
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable<WITNESS_SCALAR_LIMBS>,
    // An element in the associated public-value space $(\GG_\pp, \cdot)$,
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
>
{
    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$
    ///
    /// Used for language-specific parameters (e.g., the public parameters of the commitment scheme
    /// used for proving knowledge of decommitment - the bases $g$, $h$ in the case of Pedersen).
    ///
    /// Group public parameters are encoded separately in
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `PublicValueSpaceGroupElement::PublicParameters`.
    type PublicParameters: Serialize + PartialEq;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// A group homomorphism $\phi:\HH\to\GG$  from $(\HH_\pp, +)$, the witness space,
    /// to $(\GG_\pp,\cdot)$, the public-value space space.
    fn group_homomorphism(
        witness: &WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
    ) -> Result<PublicValueSpaceGroupElement>;
}

/// An Enhanced Batched Schnorr Zero-Knowledge Proof.
/// Implements Appendix B. Schnorr Protocols in the paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS>,
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
    Lang: Clone,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    statement_mask: PublicValueSpaceGroupElement::Value,
    response: WitnessSpaceGroupElement::Value,

    _language_choice: PhantomData<Lang>,
    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<
    const WITNESS_SCALAR_LIMBS: usize,
    const PUBLIC_VALUE_SCALAR_LIMBS: usize,
    WitnessSpaceGroupElement: Samplable<WITNESS_SCALAR_LIMBS>,
    PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
    Lang: Language<
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        WitnessSpaceGroupElement,
        PublicValueSpaceGroupElement,
    > + Clone,
    ProtocolContext: Clone + Serialize,
>
Proof<
    WITNESS_SCALAR_LIMBS,
    PUBLIC_VALUE_SCALAR_LIMBS,
    WitnessSpaceGroupElement,
    PublicValueSpaceGroupElement,
    Lang,
    ProtocolContext,
>
{
    fn new(
        statement_mask: PublicValueSpaceGroupElement,
        response: WitnessSpaceGroupElement,
    ) -> Self {
        Self {
            statement_mask: statement_mask.value(),
            response: response.value(),
            _language_choice: PhantomData,
            _protocol_context_choice: PhantomData,
        }
    }

    /// Prove an enhanced batched Schnorr zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: ProtocolContext,
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        witnesses_and_statements: Vec<(WitnessSpaceGroupElement, PublicValueSpaceGroupElement)>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if witnesses_and_statements.is_empty() {
            return Err(Error::InvalidParameters);
        }

        let batch_size = witnesses_and_statements.len();

        let (witnesses, statements): (
            Vec<WitnessSpaceGroupElement>,
            Vec<PublicValueSpaceGroupElement>,
        ) = witnesses_and_statements.iter().cloned().unzip();

        let mut transcript = Self::setup_protocol(
            &protocol_context,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
            statements,
        )?;

        let randomizer = WitnessSpaceGroupElement::sample(rng, witness_space_public_parameters)?;

        let statement_mask = Lang::group_homomorphism(
            &randomizer,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
        )?;

        let challenges: Vec<ChallengeSizedNumber> =
            Self::compute_challenges(&statement_mask.value(), batch_size, &mut transcript)?;

        // Using the "small exponents" method for batching;
        // the exponents actually need to account for the batch size.
        // We added 64-bit for that, which is fine for sampling randmoness,
        // but in practice the exponentiation (i.e. `scalar_mul`) could use
        // the real bound: `128 + log2(BatchSize)+2 < 192` to increase performance.
        // We leave that as future work in case this becomes a bottleneck.
        let response = randomizer
            + witnesses
            .into_iter()
            .zip(challenges)
            .map(|(witness, challenge)| witness.scalar_mul(&challenge))
            .reduce(|a, b| a + b)
            .unwrap();

        Ok(Self::new(statement_mask, response))
    }

    /// Verify an enhanced batched Schnorr zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: ProtocolContext,
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<()> {
        let batch_size = statements.len();

        let mut transcript = Self::setup_protocol(
            &protocol_context,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
            statements.clone(),
        )?;

        let challenges: Vec<ChallengeSizedNumber> =
            Self::compute_challenges(&self.statement_mask, batch_size, &mut transcript)?;

        let response =
            WitnessSpaceGroupElement::new(self.response.clone(), witness_space_public_parameters)?;

        let statement_mask = PublicValueSpaceGroupElement::new(
            self.statement_mask.clone(),
            public_value_space_public_parameters,
        )?;

        let response_statement: PublicValueSpaceGroupElement = Lang::group_homomorphism(
            &response,
            language_public_parameters,
            witness_space_public_parameters,
            public_value_space_public_parameters,
        )?;

        let reconstructed_response_statement: PublicValueSpaceGroupElement = statement_mask
            + statements
            .into_iter()
            .zip(challenges)
            .map(|(statement, challenge)| statement.scalar_mul(&challenge))
            .reduce(|a, b| a + b)
            .unwrap();

        if response_statement == reconstructed_response_statement {
            return Ok(());
        }
        Err(Error::ProofVerification)
    }

    fn setup_protocol(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        statements: Vec<PublicValueSpaceGroupElement>,
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(Lang::NAME.as_bytes());

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        transcript.serialize_to_transcript_as_json(
            b"language public parameters",
            language_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"witness space public parameters",
            witness_space_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"public value space public parameters",
            public_value_space_public_parameters,
        )?;

        if statements.iter().any(|statement| {
            transcript
                .serialize_to_transcript_as_json(b"statement value", &statement.value())
                .is_err()
        }) {
            return Err(Error::InvalidParameters);
        }

        Ok(transcript)
    }

    fn compute_challenges(
        statement_mask_value: &PublicValueSpaceGroupElement::Value,
        batch_size: usize,
        transcript: &mut Transcript,
    ) -> Result<Vec<ChallengeSizedNumber>> {
        transcript
            .serialize_to_transcript_as_json(b"randomizer public value", statement_mask_value)?;

        Ok((1..=batch_size)
            .map(|_| {
                let challenge = transcript.challenge(b"challenge");

                // we don't have to do this because Merlin uses a PRF behind the scenes,
                // but we do it anyways as a security best-practice
                transcript.append_uint(b"challenge", &challenge);

                challenge
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use rand_core::OsRng;
    use crate::group;

    use rstest::rstest;
    use super::*;

    fn generate_witnesses_and_statements<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable<WITNESS_SCALAR_LIMBS>,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        Lang: Language<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
        >,
    >(
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        batch_size: usize,
    ) -> Vec<(WitnessSpaceGroupElement, PublicValueSpaceGroupElement)> {
        let witnesses: Vec<WitnessSpaceGroupElement> =
            iter::repeat_with(|| WitnessSpaceGroupElement::sample(&mut OsRng, witness_space_public_parameters).unwrap())
                .take(batch_size)
                .collect();

        let statements: Vec<PublicValueSpaceGroupElement> = witnesses
            .iter()
            .map(|witness| {
                Lang::group_homomorphism(
                    &witness,
                    &language_public_parameters,
                    &witness_space_public_parameters,
                    &public_value_space_public_parameters,
                )
                    .unwrap()
            })
            .collect();

        witnesses
            .clone()
            .into_iter()
            .zip(statements.into_iter())
            .collect()
    }

    fn generate_witness_and_statement<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable<WITNESS_SCALAR_LIMBS>,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        Lang: Language<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
        >,
    >(
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
    ) -> (WitnessSpaceGroupElement, PublicValueSpaceGroupElement) {
        let (witnesses, statements): (
            Vec<WitnessSpaceGroupElement>,
            Vec<PublicValueSpaceGroupElement>,
        ) = generate_witnesses_and_statements::<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
            Lang,
        >(
            &language_public_parameters,
            &witness_space_public_parameters,
            &public_value_space_public_parameters,
            1,
        )
            .into_iter()
            .unzip();

        (
            witnesses.first().unwrap().clone(),
            statements.first().unwrap().clone(),
        )
    }

    fn generate_valid_proof<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable<WITNESS_SCALAR_LIMBS>,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        Lang: Language<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
        > + Clone,
    >(
        language_public_parameters: &Lang::PublicParameters,
        witness_space_public_parameters: &WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: &PublicValueSpaceGroupElement::PublicParameters,
        witnesses_and_statements: Vec<(WitnessSpaceGroupElement, PublicValueSpaceGroupElement)>,
    ) -> Proof<
        WITNESS_SCALAR_LIMBS,
        PUBLIC_VALUE_SCALAR_LIMBS,
        WitnessSpaceGroupElement,
        PublicValueSpaceGroupElement,
        Lang,
        PhantomData<()>,
    > {
        Proof::<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::prove(
            PhantomData,
            &language_public_parameters,
            &witness_space_public_parameters,
            &public_value_space_public_parameters,
            witnesses_and_statements,
            &mut OsRng,
        )
            .unwrap()
    }

    fn bla() {
        valid_proof_verifies()
        secp256k1::GroupElement::PublicParameters::default(),
        knowledge_of_discrete_log::PublicParameters<{U256::LIMBS}, secp256k1::Scalar, secp256k1::GroupElement,>::new(secp256k1::GroupElement::PublicParameters::default().generator),

    }

    #[rstest]
    // #[case(1)]
    // #[case(2)]
    // #[case(3)]
    fn valid_proof_verifies<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable<WITNESS_SCALAR_LIMBS>,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        Lang: Language<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
        > + Clone,
    >(
        #[case] language_public_parameters: Lang::PublicParameters,
        #[case] witness_space_public_parameters: WitnessSpaceGroupElement::PublicParameters,
        #[case] public_value_space_public_parameters: PublicValueSpaceGroupElement::PublicParameters,
        #[default(1)] batch_size: usize,
    ) {
        let witnesses_and_statements = generate_witnesses_and_statements::<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
            Lang,
        >(
            &language_public_parameters,
            &witness_space_public_parameters,
            &public_value_space_public_parameters,
            batch_size,
        );

        let proof = generate_valid_proof::<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
            Lang,
        >(
            &language_public_parameters,
            &witness_space_public_parameters,
            &public_value_space_public_parameters,
            witnesses_and_statements.clone(),
        );

        let (_, statements): (
            Vec<WitnessSpaceGroupElement>,
            Vec<PublicValueSpaceGroupElement>,
        ) = witnesses_and_statements.into_iter().unzip();

        assert!(
            proof
                .verify(
                    PhantomData,
                    &language_public_parameters,
                    &witness_space_public_parameters,
                    &public_value_space_public_parameters,
                    statements.into_iter().take(1).collect(),
                )
                .is_ok(),
            "valid proof should verify"
        );
    }

    // #[rstest]
    // #[case(1)]
    // #[case(2)]
    // #[case(3)]
    fn invalid_proof_does_not_verify<
        const WITNESS_SCALAR_LIMBS: usize,
        const PUBLIC_VALUE_SCALAR_LIMBS: usize,
        WitnessSpaceGroupElement: GroupElement<WITNESS_SCALAR_LIMBS> + Samplable<WITNESS_SCALAR_LIMBS>,
        PublicValueSpaceGroupElement: GroupElement<PUBLIC_VALUE_SCALAR_LIMBS>,
        Lang: Language<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
        > + Clone,
    >(
        invalid_witness_space_value: WitnessSpaceGroupElement::Value,
        invalid_public_value_space_value: PublicValueSpaceGroupElement::Value,
        language_public_parameters: Lang::PublicParameters,
        witness_space_public_parameters: WitnessSpaceGroupElement::PublicParameters,
        public_value_space_public_parameters: PublicValueSpaceGroupElement::PublicParameters,
        batch_size: usize, // TODO: #[case]
    ) {
        let witnesses_and_statements = generate_witnesses_and_statements::<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
            Lang,
        >(
            &language_public_parameters,
            &witness_space_public_parameters,
            &public_value_space_public_parameters,
            batch_size,
        );

        let valid_proof = generate_valid_proof::<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
            Lang,
        >(
            &language_public_parameters,
            &witness_space_public_parameters,
            &public_value_space_public_parameters,
            witnesses_and_statements.clone(),
        );

        let (witnesses, statements): (
            Vec<WitnessSpaceGroupElement>,
            Vec<PublicValueSpaceGroupElement>,
        ) = witnesses_and_statements.into_iter().unzip();

        let (wrong_witness, wrong_statement) = generate_witness_and_statement::<
            WITNESS_SCALAR_LIMBS,
            PUBLIC_VALUE_SCALAR_LIMBS,
            WitnessSpaceGroupElement,
            PublicValueSpaceGroupElement,
            Lang,
        >(
            &language_public_parameters,
            &witness_space_public_parameters,
            &public_value_space_public_parameters,
        );

        assert!(matches!(valid_proof
                .verify(
                    PhantomData,
                    &language_public_parameters,
                    &witness_space_public_parameters,
                    &public_value_space_public_parameters,
                    statements
                        .clone()
                        .into_iter()
                        .take(batch_size - 1)
                        .chain(vec![wrong_statement.clone()])
                        .collect(),
                )
                .err()
                .unwrap(), Error::ProofVerification),
                "valid proof shouldn't verify against wrong statements"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.statement_mask = wrong_statement.neutral().value();

        assert!(matches!(
            valid_proof
                .verify(
                    PhantomData,
                    &language_public_parameters,
                    &witness_space_public_parameters,
                    &public_value_space_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::ProofVerification),
                "proof with a neutral statement_mask shouldn't verify"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.response = wrong_witness.neutral().value();

        assert!(matches!(
            valid_proof
                .verify(
                    PhantomData,
                    &language_public_parameters,
                    &witness_space_public_parameters,
                    &public_value_space_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::ProofVerification),
                "proof with a neutral response shouldn't verify"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.statement_mask = invalid_public_value_space_value;

        assert!(matches!(
            valid_proof
                .verify(
                    PhantomData,
                    &language_public_parameters,
                    &witness_space_public_parameters,
                    &public_value_space_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::GroupInstantiation(group::Error::InvalidGroupElementError)),
                "proof with an invalid statement_mask value should generate an invalid parameter error when checking the element is not in the group"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.response = invalid_witness_space_value;

        assert!(matches!(
            valid_proof
                .verify(
                    PhantomData,
                    &language_public_parameters,
                    &witness_space_public_parameters,
                    &public_value_space_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::GroupInstantiation(group::Error::InvalidGroupElementError)),
                "proof with an invalid response value should generate an invalid parameter error when checking the element is not in the group"
        );

        // TODO: make cases for elliptic curve with not on group values and make sure they fail and
        // for the right reason!

        // TODO: generate a valid proof with wrong public parameters and assure it isn't valid -
        // that can only be done for Paillier, and we should just add a case for it
    }
}
