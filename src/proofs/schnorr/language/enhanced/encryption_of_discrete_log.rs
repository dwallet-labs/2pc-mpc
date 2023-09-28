// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Mul};

use crypto_bigint::{Encoding, Uint};
use language::GroupsPublicParameters;
use schnorr::language;
use serde::Serialize;

use super::EnhancedLanguage;
use crate::{
    ahe,
    commitments::HomomorphicCommitmentScheme,
    group,
    group::{additive_group_of_integers_modulu_n::power_of_two_moduli, direct_product, GroupElement as _, Samplable},
    proofs,
    proofs::{range, schnorr},
    AdditivelyHomomorphicEncryptionKey,
};

/// Encryption of Discrete Log Schnorr Language
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group and additively homomorphic
/// encryption scheme in this language, we choose to provide a fully generic
/// implementation.
///
/// However knowledge-soundness proofs are group and encryption scheme dependent, and thus we can
/// only assure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
///
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier`.
#[derive(Clone, Serialize)]
pub struct Language<
    const MASK_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
    const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
    const WITNESS_MASK_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    EncryptionKey,
    RangeProof,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
    _range_proof_choice: PhantomData<RangeProof>,
}

// todo: remove from proof the other parameters. Need to fix AsRef for that.

// todo: note the masked witness is > 256-bit, and should not go through modulation in the
// constrained witness group, nor in the range proof commitment nor in the encryption, but could and
// will go through modulation in the Scalar group - that's fine.
//
// option 1: RANGE_CLAIMS_PER_SCALAR => RANGE_CLAIMS_PER_MASKED_WITNESS
// option 2: notice we don't need to do range proof for the masked witness, so don't care if its
// bigger than RANGE_CLAIM_LIMBS. so can do the constrained witness as self_product of size
// RANGE_CLAIM_LIMBS + Statistical + Computational. then also we don't need to change the sampling
// of the original schnorr.
//
// TODO: can't
impl<
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
        const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS>,
    > schnorr::Language
    for Language<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    Scalar::Value: From<[Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>, /* TODO: remove
                                                                               * this & follow
                                                                               * paper */
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: From<Scalar>,
    range::CommitmentSchemeMessageSpaceGroupElement<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, RangeProof>:
        for<'a> From<&'a super::ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    type WitnessSpaceGroupElement =
        super::EnhancedLanguageWitness<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Self>;
    type StatementSpaceGroupElement =
        super::EnhancedLanguageStatement<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS, Self>;

    type PublicParameters = PublicParameters<
        language::WitnessSpacePublicParameters<Self>,
        language::StatementSpacePublicParameters<Self>,
        range::CommitmentSchemePublicParameters<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, RangeProof>,
        ahe::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        group::PublicParameters<Scalar>,
        GroupElement::Value,
    >;

    const NAME: &'static str = "Encryption of Discrete Log";

    fn group_homomorphism(
        witness: &language::WitnessSpaceGroupElement<Self>,
        language_public_parameters: &language::PublicParameters<Self>,
    ) -> proofs::Result<language::StatementSpaceGroupElement<Self>> {
        let (discrete_log_in_range_claim_base_self_product, commitment_randomness, encryption_randomness) = witness.into();

        let (_, group_public_parameters) = (&language_public_parameters
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        let (_, group_public_parameters) = group_public_parameters.into();

        let base = GroupElement::new(language_public_parameters.generator.clone(), group_public_parameters)?;

        let encryption_key = EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        let discrete_log_in_range_claim_base: [power_of_two_moduli::GroupElement<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR] =
            (*discrete_log_in_range_claim_base_self_product).into();
        let discrete_log: Scalar::Value = discrete_log_in_range_claim_base
            .map(|element| Uint::<WITNESS_MASK_LIMBS>::from(element))
            .into();

        let discrete_log = Scalar::new(discrete_log, &language_public_parameters.scalar_group_public_parameters)?;

        let discrete_log_plaintext = ahe::PlaintextSpaceGroupElement::<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>::new(
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(discrete_log),
            &language_public_parameters
                .encryption_scheme_public_parameters
                .as_ref()
                .plaintext_space_public_parameters,
        )?;

        Ok((
            commitment_scheme.commit(&discrete_log_in_range_claim_base_self_product.into(), commitment_randomness), /* TODO: need
                                                                                                                     * to check this
                                                                                                                     * is
                                                                                                                     * safe, or retry if it fails.
                                                                                                                     * Also, need
                                                                                                                     * to implement.
                                                                                                                     */
            (
                encryption_key.encrypt_with_randomness(&discrete_log_plaintext, encryption_randomness),
                discrete_log * base,
            )
                .into(),
        )
            .into())
    }
}

impl<
        const MASK_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize, // TOdO: potentially change to d
        const RANGE_CLAIM_LIMBS: usize,       // TODO: delta
        const WITNESS_MASK_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        Scalar: group::GroupElement,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        RangeProof: proofs::RangeProof<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS>,
    > EnhancedLanguage<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, WITNESS_MASK_LIMBS>
    for Language<
        MASK_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIM_LIMBS,
        WITNESS_MASK_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        Scalar,
        GroupElement,
        EncryptionKey,
        RangeProof,
    >
where
    Uint<RANGE_CLAIM_LIMBS>: Encoding,
    Uint<WITNESS_MASK_LIMBS>: Encoding,
    Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    Scalar::Value: From<[Uint<WITNESS_MASK_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: From<Scalar>,
    range::CommitmentSchemeMessageSpaceGroupElement<RANGE_CLAIMS_PER_SCALAR, RANGE_CLAIM_LIMBS, RangeProof>:
        for<'a> From<&'a super::ConstrainedWitnessGroupElement<RANGE_CLAIMS_PER_SCALAR, WITNESS_MASK_LIMBS>>,
{
    type UnboundedWitnessSpaceGroupElement = ahe::RandomnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;

    type RemainingStatementSpaceGroupElement =
        direct_product::GroupElement<ahe::CiphertextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>, GroupElement>;

    type RangeProof = RangeProof;
}

/// The Public Parameters of the Encryption of Discrete Log Schnorr Language
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    WitnessSpacePublicParameters,
    StatementSpacePublicParameters,
    CommitmentSchemePublicParameters,
    EncryptionKeyPublicParameters,
    ScalarPublicParameters,
    GroupElementValue,
> {
    pub groups_public_parameters: GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    // The base of the discrete log
    pub generator: GroupElementValue,
    // todo: range claim. - of type RANGE_CLAIM_LIMBS * RANGE_CLAIMS_PER_SCALAR
}

impl<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
        EncryptionKeyPublicParameters,
        ScalarPublicParameters,
        GroupElementValue,
    > AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
    for PublicParameters<
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
        CommitmentSchemePublicParameters,
        EncryptionKeyPublicParameters,
        ScalarPublicParameters,
        GroupElementValue,
    >
{
    fn as_ref(&self) -> &GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
        &self.groups_public_parameters
    }
}
