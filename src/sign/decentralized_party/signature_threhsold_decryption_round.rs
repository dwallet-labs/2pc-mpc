// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{
    collections::{HashMap, HashSet},
    ops::Neg,
};

use crypto_bigint::{NonZero, Uint};
use group::{
    AffineXCoordinate, GroupElement, Invert, KnownOrderGroupElement, PartyID, PrimeGroupElement,
    Reduce,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
};

use crate::{sign::verify_signature, Error};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
> {
    pub(super) threshold: PartyID,
    pub(super) decryption_key_share_public_parameters: DecryptionKeyShare::PublicParameters,
    pub(super) scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    pub(super) message: GroupElement::Scalar,
    pub(super) public_key: GroupElement,
    pub(super) nonce_x_coordinate: GroupElement::Scalar,
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        DecryptionKeyShare,
    >
where
    Error: From<DecryptionKeyShare::Error>,
{
    /// The amortized threshold decryption party, which performs the heavy-lifting $$ O(n) $$ public
    /// decryption logic. An honest party would verify the signature and output it if and only if it
    /// is valid, otherwise (i.e. when `Error::SignatureVerification` is returned) requesting an
    /// identifiable abort protocol to be commenced.
    ///
    /// This function never returns an invalid signature, so that parties that receive an invalid
    /// signature can blame the decrypter.
    pub fn decrypt_signature(
        self,
        lagrange_coefficients: HashMap<PartyID, DecryptionKeyShare::LagrangeCoefficient>,
        partial_signature_decryption_shares: HashMap<PartyID, DecryptionKeyShare::DecryptionShare>,
        masked_nonce_decryption_shares: HashMap<PartyID, DecryptionKeyShare::DecryptionShare>,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)> {
        let decrypters: HashSet<_> = lagrange_coefficients.clone().into_keys().collect();
        if decrypters.len() != usize::from(self.threshold)
            || decrypters
                != partial_signature_decryption_shares
                    .keys()
                    .cloned()
                    .collect::<HashSet<_>>()
            || decrypters
                != masked_nonce_decryption_shares
                    .keys()
                    .cloned()
                    .collect::<HashSet<_>>()
        {
            return Err(Error::InvalidParameters);
        }

        let partial_signature: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            DecryptionKeyShare::combine_decryption_shares_semi_honest(
                partial_signature_decryption_shares,
                lagrange_coefficients.clone(),
                &self.decryption_key_share_public_parameters,
            )?
            .into();

        let group_order = GroupElement::Scalar::order_from_public_parameters(
            &self.scalar_group_public_parameters,
        );

        let group_order =
            Option::<_>::from(NonZero::new(group_order)).ok_or(Error::InternalError)?;

        let partial_signature = GroupElement::Scalar::new(
            partial_signature.reduce(&group_order).into(),
            &self.scalar_group_public_parameters,
        )?;

        let masked_nonce: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            DecryptionKeyShare::combine_decryption_shares_semi_honest(
                masked_nonce_decryption_shares,
                lagrange_coefficients,
                &self.decryption_key_share_public_parameters,
            )?
            .into();

        let masked_nonce = GroupElement::Scalar::new(
            masked_nonce.reduce(&group_order).into(),
            &self.scalar_group_public_parameters,
        )?;

        let inverted_masked_nonce = masked_nonce.invert();

        if inverted_masked_nonce.is_none().into() {
            return Err(Error::SignatureVerification);
        }

        let signature_s = inverted_masked_nonce.unwrap() * partial_signature;
        let negated_signature_s = signature_s.neg();

        // Attend to malleability.
        let signature_s = if negated_signature_s.value() < signature_s.value() {
            negated_signature_s
        } else {
            signature_s
        };

        verify_signature(
            self.nonce_x_coordinate,
            signature_s,
            self.message,
            self.public_key,
        )?;

        Ok((self.nonce_x_coordinate, signature_s))
    }

    // TODO: rename amortized party, perhaps to coordinator
    // TODO: must I get the party ID of the coordinator and blame it in case of error, or is it
    // sufficient to return the error and push that logic to implementors?

    /// The lightweight $$ O(1) $$ threshold decryption logic, which simply verifies the output of
    /// the decryption sent by the amortized party. Blames it in case of an invalid signature, and
    /// accepts otherwise.
    pub fn verify_decrypted_signature(
        self,
        signature_s: GroupElement::Scalar,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)> {
        verify_signature(
            self.nonce_x_coordinate,
            signature_s,
            self.message,
            self.public_key,
        )?;

        Ok((self.nonce_x_coordinate, signature_s))
    }
}
