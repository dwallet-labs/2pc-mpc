// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use group::PartyID;
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
};

use crate::Error;

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
> {
    pub(super) threshold: PartyID,
    pub(super) decryption_key_share_public_parameters: DecryptionKeyShare::PublicParameters,
    pub(super) encrypted_partial_signature: EncryptionKey::CiphertextSpaceGroupElement,
    pub(super) encrypted_masked_nonce_share: EncryptionKey::CiphertextSpaceGroupElement,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    > Party<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey, DecryptionKeyShare>
where
    Error: From<DecryptionKeyShare::Error>,
{
    pub fn identify_malicious_decrypters(
        self,
        lagrange_coefficients: HashMap<PartyID, DecryptionKeyShare::LagrangeCoefficient>,
        partial_signature_decryption_shares: HashMap<PartyID, DecryptionKeyShare::DecryptionShare>,
        masked_nonce_decryption_shares: HashMap<PartyID, DecryptionKeyShare::DecryptionShare>,
        signature_partial_decryption_proofs: HashMap<
            PartyID,
            DecryptionKeyShare::PartialDecryptionProof,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Error {
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
            return Error::InvalidParameters;
        }

        let provers: HashSet<_> = signature_partial_decryption_proofs
            .clone()
            .into_keys()
            .filter(|pid| decrypters.contains(pid))
            .collect();

        let mut unresponsive_parties: Vec<PartyID> =
            decrypters.difference(&provers).cloned().collect();

        unresponsive_parties.sort();

        if !unresponsive_parties.is_empty() {
            return Error::UnresponsiveParties(unresponsive_parties);
        }

        // safe to unwrap as we've checked the keys of the maps all exists.
        let decryption_shares_and_proofs = decrypters
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    (
                        vec![
                            partial_signature_decryption_shares
                                .get(&party_id)
                                .unwrap()
                                .clone(),
                            masked_nonce_decryption_shares
                                .get(&party_id)
                                .unwrap()
                                .clone(),
                        ],
                        signature_partial_decryption_proofs
                            .get(&party_id)
                            .unwrap()
                            .clone(),
                    ),
                )
            })
            .collect();

        DecryptionKeyShare::combine_decryption_shares(
            vec![
                self.encrypted_partial_signature,
                self.encrypted_masked_nonce_share,
            ],
            decryption_shares_and_proofs,
            lagrange_coefficients,
            &self.decryption_key_share_public_parameters,
            rng,
        )
        .err()
        .map(Error::from)
        .unwrap_or(Error::InternalError)
    }
}
