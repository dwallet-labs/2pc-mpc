// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use group::PartyID;
pub mod dkg;
pub mod presign;
pub mod sign;

/// 2PC-MPC error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("commitment error")]
    Commitment(#[from] commitment::Error),
    #[error("homomorphic encryption error")]
    HomomorphicEncryption(#[from] homomorphic_encryption::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("maurer error")]
    Maurer(#[from] maurer::Error),
    #[error("enhanced maurer error")]
    EnhancedMaurer(#[from] enhanced_maurer::Error),
    #[error("tiresias error")]
    Tiresias(#[from] tiresias::Error),
    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),
    #[error("parties {:?} sent mismatching encrypted masks in the first and second proof aggregation protocols in the presign protocol", .0)]
    MismatchingEncrypedMasks(Vec<PartyID>),
    #[error("the other party maliciously attempted to bypass the commitment round by sending decommitment which does not match its commitment")]
    WrongDecommitment,
    #[error("signature failed to verify")]
    SignatureVerification,
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

/// 2PC-MPC result.
pub type Result<T> = std::result::Result<T, Error>;

pub const CENTRALIZED_PARTY_ID: PartyID = 1;
pub const DECENTRALIZED_PARTY_ID: PartyID = 2;

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use crypto_bigint::Uint;
    use group::secp256k1;
    use proof::range::bulletproofs::RANGE_CLAIM_BITS;

    pub const RANGE_CLAIMS_PER_SCALAR: usize =
        Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS / RANGE_CLAIM_BITS;
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(benches, sign::benchmark);
