// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear
pub mod range;
pub mod schnorr;
pub(crate) mod transcript_protocol;

pub use range::{bulletproofs, lightningproofs, RangeProof};
use transcript_protocol::TranscriptProtocol;

use crate::{ahe, group};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters")]
    InvalidParameters,

    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,

    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),

    #[error("unsupported repetitions: must be either 1 or 128")]
    UnsupportedRepetitions,

    #[error("invalid proof - did not satisfy the verification equation")]
    ProofVerification,

    #[error("group error")]
    GroupInstantiation(#[from] group::Error),

    #[error("additively homomorphic encryption scheme error")]
    AdditivelyHomomorphicEncryptionScheme(#[from] ahe::Error),

    #[error("schnorr proof aggregation protocol error")]
    AggregationProtocol(#[from] schnorr::aggregation::Error),

    #[error("range proof error")]
    Range(#[from] range::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
