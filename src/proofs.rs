// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod range;
pub mod schnorr;
pub(crate) mod transcript_protocol;

// pub use range::{bulletproofs, lightningproofs}; // TODO
use transcript_protocol::TranscriptProtocol;

use crate::{ahe, group};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters")]
    InvalidParameters,

    #[error("conversion error")]
    Conversion,

    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid proof - did not satisfy the verification equation")]
    ProofVerification,

    #[error("group error")]
    GroupInstantiation(#[from] group::Error),

    #[error("additively homomorphic encryption scheme error")]
    AdditivelyHomomorphicEncryptionScheme(#[from] ahe::Error),

    #[error("bulletproofs error")]
    Bulletproofs(#[from] bulletproofs::ProofError),

    #[error("schnorr proof aggregation protocol error")]
    AggregationProtocol(#[from] schnorr::aggregation::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
