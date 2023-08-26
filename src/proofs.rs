// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0
pub mod schnorr;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid Parameters")]
    InvalidParameters(),

    #[error("Invalid proof - didn't satisfy the proof equation")]
    ProofVerificationError(),
}

pub type Result<T> = std::result::Result<T, Error>;
