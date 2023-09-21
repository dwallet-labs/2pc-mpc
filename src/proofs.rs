// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
mod range;
pub mod schnorr;

use crypto_bigint::{Encoding, Limb, Uint};
use merlin::Transcript;
use serde::Serialize;

use crate::{ahe, group};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters")]
    InvalidParameters,

    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid proof - did not satisfy the verification equation")]
    ProofVerification,

    #[error("range verification failure - the response is out of range")]
    ResponseOutOfRange,

    #[error("group error")]
    GroupInstantiation(#[from] group::Error),

    #[error("additively homomorphic encryption scheme error")]
    AdditivelyHomomorphicEncryptionScheme(#[from] ahe::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A transcript protocol for fiat-shamir transforms of interactive to non-interactive proofs.
trait TranscriptProtocol {
    fn serialize_to_transcript_as_json<T: Serialize>(
        &mut self,
        label: &'static [u8],
        message: &T,
    ) -> serde_json::Result<()>;

    fn append_uint<const LIMBS: usize>(&mut self, label: &'static [u8], value: &Uint<LIMBS>)
    where
        Uint<LIMBS>: Encoding;

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS>;
}

impl TranscriptProtocol for Transcript {
    fn serialize_to_transcript_as_json<T: Serialize>(
        &mut self,
        label: &'static [u8],
        message: &T,
    ) -> serde_json::Result<()> {
        let serialized_message = serde_json::to_vec(message)?;

        self.append_message(label, serialized_message.as_slice());

        Ok(())
    }

    fn append_uint<const LIMBS: usize>(&mut self, label: &'static [u8], value: &Uint<LIMBS>)
    where
        Uint<LIMBS>: Encoding,
    {
        self.append_message(label, Uint::<LIMBS>::to_le_bytes(value).as_mut());
    }

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS> {
        let mut buf: Vec<u8> = vec![0u8; LIMBS * Limb::BYTES];
        self.challenge_bytes(label, buf.as_mut_slice());

        Uint::<LIMBS>::from_le_slice(&buf)
    }
}
