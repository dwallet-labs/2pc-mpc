// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0
use crypto_bigint::{Limb, Uint};
use merlin::Transcript;
use serde::Serialize;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid Parameters")]
    InvalidParameters(),

    #[error("Invalid proof - didn't satisfy the proof equation")]
    ProofVerificationError(),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A transcript protocol for fiat-shamir transforms of interactive to non-interactive proofs.
trait TranscriptProtocol {
    fn serialize_to_transcript_as_json<T: Serialize>(
        &mut self,
        label: &'static [u8],
        message: &T,
    ) -> serde_json::Result<()>;

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

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS> {
        let mut buf: Vec<u8> = vec![0u8; LIMBS * Limb::BYTES];
        self.challenge_bytes(label, buf.as_mut_slice());

        Uint::<LIMBS>::from_le_slice(&buf)
    }
}
