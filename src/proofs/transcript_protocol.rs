// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;
use crypto_bigint::{Encoding, Limb, Uint};
use merlin::Transcript;
use serde::Serialize;

/// A transcript protocol for fiat-shamir transforms of interactive to non-interactive proofs.
pub(crate) trait TranscriptProtocol {
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
        let serialized_message = serde_json::to_string_pretty(message)?;

        self.append_message(label, serialized_message.as_bytes());

        Ok(())
    }

    fn append_uint<const LIMBS: usize>(&mut self, label: &'static [u8], value: &Uint<LIMBS>)
    where
        Uint<LIMBS>: Encoding,
    {
        self.append_message(label, Uint::<LIMBS>::to_le_bytes(value).as_ref());
    }

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS> {
        let mut buf: Vec<u8> = vec![0u8; LIMBS * Limb::BYTES];
        self.challenge_bytes(label, buf.as_mut_slice());

        Uint::<LIMBS>::from_le_slice(&buf)
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::{collections::HashMap, iter, marker::PhantomData};

    use criterion::{BatchSize, Criterion};
    use crypto_bigint::{Encoding, Uint};
    use rand_core::OsRng;

    use super::*;

    pub(crate) fn benchmark(c: &mut Criterion) {
        let mut g = c.benchmark_group("transcript");

        g.sample_size(10);

        let message = vec![42u8; 1];

        g.bench_function(
            format!("append_message() of 1000 independent bytes"),
            |bench| {
                bench.iter_batched(
                    || Transcript::new(b""),
                    |mut transcript| {
                        for _ in 0..1000 {
                            transcript.append_message(b"", &message)
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let messages: Vec<_> = iter::repeat(message.clone()).take(1000).collect();

        g.bench_function(
            format!("append_message() of 1000 bytes after combining"),
            |bench| {
                bench.iter_batched(
                    || Transcript::new(b""),
                    |mut transcript| {
                        transcript.append_message(
                            b"",
                            messages
                                .clone()
                                .into_iter()
                                .flatten()
                                .collect::<Vec<u8>>()
                                .as_slice(),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        for number_of_bytes in [1, 8, 16, 32, 1024] {
            let message = vec![42u8; number_of_bytes];

            g.bench_function(
                format!("clone Vec<u8> of {number_of_bytes} bytes"),
                |bench| {
                    bench.iter_batched(
                        || message.to_vec(),
                        |vec| vec.clone(),
                        BatchSize::SmallInput,
                    );
                },
            );

            g.bench_function(
                format!("append_message() over {number_of_bytes} bytes"),
                |bench| {
                    bench.iter_batched(
                        || Transcript::new(b""),
                        |mut transcript| transcript.append_message(b"", &message),
                        BatchSize::SmallInput,
                    );
                },
            );

            g.bench_function(
                format!("append_message() from Vec<u8> of {number_of_bytes} bytes"),
                |bench| {
                    bench.iter_batched(
                        || Transcript::new(b""),
                        |mut transcript| transcript.append_message(b"", &message),
                        BatchSize::SmallInput,
                    );
                },
            );

            // 2-4x slower than vec. Appears that serialization takes 1-3x times as append_message()
            g.bench_function(
                format!("serialize_to_transcript_as_json() over {number_of_bytes} bytes"),
                |bench| {
                    bench.iter_batched(
                        || Transcript::new(b""),
                        |mut transcript| transcript.serialize_to_transcript_as_json(b"", &message),
                        BatchSize::SmallInput,
                    );
                },
            );

            let mut transcript = Transcript::new(b"");
            transcript.append_message(b"", &message);

            for challenge_bytes in [1, 8, 16, 32, 1024] {
                let mut buf: Vec<u8> = vec![0u8; challenge_bytes];

                g.bench_function(format!("challenge_bytes() of {challenge_bytes} bytes from transcript with {number_of_bytes} bytes"), |bench| {
                    bench.iter_batched(
                        || {
                            let mut transcript = Transcript::new(b"");
                            transcript.append_message(b"", &message);

                            transcript
                        },
                        |mut transcript| transcript.challenge_bytes(b"", buf.as_mut_slice()),
                        BatchSize::SmallInput,
                    );
                });
            }
        }

        g.finish();
    }
}
