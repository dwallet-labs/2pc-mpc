# 2pc-mpc

This crate is the official pure-Rust implementation of
the ["2PC-MPC: Emulating Two Party ECDSA in Large-Scale MPC"](https://eprint.iacr.org/2024/253) paper by

- Offir Friedman, dWallet Labs
- Avichai Marmor, dWallet Labs
- Dolev Mutzari, dWallet Labs
- Omer Sadika, dWallet Labs
- Yehonatan C. Scaly, dWallet Labs
- Yuval Spiizer, dWallet Labs
- Avishay Yanai, dWallet Labs.

It provides the distributed key generation (`dkg`), `presign` and `sign` protocols for multiparty ECDSA under the novel
2PC-MPC access structure: a two-party ECDSA where the second party is fully emulated by a network of `n` parties.
Designed with the use case of _dWallets_ in mind, where a user signs transactions with a massively decentralized
network [the dWallet Network](https://dwallet.io), the _2PC_ protocol is:

- non-collusive: both the centralized party (the user) and (a threshold) of the decentralized party (network) are
  required to participate in signing, while abstracting away the internal structure of the decentralized party.
- locality: centralized party is `O(1)`: communication and computation complexities of the client remain independent of
  the network properties (e.g., size).
  > Not fully implemented due to a restriction in `bulletproofs`, which are not actually aggregatable range proofs.
  It Will be fixed in the future.

The _MPC_ protocol, where the decentralized party emulates the second party in the _2PC_ protocol, is:

- UC secure: meaning it is secure for composition with other UC protocols and allows multiple sessions to execute in
  parallel.
- broadcast-only: no P2P/unicast communication, instead this protocol assumes a reliable broadcast channel exclusively.
- identifiable abort: malicious behavior aborts the protocol identifiably, which is extremely important
  for use-cases where there is no trust between the parties so that no party can deny (DOS) the ability to sign in
  multiparty without being identified.
- publicly verifiable: a session's result, whether it terminates in a successful output or in an identifiable abort, can
  be cryptographically verified publicly, so anyone (even if they are not a party in the protocol) can verify the
  result from that session's transcript, containing the (signed) messages sent by all parties in that session.
- scalable & massively-decentralized:
    - O(n) communication: linear-scaling in communication.
    - practically O(1) in computation: due to novel aggregation & amortization techniques, the amortized cost per-party
      remains constant up to *thousands of parties*.

> Note: this protocol can easily be used as a traditional Threshold ECDSA protocol by emulating a centralized party
> with `0` secrets.

# Security

We have gone through a rigorous internal auditing process throughout development, requiring the approval of two
additional cryptographers and one additional programmer in every pull request.
That being said, this code has not been audited by a third party yet; use it at your own risk.

# Releases

This code has no official releases yet, and we reserve the right to change some of the public API until then.

# Glossary

- Centralized Party is a client (user) that holds a secret key share.
- Decentralized Party is a network of parties that hold secret key shares.
- 2PC is a two-party computation protocol where the second party is emulated by a network of parties.
- MPC is a multiparty computation protocol where the network emulates the second party in the 2PC protocol.
- sid = session id.
- pid = party (public) id.

## The Two-Party Protocol




