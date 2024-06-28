# The Two-Party Protocol

## Key Generation for ECDSA

Two-party key generation process for Elliptic Curve Digital Signature Algorithm (ECDSA). The goal
is to securely generate a shared key between two parties, Alice (A) and Bob (B), ensuring that neither party can cheat
nor change their input once they have seen the other’s contribution. Here’s a step-by-step summary:

1. **Initial Setup:**
    - Both parties hold a common session identifier and have public identities.

2. **Alice’s Initial Steps:**
    - Alice selects a random integer $x_A$ from the group $Z_q$ and computes $X_A = x_A \cdot G$, where $G$ is a
      generator of the group.
    - She sends a commitment and proof of $x_A$ to a functionality $FLDL$, ensuring that she cannot change $x_A$ later.
      denoted as: $(com–prove, pid_A, X_A; x_A)$ to $FLDL$.
      > - **Message Structure:** The message sent to $FLDL$ is structured as follows:
          - `com-prove`: Indicates the operation being performed (commitment and proof).
          - `pid_A`: A unique identifier for Alice in the protocol.
          - `X_A`: The commitment value computed from $x_A$.
          - `x_A`: The original value (not sent directly but used in constructing the proof).

3. **Bob’s Initial Steps:**
    - Bob receives Alice’s commitment receipt.
    - He selects his own random integer $x_B$ from $Z_q$ and computes $X_B = x_B \cdot G$.
    - Bob generates a public-private key pair $(pk, sk)$ for additively homomorphic encryption (AHE) and encrypts
      his secret share $x_B$ into a ciphertext $ctkey$.
    - He sends his computed values and proofs to functionalities $FLGenAHE$ and $FLEncDL$ to verify their
      validity: $(prove, pid_B, pk; aux)$ to $FLGenAHE$ and $(prove, pid_B, X_B, ctkey; x_B, \eta)$ to $FLEncDL$.
      > aux: Auxiliary information, or "aux," refers to additional data or parameters that may be necessary to support
      the execution of cryptographic operations or protocols.
      > $\eta$: A random value used in the encryption process to ensure the security of the ciphertext.
      > Bob encrypts his secret value $x_B$ and sends the ciphertext $ctkey$ along with a zero-knowledge proof
      that he knows $x_B$.
      > $FLEncDL$ ensures that the proof is valid and verifies Bob's knowledge of $x_B$ without revealing $x_B$ itself.
      > Bob uses $FLGenAHE$ to generate a public-private key pair for additively homomorphic encryption (AHE).
      > The public key $pk$ and private key $sk$ are securely generated and shared as needed.

4. **Alice’s Verification:**
    - Alice receives the proofs from Bob regarding $X_B$ and $ctkey$. If these proofs are valid, she proceeds;
      otherwise, she aborts the process.
    - Alice then decommits her $X_A$ and sends its proof to Bob via $FLDL$.

5. **Bob’s Verification:**
    - Bob verifies Alice’s decommitment and proof. If the verification is successful, he proceeds; otherwise, he aborts
      the process.

6. **Key Generation Completion:**
    - Both Alice and Bob compute the shared ECDSA verification key $X = X_A + X_B = (x_A + x_B) \cdot G$.
    - They also retain important public values $X_A, X_B, pk,$ and $ctkey$, with Bob keeping his decryption
      key $sk$ as well.

### Key Points:

- **Commitments and Zero-Knowledge Proofs:** These are used to ensure neither party can change their input after seeing
  the other’s contribution, maintaining the integrity and security of the key generation process.
- **Additively Homomorphic Encryption (AHE):** This allows Bob to encrypt his share securely and proves that the
  encryption is valid.
- **Decommitment:** Alice decommits her value $X_A$ to prove to Bob that her initial commitment was valid.

This protocol ensures a fair and secure process for generating a shared ECDSA key between two parties, leveraging
cryptographic techniques to maintain privacy and integrity.

### $FLGenAHE$

#### Purpose:

- **Key Generation for Additively Homomorphic Encryption (AHE):** This functionality handles the generation of public
  and private keys used in additively homomorphic encryption schemes.

#### Steps:

- **Input:** Party identifiers, session identifiers, and any required auxiliary information.
- **Output:** A public key $pk$ and corresponding private key $sk$.
- **Verification:** Ensures that the generated keys are valid and secure.

### $FLEncDL$

#### Purpose:

- **Encryption and Proof of Knowledge of Discrete Logarithm:** This functionality handles the encryption of values and
  provides zero-knowledge proofs that a party knows the discrete logarithm of a group element.

#### Steps:

- **Input:**
    - $pid_B$: Party identifier for Bob.
    - $X_B$: Group element corresponding to Bob's random value.
    - $ctkey$: Ciphertext of Bob’s secret value $x_B$ encrypted using the public key $pk$.
    - $x_B$, $\eta$: Bob's secret value and any randomness used in the encryption process.
- **Output:** A zero-knowledge proof that $x_B$ is the discrete logarithm of $X_B$.

# 2PCMPC

## Explanation of DKG Protocol 4

**DKG Protocol 4** (Distributed Key Generation Protocol 4) is detailed in the context of the ECDSA group description (G,
G, q). It involves interactions between $n+1$ parties: a primary party $A$ and $n$ secondary parties $B1, ..., Bn$. Each
party holds the public key (pk) as input, and the protocol proceeds with the following steps:

### Protocol Steps

1. **A's First Message:**
    - **Random Sampling:** Party A samples a random $x_A \in Z_q$ and computes $X_A = x_A \cdot G$.
    - **Commit-Prove:** Party A sends a commit-prove message $(com-prove, pid_A, X_A; x_A)$ to $F_{LDL}^{com-zk}$.
    - Can be found in [here](./src/dkg/centralized_party/commitment_round.rs).

2. **Bi's First Message:**
    - **Receipt:** Each party $Bi$ receives a receipt $(receipt, pid_A)$ from $F_{LDL}^{com-zk}$.
    - **Random Sampling:** Each $Bi$ samples a random $x_i \in Z_q$ and computes $X_i = x_i \cdot G$.
    - **Key Generation (First Execution Only):** Each $Bi$ sends a $(keygen, sid)$ message to $F_{TAHE}$ and
      waits for a response. If the response is $(pubkey, sid, ⊥, U' \cap U)$, the protocol outputs $U' \cap U$
      and aborts. If the response is $(pubkey, sid, pk)$, the protocol continues.
    - **Encryption:** Each $Bi$ computes $ct_i = AHE.Enc(pk, x_i; \rho_i)$ for a randomly chosen $\rho_i$.
    - **Prove:** Each $Bi$ sends a prove message $(prove, sid, pid_i, X_i, ct_i; x_i, \rho_i)$ to $F_
      {LEncDL}^{agg-zk}$.
    - **Aggregate Proofs:** Each $B_i$ receives the aggregated proof $(proof, sid, X_B, ctkey)$ from
      $F_{LEncDL}^{agg-zk}$.
      If the proof is not received, they get the set of corrupted parties and abort.

3. **A's Second Message:**
    - **Proof Receipt:** Party A receives $(proof, sid, X_B, ctkey)$ from $F_{LEncDL}^{agg-zk}$, implicitly
      receiving pk as part of the public parameters of language $L_{EncDL}$.
    - **Certification:** Party A sends a $(certify, pk)$ message to $F_{TAHE}$ and waits for a response. If the
      response is 1, the protocol continues; otherwise, it aborts.
    - **Decommit-Proof:** Party A sends a decommit-proof message $(decom-proof, pid_A)$ to $F_{LDL}^{com-zk}$.

4. **Bi's Verification:**
    - **Proof Receipt:** Each $Bi$ receives a decommit-proof message $(decom-proof, pid_A, X_A)$ from $F_
      {LDL}^{com-zk}$. If not received, the protocol aborts.

5. **Output:**
    - **A's Output:** Party A outputs $X = X_A + X_B$ and records $(keygen, X_B, X, ctkey, pk)$.
    - **Bi's Output:** Each $Bi$ outputs $X = X_A + X_B$ and records $(keygen, X_A, X, ctkey, pk)$.

### Security

Theorem 2.4 states that achieving G*-simulatability is sufficient for ensuring UC security for a threshold signature as
defined in the protocol.

**References:**

- The details of the protocol are elaborated in the document sections on Key Generation Protocols, specifically under
  Protocol 4 in the provided PDF【7:1†source】【7:2†source】.
