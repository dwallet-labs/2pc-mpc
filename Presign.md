# Summary of Protocol 5: Presigning $\Pi_{\text{pres}}$ (Protocol 5)

The presigning protocol involves multiple parties (A, $B_1, B_2, \ldots, B_n$) with the goal of generating a shared
random nonce $k$. The protocol uses public key $pk$ and ciphertext $ctkey$ as inputs, and it consists of
several rounds and messages exchanged between the parties.

## 1. Alice's Message:

(a) **Sampling and Commitment:**

- Alice samples a random $k_A$ from $Z_q$ and computes $K_A = \text{Com}(k_A; \rho_1)$.
- Alice sends $(\text{prove, sid, pid}\_A, K_A; k_A, \rho_1)$ to $\mathcal{F}\_{\text{LDCom}_{zk}}$.
- Can be found in [here](./src/presign/centralized_party/commitment_round.rs).

## 2. Bob's Message:

(a) **First Round:**

- (i) **Receive Commitment:**
    - $B_i$ receives $(\text{proof, sid, pid}\_A, K_A)$ from $\mathcal{F}\_{\text{LDCom}_{zk}}$. If not valid,
      it aborts.
- (ii) **Sample and Compute:**
    - $B_i$ samples $k_i \leftarrow Z_q^*$ and computes $R_i = k_i \cdot G$. Denote $k_B = \sum_i k_i$.
- (iii) **Generate AHE Components:**
    - $B_i$ samples $\gamma_i \leftarrow [0, q]$, and randomness $\eta_i$ for masks.
    - $\text{ct}_1 = \text{AHE.Enc}(pk, \gamma_i; \eta\_{\text{mask}_1})$.
    - $\text{ct}\_2 = \text{AHE.Eval}(pk, f_i, \text{ctkey}, \eta_{\text{mask}_2})$ where $f_i(x) = \gamma_i \cdot
      x$.
    - $\text{ct}_3 = \text{AHE.Enc}(pk, k_i; \eta\_{\text{mask}_3})$.
- (iv) **Send Proofs:**
    - $B_i$ sends $(\text{prove, sid} \| \gamma, \text{pid}_i, \text{ct}\_1, \text{ct}\_2; \gamma_i, \eta\_
      {\text{mask}\_1}, \eta\_{\text{mask}\_2})$ to $\mathcal{F}\_{\text{LEncDH}\[pk, \text{ctkey}\]}^{\text{agg-zk}}$.
- (v) **Send $R_i$ and $k_i$:**
    - $B_i$ sends $(\text{prove, sid, pid}_i, R_i, \text{ct}\_3; k_i, \eta\_{\text{mask}\_3})$ to
      $\mathcal{F}\_{\text{LEncDL}}^{\text{agg-zk}}$.
- Can be found in [here](./src/presign/decentralized_party/encrypted_masked_key_share_and_public_nonce_shares_round.rs).

(b) **Second Round:**

- (i) **Receive Proofs:**
    - $B_i$ receives $(\text{proof, sid} \| \gamma, \text{ct}\_1, \text{ct}\_2)$ from $\mathcal{F}\_
      {\text{LEncDH}\[pk, \text{ctkey}]}^{\text{agg-zk}}$ and $(\text{proof, sid, R, ct}\_3)$ from $\mathcal{F}_
      {\text{LEncDL}}^{\text{agg-zk}}$.
- (ii) **Malicious Check:**
    - If $B_i$ receives $(\text{malicious, sid, U'})$, it records the malicious parties and aborts.
- (iii) **Compute Combined Ciphertext:**
    - $B_i$ computes $\text{ct}_4 = \text{AHE.Eval}(pk, f_i', \text{ct}\_1, \eta\_{\text{mask}_4})$ where $f_i'(
      x) = k_i \cdot x$.
- (iv) **Send Proofs:**
    - $B_i$ sends $(\text{prove, sid} \| k, \text{pid}_i, \text{ct}_3, \text{ct}\_4; k_i, \eta\_{\text{mask}\_3},
      \eta\_{\text{mask}\_4})$ to $\mathcal{F}\_{\text{LEncDH}\[pk, \text{ct}_1]}^{\text{agg-zk}}$.

(c) **Proof Verification:**

- $B_i$ receives $(\text{proof, sid} \| k, \text{ct}_3, \text{ct}\_4)$ from
  $\mathcal{F}\_{\text{LEncDH}\[pk, \text{ct}_1\]}^{\text{agg-zk}}$. If valid, continues; otherwise, records the malicious
  parties and aborts.

Can be found in [here](./src/presign/decentralized_party/encrypted_masked_nonces_round.rs)

## 3. Alice's Verification:

(a) **Verify $R_B$ and $\text{ct}\_3$:**

- Alice receives $(\text{proof, sid, R}\_B, \text{ct}\_3)$ from $\mathcal{F}_{\text{LEncDL}}^{\text{agg-zk}}$. If
  valid, continues; otherwise, aborts.

(b) **Verify Combined Ciphertexts:**

- Alice receives $(\text{proof, sid, ct}_1, \text{ct}\_2)$ from $\mathcal{F}\_{\text{LEncDH}\[pk, \text{ctkey}]
  }^{\text{agg-zk}}$. If valid, continues; otherwise, aborts.

Can be found in [here](./src/presign/centralized_party/proof_verification_round.rs)

## 4. Output:

(a) **Alice Records:**

- Alice records $(\text{presign, sid, R}_B, \text{ct}_1, \text{ct}_2; k_A, \rho_1)$ where $\text{ct}_1$ and
  $\text{ct}_2$ are encryptions of $\gamma$ and $\gamma \cdot x_B$.

(b) **Bob Records:**

- Bob records $(\text{presign, sid, R}_B, K_A, \text{ct}_3, \text{ct}_4)$, where $\text{ct}_4$ encrypts
  $\gamma \cdot k_B \mod q$.

## Summary:

- **Rounds and Steps:**
    - **Alice:** Samples $k_A$, computes $K_A$, sends commitment and proof.
    - **Bob (First Round):** Receives commitment, samples $k_i$, computes $R_i$, generates AHE components, sends
      proofs.
    - **Bob (Second Round):** Receives proofs, checks for malicious activity, computes combined ciphertext, sends
      proofs.
    - **Proof Verification:** Both Alice and Bob verify each other's proofs.
    - **Output:** Both Alice and Bob record the necessary presign data.
- **Security:** Utilizes zero-knowledge proofs and commitment schemes to ensure integrity and prevent cheating.
- **Efficiency:** Aggregates proofs to minimize computational overhead.

This protocol ensures a secure and efficient presigning phase, crucial for the integrity of the subsequent key
generation and signing processes.

# Glossary for Protocol 5: Presigning Protocol

This glossary provides definitions for the variables and functions used in Protocol 5, which is the presigning phase of
the key generation process between multiple parties.

## Variables:

1. **$k_A$**:
    - **Definition:** A random integer sampled by Alice from the group $Z_q$.
    - **Role:** Used by Alice in the commitment process to generate $K_A$.

2. **$K_A$**:
    - **Definition:** Commitment generated by Alice.
    - **Formula:** $K_A = \text{Com}(k_A; \rho_1)$.
    - **Role:** Ensures Alice cannot change $k_A$ after committing to it.

3. **$\rho_1$**:
    - **Definition:** Randomness used by Alice in the commitment process.
    - **Role:** Adds security to the commitment $K_A$.

4. **$k_B$**:
    - **Definition:** Sum of random values $k_i$ sampled by each $B_i$ from the group $Z_q^*$.
    - **Formula:** $k_B = \sum_i k_i$.
    - **Role:** Used to compute the shared nonce $k$.

5. **$k_i$**:
    - **Definition:** Random integer sampled by each $B_i$ from the group $Z_q^*$.
    - **Role:** Individual contribution from each $B_i$ to the shared nonce $k_B$.

6. **$R_i$**:
    - **Definition:** Group element computed by each $B_i$.
    - **Formula:** $R_i = k_i \cdot G$.
    - **Role:** Part of the contribution from $B_i$ to the overall protocol.

7. **$R_B$**:
    - **Definition:** Sum of group elements $R_i$.
    - **Role:** Used in the signature protocol.

8. **$\gamma_i$**:
    - **Definition:** Random value sampled by each $B_i$.
    - **Role:** Used in the generation of AHE components.

9. **$\eta\_{\text{mask}\_1}, \eta\_{\text{mask}\_2}, \eta\_{\text{mask}\_3}, \eta\_{\text{mask}\_4}$**:
    - **Definition:** Random values used for masking during encryption.
    - **Role:** Adds security to the encryption process.

10. **$\text{ct}_1$**:
    - **Definition:** Ciphertext of $\gamma_i$ encrypted using AHE.
    - **Formula:** $\text{ct}_1 = \text{AHE.Enc}(pk, \gamma_i; \eta_{\text{mask}_1})$.

11. **$\text{ct}_2$**:
    - **Definition:** Ciphertext of $\gamma_i \cdot x_B$ evaluated using AHE.
    - **Formula:** $\text{ct}_2 = \text{AHE.Eval}(pk, f_i, \text{ctkey}, \eta_{\text{mask}_2})$.
    - **Function:** $f_i(x) = \gamma_i \cdot x$.

12. **$\text{ct}_3$**:
    - **Definition:** Ciphertext of $k_i$ encrypted using AHE.
    - **Formula:** $\text{ct}_3 = \text{AHE.Enc}(pk, k_i; \eta_{\text{mask}_3})$.

13. **$\text{ct}_4$**:
    - **Definition:** Combined ciphertext computed by each $B_i$.
    - **Formula:** $\text{ct}_4 = \text{AHE.Eval}(pk, f_i', \text{ct}_1, \eta_{\text{mask}_4})$.
    - **Function:** $f_i'(x) = k_i \cdot x$.

14. **$pk$**:
    - **Definition:** Public key used in the AHE scheme.
    - **Role:** Used for encryption and evaluation.

15. **$\text{ctkey}$**:
    - **Definition:** Ciphertext of the key used in the AHE scheme.
    - **Role:** Used in the evaluation of $\text{ct}_2$.

16. **$\mathcal{F}\_{\text{LDCom}\_{zk}}$**:
    - **Definition:** Functionality handling commitments and zero-knowledge proofs for discrete logarithms.
    - **Role:** Ensures commitments are valid and proofs are verified.

17. **$\mathcal{F}_{\text{LEncDH}\[pk, \text{ctkey}\]}^{\text{agg-zk}}$**:
    - **Definition:** Functionality handling encrypted discrete logarithms with aggregated zero-knowledge proofs.
    - **Role:** Verifies the encrypted commitments and their proofs.

18. **$\mathcal{F}\_{\text{LEncDL}}^{\text{agg-zk}}$**:
    - **Definition:** Functionality handling encrypted discrete logarithms with aggregated zero-knowledge proofs.
    - **Role:** Ensures that the encrypted values and their proofs are valid.

## Protocol Steps:

1. **Alice’s Message (Round 1):**
    - Alice commits to $k_A$ and sends $K_A$ and proof to $\mathcal{F}_{\text{LDCom}_{zk}}$.

2. **Bob’s Message (First Round):**
    - $B_i$ receives commitment, samples $k_i$, computes $R_i$, generates AHE components, and sends proofs
      to $\mathcal{F}_{\text{LEncDH}[pk, \text{ctkey}]}^{\text{agg-zk}}$ and $\mathcal{F}_
      {\text{LEncDL}}^{\text{agg-zk}}$.

3. **Bob’s Message (Second Round):**
    - $B_i$ receives proofs, checks for malicious activity, computes combined ciphertext, and sends proofs to \(
      \mathcal{F}_{\text{LEncDH}[pk, \text{ct}_1]}^{\text{agg-zk}}$.

4. **Proof Verification:**
    - Both Alice and Bob verify each other’s proofs using the functionalities.

5. **Output:**
    - Alice and Bob record the necessary presign data, ensuring they have consistent and valid commitments.

This glossary provides a detailed reference to the variables and functions used in Protocol 5, helping to understand the
roles and operations performed by each component in the presigning process.

# Explanation of $\mathcal{F}\_{\text{LDCom}\_{zk}}$

## Definition:

$\mathcal{F}_{\text{LDCom}\_{zk}}$ stands for the functionality of "Linear Decomposition Commitments with
Zero-Knowledge Proofs." This functionality is part of the cryptographic protocols that handle commitments and their
associated zero-knowledge proofs (ZKPs).

## Purpose:

The primary purpose of $\mathcal{F}\_{\text{LDCom}\_{zk}}$ is to securely manage the commitments made by parties and
to verify zero-knowledge proofs associated with those commitments. This functionality ensures that the commitments are
both binding and hiding, providing integrity and security to the protocol.

## Key Features:

1. **Commitment Handling:**
    - **Binding:** Once a value is committed, it cannot be changed. This ensures that the party who made the commitment
      cannot alter the value after seeing the commitments from other parties.
    - **Hiding:** The commitment does not reveal the committed value. This ensures that the value remains secret until
      the party chooses to reveal it.

2. **Zero-Knowledge Proofs:**
    - The functionality verifies zero-knowledge proofs provided by the parties. These proofs demonstrate that the party
      knows the value associated with the commitment without revealing the value itself.
    - Zero-knowledge proofs are crucial for maintaining the privacy and security of the committed values.

## Role in Protocol 5:

In Protocol 5 (Presigning Protocol), $\mathcal{F}\_{\text{LDCom}_{zk}}$ plays a critical role in the initial steps
where Alice commits to her random value $k_A$. Here’s how it works in the context of the protocol:

### Steps Involving $\mathcal{F}_{\text{LDCom}_{zk}}$:

1. **Alice’s Commitment:**
    - **Value Selection:** Alice selects a random value $k_A$ from the group $Z_q$.
    - **Compute Commitment:** Alice computes the commitment $K_A = \text{Com}(k_A; \rho_1)$, where $\rho_1$ is a
      random value used to add security to the commitment.
    - **Send Commitment and Proof:** Alice sends $(\text{prove, sid, pid}\_A, K_A; k_A, \rho_1)$ to $\mathcal{F}_
      {\text{LDCom}_{zk}}$. This message includes the commitment $K_A$ and a zero-knowledge proof that she
      knows $k_A$.

2. **Verification by $\mathcal{F}\_{\text{LDCom}\_{zk}}$:**
    - **Verify Commitment:** $\mathcal{F}_{\text{LDCom}\_{zk}}$ verifies that the commitment $K_A$ is correctly
      formed.
    - **Verify Zero-Knowledge Proof:** $\mathcal{F}_{\text{LDCom}\_{zk}}$ verifies the zero-knowledge proof provided
      by Alice, ensuring that she indeed knows the value $k_A$ without learning what $k_A$ actually is.

### Security and Integrity:

- **Commitment Scheme:** Ensures that once Alice commits to $k_A$, she cannot change it, providing binding.
- **Zero-Knowledge Proofs:** Ensure that Alice can prove knowledge of $k_A$ without revealing it, maintaining
  privacy and security.

## Summary:

$\mathcal{F}_{\text{LDCom}\_{zk}}$ is a crucial cryptographic functionality that manages commitments and their
zero-knowledge proofs. In Protocol 5, it ensures that Alice’s commitment to $k_A$ is secure and verifiable without
revealing $k_A$. This functionality provides the foundation for secure and private commitment schemes in the
protocol.
