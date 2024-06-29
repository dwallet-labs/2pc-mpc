# Detailed Explanation of Protocol 6: Signature Generation Protocol

## Overview

Protocol 6 describes the steps for generating a digital signature using a shared secret established previously. The
process involves multiple rounds of communication and computation between parties to securely generate a valid signature
on a given message.

## 1. Alice's Message:

### Step (a)

- **Compute:**
  $$R = (k_A)^{-1} \cdot R_B = (k_A)^{-1} k_B \cdot G$$
  where $r = R|_{x\text{-axis}} \mod q$ and denote $k = k_A^{-1} k_B$.

**Variables:**

- $k_A, k_B$: Nonce values chosen by Alice and Bob respectively.
- $G$: Generator of the group.
- $q$: A large prime number.
- $r$: The x-coordinate of $R$ modulo $q$.
- $k$: Product of inverse of $k_A$ and $k_B$.

**Purpose:**

- To calculate the shared nonce $R$ and its x-coordinate $r$, which is part of the signature.

### Step (b)

- **Sample and Compute:**
  $$
  \rho_2 \in \mathbb{R}_{pp}
  $$
  $$
  U_A = \text{Com}(k_A; \rho_2)
  $$

**Variables:**

- $\rho_2$: Random value chosen from a uniform distribution.
- $\text{Com}$: Commitment function.

**Purpose:**

- To create a commitment $U_A$ for $k_A$ using $\rho_2$, ensuring $k_A$ is not changed later.

### Step (c)

- **Set Values:**
  $$
  a_1 = r \cdot k_A + x_A + m \cdot k_A
  $$
  $$
  a_2 = r \cdot k_A
  $$

**Variables:**

- $r$: x-coordinate of $R$.
- $x_A$: Alice's private key share.
- $m$: Message to be signed.

**Purpose:**

- To compute intermediate values $a_1$ and $a_2$ for the signature generation.

### Step (d)

- **Homomorphically Evaluate:**
  $$
  a_1 x_1 + a_2 x_2
  $$
  $$
  \text{ct}_A = \text{AHE.Eval}(pk, f_A, \text{ct}_1, \text{ct}_2; \eta_{\text{eval}})
  $$

**Variables:**

- $\text{ct}_1, \text{ct}_2$: Ciphertexts of values.
- $f_A$: Alice's private function.
- $\eta_{\text{eval}}$: Randomness used for evaluation.

**Purpose:**

- To perform homomorphic evaluation on the ciphertexts, ensuring computations are done securely without decrypting the
  values.

### Step (e)

- **Send Proofs:**
    - Alice sends the following proofs:
      $$
      (\text{prove, sid, pid}_A, K_A, R_B; k_A, \rho_1) \text{ to } \mathcal{F}_
      {\text{LDComDL}}[\mathbb{R}_{pp}, \mathbb{G}, \mathbb{Q}]
      $$
      $$
      (\text{prove, sid, pid}_A, K_A, U_A, X_A; k_A, x_A, \rho_2) \text{ to } \mathcal{F}_
      {\text{LDComRatio}}[\mathbb{P}_{pp}, (\mathbb{G}, \mathbb{Q})]_{zk}
      $$
      $$
      (\text{prove, sid, pid}_A,
      \text{ct}_A, C_1, C_2; a_1, a_2, r, \rho_2 + m \cdot \rho_1, r \cdot \rho_1, \eta) \text{ to } \mathcal{F}_
      {\text{LDComEval}}[\mathbb{P}_{pp}, \mathbb{P}_{pk}, \mathbb{P}_{ct}_1, \mathbb{P}_{ct}_2]_{zk}
      $$

**Variables:**

- $\mathcal{F}_{\text{LDComDL}}, \mathcal{F}_{\text{LDComRatio}}, \mathcal{F}_{\text{LDComEval}}$: Ideal
  functionalities handling commitments and zero-knowledge proofs.
- $K_A, R_B, U_A, X_A$: Commitments and values being proved.
- $C_1, C_2$: Computed values used in the proofs.

**Purpose:**

- To send the necessary proofs to the ideal functionalities, ensuring the integrity and correctness of the computations.

## 2. Bob’s Verification and Output:

### Step (a)

- **Verification of Proofs:**
    - Bob receives and verifies the following proofs:
      $$
      (\text{proof, sid} \| \text{pid}_A, K_A, R_B) \text{ from } \mathcal{F}_
      {\text{LDComDL}}[\mathbb{P}_{pp}, \mathbb{G}, \mathbb{Q}]
      $$
      $$
      (\text{proof, sid} \| \text{pid}_A, K_A, U_A, X_A) \text{ from } \mathcal{F}_
      {\text{LDComRatio}}[\mathbb{P}_{pp}, (\mathbb{G}, \mathbb{Q})]_{zk}
      $$
      $$
      (\text{proof, sid} \| \text{pid}_A, \text{ct}_A, C_1, C_2) \text{ from } \mathcal{F}_
      {\text{LDComEval}}[\mathbb{P}_{pp}, \mathbb{P}_{pk}, \mathbb{P}_{ct}_1, \mathbb{P}_{ct}_2]_{zk}
      $$

**Variables:**

- Bob verifies the received proofs to ensure they are consistent with the values obtained previously.

**Purpose:**

- To ensure that Alice’s commitments and computations are valid and consistent with the agreed protocol.

### Step (b)

- **Validation of Values:**
    - Bob verifies that the values used in the proofs are consistent with previously known records (keygen, \(
      X_A$, $X$, $\text{ctkey}$, $pk$) and presign data ($R_B, K_A, U_A$).

### Step (c)

- **Decryption and Computation:**
    - Bob sends:
      $$
      (\text{decrypt, pk, ct}_A) \text{ and } (\text{decrypt, pk, ct}_4) \text{ to } \mathcal{F}_{\text{AHE}}
      $$
    - Bob waits for responses:
      $$
      \text{Let the responses be } (\text{decrypted, pk, ct}_A, pt_4, U_A)
      $$
        - If $pt_4 = \bot$ or $pt_4 = \bot$, aborts.
        - Otherwise, computes:
          $$
          s' = pt_4 - \gamma \cdot \text{mod } q
          $$
          $$
          s' = min \{ s', q - s' \}
          $$

**Variables:**

- $pt_4$: Plaintext value decrypted from $ct_4$.
- $s'$: Intermediate signature value.

**Purpose:**

- To decrypt the ciphertexts and compute the intermediate signature value $s'$, ensuring it is within the valid
  range.

## 3. Output:

- **Final Signature:**
    - Bob outputs the signature $(r, s)$, where $s = min \{ s', q - s' \}$.

**Variables:**

- $r$: x-coordinate of the combined nonce.
- $s$: Final signature value.

**Purpose:**

- To produce the final digital signature on the message, ensuring its validity and security.

## Summary:

Protocol 6 describes a secure multi-party process for generating a digital signature. The process involves multiple
rounds of commitments, computations, and verifications to ensure the signature is generated collaboratively and verified
correctly. Each step is designed to maintain the security and integrity of the signature generation process using
cryptographic techniques like homomorphic encryption and zero-knowledge proofs.
