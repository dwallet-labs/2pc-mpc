# Detailed Explanation of Protocol 6: Signature Generation Protocol

## Overview

Protocol 6 describes the steps for generating a digital signature using a shared secret established previously. The
process involves multiple rounds of communication and computation between parties to securely generate a valid signature
on a given message.

## 1. Alice's Message:

### Step (a)

- **Compute:**
  $R = (k_A)^{-1} \cdot R_B = (k_A)^{-1} k_B \cdot G$
  and $r = R|_{x\text{-axis}} \mod q$; denote $k = k_A^{-1} k_B$.

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
  Sample: $\rho_2 \in \mathbb{R}_{pp}$  
  Compute: $U_A = \text{Com}(k_A; \rho_2)$

**Variables:**

- $\rho_2$: Random value chosen from a uniform distribution.
- $\text{Com}$: Commitment function.

**Purpose:**

- To create a commitment $U_A$ for $k_A$ using $\rho_2$, ensuring $k_A$ is not changed later.

### Step (c)

- **Set Values:**  
  $a_1 = r \cdot k_A + x_A + m \cdot k_A$  
  $a_2 = r \cdot k_A$

**Variables:**

- $r$: x-coordinate of $R$.
- $x_A$: Alice's private key share.
- $m$: Message to be signed.

**Purpose:**

- To compute intermediate values $a_1$ and $a_2$ for the signature generation.

### Step (d)

**Alice performs a homomorphic evaluation of the ciphertexts $\text{ct}\_1$ and $\text{ct}\_2$ using her private
function $f_A(x_1, x_2)$:**

1. **Private Function Definition:**  
   $f_A(x_1, x_2) := a_1 x_1 + a_2 x_2$  
   where $a_1$ and $a_2$ are coefficients previously computed by Alice.

2. **Homomorphic Evaluation:**
   $\text{ct}_A \leftarrow \text{AHE.Eval}(pk, f_A, \text{ct}_1, \text{ct}_2; \eta\_{\text{eval}})$

**Variables:**

- $\text{ct}_1, \text{ct}_2$: Ciphertexts of values.
- $f_A$: Alice's private function.
- $\eta_{\text{eval}}$: Randomness used for evaluation.

**Explanation:**

- **$\text{AHE.Eval}(pk, f_A, \text{ct}\_1, \text{ct}\_2; \eta\_{\text{eval}})$:** This function evaluates the encrypted
  ciphertexts $\text{ct}_1$ and $\text{ct}\_2$ using the public key $pk$ and the specified function $f_A$.
  The evaluation uses randomness $\eta\_{\text{eval}}$ to ensure security.
- **Output:** The result of this homomorphic evaluation is a new ciphertext $\text{ct}_A$ which represents the
  encrypted form of the value computed by the function $f_A(x_1, x_2)$.

**Purpose:**

- To perform homomorphic evaluation on the ciphertexts, ensuring computations are done securely without decrypting the
  values.

### Step (e) - Sending Proofs

**Explanation:**

Alice sends a series of proofs to various functionalities to ensure the integrity and correctness of the values and
computations involved in the signature generation process. These proofs are verified by the functionalities to maintain
the protocol's security.

**Variables:**

- **$\text{prove}$**: Operation indicating that Alice is providing a proof of knowledge or correctness.
- **$\text{sid}$**: Session identifier, uniquely identifying the current session of the protocol.
- **$\text{pid}\_A$**: Protocol identifier for Alice.
- **$K_A$**: Commitment to Alice's nonce.
- **$R_B$**: Bob's public value related to his nonce.
- **$k_A$**: Alice's nonce.
- **$\rho\_1$**: Randomness used in Alice's initial commitment.
- **$U_A$**: Commitment to Alice's nonce with additional randomness $\rho_2$.
- **$X_A$**: Alice's public key share.
- **$x_A$**: Alice's private key share.
- **$\rho_2$**: Additional randomness used in the commitment $U_A$.
- **$\text{ct}\_A$**: Ciphertext resulting from the homomorphic evaluation.
- **$C_1, C_2$**: Computed values used in the proofs.
- **$a_1, a_2$**: Intermediate values computed by Alice.
- **$r$**: x-coordinate of the combined nonce.
- **$m$**: Message to be signed.
- **$\eta$**: Randomness used in the evaluation.

**Explanation:**

1. **Sending Initial Proofs:**
    - **Proof 1:**  
      Alice sends $(\text{prove, sid, pid}_A, K_A, R_B; k_A, \rho_1)$ to $\mathcal{F}\_
      {\text{LDComDL}}\[\text{pp}, (\mathbb{G}, R, q)\]\_{zk}$.

    - **Proof 2:**
      $\text{prove, sid, pid}\_A, K_A, U_A, X_A; k_A, x_A, \rho_2$  
      Sent to $\mathcal{F}\_{\text{LDComRatio}}\[\mathbb{P}_{pp}, (\mathbb{G}, \mathbb{Q})\]_{zk}$.

**Purpose:**

- These proofs demonstrate that Alice's commitments $K_A$ and $U_A$ and the values $R_B$ and $X_A$ are
  correctly computed and related to her private nonce $k_A$ and public key share $x_A$. The proofs ensure the
  integrity of Alice's commitments and key shares.

2. **Computing $C_1$ and $C_2$:**
    - **Computation:**
      $
      C_1 = (r \circ U_A) \oplus (m \circ K_A)
      $
      $
      C_2 = r \circ K_A
      $

**Variables:**

- **$\circ$**: A cryptographic operation (e.g., point multiplication on an elliptic curve).
- **$\oplus$**: Another cryptographic operation (e.g., addition or XOR).

**Purpose:**

- $C_1$ and $C_2$ are computed values that combine Alice's commitments and the message $m$. These values are
  used to provide further proof of correctness in the protocol.

3. **Sending Final Proof:**
    - **Proof 3:**
      $
      \text{prove, sid, pid}_A, \text{ct}_A, C_1, C_2; a_1, a_2, r, \rho_2 + m \cdot \rho_1, r \cdot \rho_1, \eta
      $
      Sent to $\mathcal{F}_{\text{LDComEval}}[\mathbb{P}_{pp}, \mathbb{P}_{pk}, \mathbb{P}_{ct}_1, \mathbb{P}_{ct}_2]_
      {zk}$.

**Purpose:**

- This proof ensures that the homomorphic evaluation resulting in $\text{ct}_A$ is correct and that the values $
  C_1$ and $C_2$ are correctly computed based on the initial commitments and the message $m$. The proof
  includes intermediate values $a_1$ and $a_2$, as well as the randomness used in the evaluation.

### Summary:

In step (e), Alice sends a series of proofs to various ideal functionalities to ensure that her commitments, computed
values, and the resulting ciphertext from the homomorphic evaluation are all correct and consistent. These proofs are
essential for maintaining the protocol's integrity and security, as they allow Bob and any verifying party to trust that
Alice has followed the protocol correctly without revealing her private values.

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
    - Bob verifies that the values used in the proofs are consistent with previously known records (keygen, $
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
