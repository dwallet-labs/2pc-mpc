# Detailed Explanation of Protocol 6: Signature Generation Protocol

## Overview

Protocol 6 describes the steps for generating a digital signature using a shared secret established previously. The
process involves multiple rounds of communication and computation between parties to securely generate a valid signature
on a given message.

## 1. Alice's Message

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

Alice sends a series of proofs to various functionalities to ensure the integrity and correctness of the values and
computations involved in the signature generation process. These proofs are verified by the functionalities to maintain
the protocol's security.

1. **Sending Initial Proofs:**
    - **Explanation:**

        - **Proof 1:**  
          Alice sends $(\text{prove, sid, pid}_A, K_A, R_B; k_A, \rho_1)$ to $\mathcal{F}\_
          {\text{LDComDL}}\[\text{pp}, (\mathbb{G}, R, q)\]\_{zk}$.

        - **Proof 2:**  
          Alice sends $(\text{prove, sid, pid}\_A, K_A, U_A, X_A; k_A, x_A, \rho_1, \rho_2)$ to $\mathcal{F}_
          {\text{LDComRatio}}\[\text{pp}, (\mathbb{G}, G, q)\]_{zk}$.

    - **Variables:**
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
        - **$a_1, a_2$**: Intermediate values computed by Alice.
        - **$r$**: x-coordinate of the combined nonce.
        - **$m$**: Message to be signed.
        - **$\eta$**: Randomness used in the evaluation.

    - **Purpose:**
        - These proofs demonstrate that Alice's commitments $K_A$ and $U_A$ and the values $R_B$ and $X_A$ are
          correctly computed and related to her private nonce $k_A$ and public key share $x_A$. The proofs ensure the
          integrity of Alice's commitments and key shares.

2. **Computing and Sending $C_1$ and $C_2$**

   Alice computes two values, $C_1$ and $C_2$, which are used to provide further proof of
   correctness in the protocol. These values are then sent along with additional proofs to ensure the integrity and
   correctness of the computations.

    - **Computation and Sending:**

        1. **Computing $C_1$ and $C_2$:**
            - **Computation of $C_1$:**
              $C_1 = (r \circ U_A) \oplus (m \circ K_A)$
            - **Computation of $C_2$:**
              $C_2 = r \circ K_A$

        2. **Sending Proofs:**
            - Alice sends:
              $(\text{prove, sid, pid}_A, \text{ct}_A, C_1, C_2; a_1, a_2, r \cdot \rho_2 + m \cdot \rho_1, r \cdot
              \rho_1, \eta)$
           - To: $\mathcal{F}_{\text{LDComEval}}\[\text{pp}, pk, \text{ct}_1, \text{ct}_2\]\_{zk}$

    - **Variables:**
        - **$r$**: x-coordinate of the combined nonce $R$.
        - **$U_A$**: Commitment to Alice's nonce with additional randomness $\rho_2$.
        - **$K_A$**: Commitment to Alice's nonce.
        - **$m$**: Message to be signed.
        - **$\circ$**: A cryptographic operation (e.g., point multiplication on an elliptic curve).
        - **$\oplus$**: Another cryptographic operation (e.g., addition or XOR).
        - **$\text{ct}_A$**: Ciphertext resulting from the homomorphic evaluation.
        - **$a_1, a_2$**: Intermediate values computed by Alice.
        - **$\rho_2$**: Additional randomness used in the commitment $U_A$.
        - **$\rho_1$**: Randomness used in Alice's initial commitment.
        - **$\eta$**: Randomness used in the evaluation.
        - **$C_1, C_2$**: Computed values used in the proofs.

    - **Purpose:**

        - **Computation of $C_1$ and $C_2$:**
            - **$C_1$:** Combines $r$ with the commitment $U_A$ and the message $m$ with the commitment $K_A$, ensuring
              that
              the final value incorporates both the nonce and the message.
            - **$C_2$:** Combines $r$ directly with the commitment $K_A$, ensuring the consistency of the nonce and
              the commitment.

        - **Sending Proofs:**
            - The proofs ensure that the computations resulting in $\text{ct}_A$, $C_1$, and $C_2$ are correct and
              consistent with the previously committed values and the message $m$. The inclusion of $a_1$, $a_2$,
              $r \cdot \rho_2 + m \cdot \rho_1$, $r \cdot \rho_1$, and $\eta$ in the proof provides all the necessary
              intermediate values and randomness used in the computations, allowing the functionality to verify the
              correctness
              without revealing Alice's private values.

    - **Summary:**
      In this step, Alice computes two values $C_1$ and $C_2$ that combine her nonce commitments and the message to be
      signed. She then sends these values along with additional proofs to the ideal functionality
      $\mathcal{F}_{\text{LDComEval}}$. This process ensures the integrity and correctness of the computations,
      maintaining the security of the protocol while allowing Bob and any verifying party to trust that Alice has
      followed the protocol correctly.

## 2 - Bob's Verification and Output

### Step (a)

**Explanation:**
Bob receives and verifies a series of proofs from Alice to ensure the integrity and correctness of the values and
computations involved in the signature generation process. If any of the proofs are invalid or not received, Bob aborts
the protocol.

#### Variables and Functions Used:

- **$\text{proof}$**: Indicates that Alice is providing a proof of knowledge or correctness.
- **$\text{sid}$**: Session identifier, uniquely identifying the current session of the protocol.
- **$\text{pid}_A$**: Protocol identifier for Alice.
- **$K_A$**: Commitment to Alice's nonce.
- **$R_B$**: Bob's public value related to his nonce.
- **$U_A$**: Commitment to Alice's nonce with additional randomness $\rho_2$.
- **$X_A$**: Alice's public key share.
- **$\text{ct}\_A$**: Ciphertext resulting from the homomorphic evaluation.
- **$C_1, C_2$**: Computed values used in the proofs.
- **$\mathcal{F}\_{\text{LDComDL}}\[\mathbb{P}\_{pp}, (\mathbb{G}, R, q)]\_{zk}$**: Ideal functionality handling
  commitments and zero-knowledge proofs for discrete logarithms.
- **$\mathcal{F}\_{\text{LDComRatio}}[\mathbb{P}\_{pp}, (\mathbb{G}, G, q)\]\_{zk}$**: Ideal functionality handling
  commitments and zero-knowledge proofs for ratios.
- **$\mathcal{F}\_{\text{LDComEval}}\[\mathbb{P}\_{pp}, pk, \text{ct}\_1, \text{ct}\_2]\_{zk}$**: Ideal functionality
  handling commitments and zero-knowledge proofs for evaluations.

#### Proofs Received by Bob:

1. **Proof from $\mathcal{F}\_{\text{LDComDL}}\[\mathbb{P}\_{pp}, (\mathbb{G}, R, q)]\_{zk}$:**
    - **Proof Content:**  
      $(\text{proof, sid} \| \text{pid}_A, K_A, R_B)$

   **Purpose:**

    - This proof ensures that the commitments $K_A$ and $R_B$ are correctly related to Alice's nonce $k_A$ and
      the randomness $\rho_1$. This maintains the integrity of Alice's commitment and the correctness of the public
      value $R_B$.

2. **Proof from $\mathcal{F}\_{\text{LDComRatio}}\[\mathbb{P}\_{pp}, (\mathbb{G}, G, q)\]\_{zk}$:**
    - **Proof Content:**  
      $(\text{proof, sid} \| \text{pid}_A, K_A, U_A, X_A)$

   **Purpose:**

    - This proof ensures that the commitments $K_A$, $U_A$, and $X_A$ are correctly related to Alice's nonce $
      k_A$ and private key share $x_A$. This verifies the integrity of Alice's key shares and the correctness of the
      commitments.

3. **Proof from $\mathcal{F}\_{\text{LDComEval}}$\mathbb{P}\_{pp}, pk, \text{ct}\_1, \text{ct}\_2]\_{zk}$:**
    - **Proof Content:**
      $(\text{proof, sid} \| \text{pid}_A, \text{ct}_A, C_1, C_2)$

   **Purpose:**

    - This proof ensures that the ciphertext $\text{ct}_A$ is correctly computed using the intermediate values $a_1$
      and $a_2$, and that the values $C_1$ and $C_2$ are correctly related to the commitments and the message $
      m$. This maintains the integrity and correctness of the homomorphic evaluation and the resulting ciphertext.

#### Summary:

In this step, Bob receives and verifies a series of proofs from Alice. These proofs are essential for ensuring that
Alice's commitments, computed values, and the resulting ciphertext from the homomorphic evaluation are all correct and
consistent. If any of the proofs are invalid or not received, Bob aborts the protocol. This process is crucial for
maintaining the protocol's integrity and security, allowing Bob to trust that Alice has followed the protocol correctly
without revealing her private values.

### Step (b) - Verification of Values

**Explanation:**  
Bob verifies that the values used in the proofs provided by Alice are consistent with the values he has previously
obtained. This ensures that all commitments, key shares, and computed values match and are valid.

#### Variables and Functions Used:

- **keygen**: The process of generating keys.
- **$X_A$**: Alice's public key share.
- **$X$**: Combined public key.
- **ctkey**: Ciphertext key used in previous steps.
- **$pk$**: Public key.
- **presign**: Pre-signing phase data.
- **$sid$**: Session identifier.
- **$R_B$**: Bob's public value related to his nonce.
- **$K_A$**: Commitment to Alice's nonce.
- **$pt'$**: Plaintext value from pre-signing.
- **$r$**: x-coordinate of the combined nonce $R$.
- **$U_A$**: Commitment to Alice's nonce with additional randomness $\rho_2$.
- **$C_1$**: Computed value combining $U_A$ and $K_A$ with the message $m$.
- **$C_2$**: Computed value combining $r$ and $K_A$.
- **$R|_{x\text{-axis}}$**: x-coordinate of the combined nonce $R$.

#### Verification Steps:

1. **Verify Consistency with Previous Records:**
    - Bob checks that the values used in Alice's proofs match his previously recorded values:
        - Records include (keygen, $X_A$, $X$, ctkey, pk).
        - Pre-signing data (presign, sid, $R_B$, $K_A$, pt').

   **Purpose:**

    - This step ensures that the values used in Alice's proofs are consistent with the values obtained during key
      generation and pre-signing phases. Consistency verifies that no tampering or errors have occurred.

2. **Verify Computed Values $C_1$ and $C_2$:**
    - Bob verifies that:
        - $C_1 = (r \circ U_A) \oplus (m \circ K_A)$
        - $C_2 = r \circ K_A$
    - Where $r = R|_{x\text{-axis}}$.

   **Purpose:**
    - Verifying $C_1$ and $C_2$ ensures that Alice's computations involving her commitments, nonce, and the message
      are correct. This step is crucial for validating the integrity of the signature generation process.

#### Summary:

In step (b), Bob verifies that the values used in Alice's proofs are consistent with his previously recorded values and
that the computed values $C_1$ and $C_2$ are correct. This verification step is essential for maintaining the
integrity and security of the protocol, ensuring that all commitments, key shares, and computed values match and are
valid. If any inconsistencies are found, Bob aborts the protocol.

### Step (c) - Decryption and Computation

**Explanation:**
Bob performs decryption on received ciphertexts and computes the intermediate signature value. This step is critical for
ensuring that the computations are valid and for producing the final signature component.

#### Variables and Functions Used:

- **$\text{decrypt}$**: Function to decrypt the given ciphertext.
- **$pk$**: Public key.
- **$\text{ct}_A$**: Ciphertext resulting from the homomorphic evaluation.
- **$\text{ct}_4$**: Additional ciphertext used in the decryption process.
- **$U_A$**: Commitment to Alice's nonce with additional randomness $\rho_2$.
- **$pt_4$**: Plaintext result obtained from decrypting $\text{ct}_4$.
- **$\gamma$**: Random value used in computations.
- **$r$**: x-coordinate of the combined nonce $R$.
- **$\rho_1$**: Randomness used in Alice's initial commitment.
- **$\rho_2$**: Additional randomness used in the commitment $U_A$.
- **$s'$**: Intermediate signature value.
- **$q$**: Large prime number.
- **$m$**: Message to be signed.
- **$\eta$**: Randomness used in the evaluation.

#### Decryption and Computation Steps:

1. **Sending Decryption Requests:**
    - Bob sends the following decryption requests to the ideal functionality $\mathcal{F}_{\text{AHE}}$:  
      $\text{decrypt, pk, ct}_A$  
      $\text{decrypt, pk, ct}_4$

2. **Waiting for Responses:**
    - Bob waits for the responses, which include the decrypted values:
        - $(\text{decrypted, pk, ct}_A, pt_a, U_A)$
        - $(\text{decrypted, pk, ct}_4, pt_4, U_4)$

3. **Handling Decryption Failures:**
    - If $pt_4$ is invalid ($pt_4 = \bot$) or missing, Bob aborts the protocol.
    - If $pt_a$ is invalid ($pt_a = \bot$) or missing, Bob aborts the protocol.
    - On both cases output: output $U_A \cup U_4$ and abort.

4. **Computing Intermediate Signature $s'$:**
    - Otherwise, compute:  
      $s' = pt_4^{-1} \cdot pt_A \mod q$  
      which is equal to:  
      $(\gamma k_B)^{-1} \cdot ((r k_A x_A + m k_A) \gamma + r k_A \gamma x_B) = k^{-1} (r x + m) \mod q$
    - Bob then
      computes ([to ensure the uniqueness of the signature](#explanation-of-ensuring-uniqueness-of-the-signature)):

```math
s = \min \left\{ s', q - s' \right\}
```

**Purpose:**

- **Decryption:** To obtain the plaintext values from the ciphertexts, allowing Bob to verify the correctness of the
  encrypted computations.
- **Intermediate Signature Computation:** To compute the intermediate signature value $s'$ and ensure it is within
  the valid range by taking the minimum value between $s'$ and $q - s'$. This step finalizes the computation
  needed for the signature.

#### Summary:

In step (c), Bob decrypts the received ciphertexts and computes the intermediate signature value $s'$. This involves
handling decryption failures and ensuring the correctness of the decrypted values. Bob then computes the final signature
component $s$ by taking the minimum value between $s'$ and $q - s'$. This step is critical for producing a
valid signature and maintaining the integrity and security of the protocol. If any inconsistencies or errors are found
during decryption, Bob aborts the protocol.

## 3 - Output

**Explanation:**
After performing all the necessary verifications and computations, Bob outputs the final signature.

#### Variables and Functions Used:

- **$r$**: x-coordinate of the combined nonce $R$.
- **$s$**: Final signature component computed in the previous step.

#### Output:

- **Signature:**
  $\sigma = (r, s)$

**Purpose:**

- The purpose of this step is to produce the final digital signature $\sigma$ on the message. The signature is
  composed of the values $r$ and $s$, which have been verified and computed through the secure multi-party
  protocol.

### Summary:

In step 3, Bob outputs the final signature $\sigma = (r, s)$. This signature is the result of the secure multi-party
computation process, ensuring that it is valid, unique, and consistent with the inputs and computations performed by
both Alice and Bob throughout the protocol. This step concludes the signature generation process, providing a secure and
verifiable digital signature on the message.

## Explanation of Ensuring Uniqueness of the Signature

In the last sentence of step 2(c), it states that Bob outputs $s = \min(s', q - s')$ to ensure the uniqueness of the
signature. Here’s why this step is important:

#### Ensuring Uniqueness

1. **Range of Signature Values:**
    - The signature value $s$ needs to be unique and fall within a standardized range to prevent ambiguity. In
      modular arithmetic, a value and its complement modulo $q$ can represent the same result.
    - For example, if $s'$ is a computed value, both $s'$ and $q - s'$ can be considered valid
      representations. However, using both can lead to multiple valid signatures for the same message, which is
      undesirable.

2. **Standardizing the Signature:**
    - By taking $s = \min(s', q - s')$, Bob ensures that the signature value $s$ is always the smaller of the
      two possible representations.
    - This standardization ensures that for any given message and nonce, there is only one unique signature \(
      \sigma = (r, s)$.

3. **Preventing Ambiguity:**
    - Ensuring that $s$ is within a specific range prevents any ambiguity in the signature verification process. It
      guarantees that each message will have one unique signature, making the signature scheme more robust and secure.
    - This also simplifies the verification process since verifiers do not need to consider multiple possible values
      for $s$.

### Summary:

In step 2(c), the final computation of $s$ as $s = \min(s', q - s')$ ensures the uniqueness of the signature.
This step is crucial because it standardizes the signature value, preventing multiple valid representations and ensuring
that each message has a single, unique signature. This enhances the security and robustness of the signature scheme,
making it easier and more reliable to verify signatures.
