# Summary of Protocol 5: Presigning $\Pi_{\text{pres}}$ (Protocol 5)

The presigning protocol involves multiple parties (A, $B_1, B_2, \ldots, B_n$) with the goal of generating a shared
random nonce $k$. The protocol uses public key $pk$ and ciphertext $ctkey$ as inputs, and it consists of
several rounds and messages exchanged between the parties.

#### 1. Alice's Message:

(a) **Sampling and Commitment:**

- Alice samples a random $k_A$ from $Z_q$ and computes $K_A = \text{Com}(k_A; \rho_1)$.
- Alice sends $(\text{prove, sid, pid}\_A, K_A; k_A, \rho_1)$ to $\mathcal{F}_{\text{LDCom}_{zk}}$.

#### 2. Bob's Message:

(a) **First Round:**

- (i) **Receive Commitment:**
    - $B_i$ receives $(\text{proof, sid, pid}_A, K_A)$ from $\mathcal{F}_{\text{LDCom}_{zk}}$. If not valid,
      it aborts.
- (ii) **Sample and Compute:**
    - $B_i$ samples $k_i \leftarrow Z_q^*$ and computes $R_i = k_i \cdot G$. $k_B = \sum_i k_i$.
- (iii) **Generate AHE Components:**
    - $B_i$ samples $\gamma_i \leftarrow [0, q]$, and randomness $\eta_i$ for masks.
    - $\text{ct}_1 = \text{AHE.Enc}(pk, \gamma_i; \eta_{\text{mask}_1})$.
    - $\text{ct}_2 = \text{AHE.Eval}(pk, f_i, \text{ctkey}, \eta_{\text{mask}_2})$ where $f_i(x) = \gamma_i \cdot
      x$.
    - $\text{ct}_3 = \text{AHE.Enc}(pk, k_i; \eta_{\text{mask}_3})$.
- (iv) **Send Proofs:**
    - $B_i$ sends $(\text{prove, sid} \| \gamma, \text{pid}_i, \text{ct}_1, \text{ct}_2; \gamma_i, \eta_
      {\text{mask}_1}, \eta_{\text{mask}_2})$ to $\mathcal{F}_{\text{LEncDH}[pk, \text{ctkey}]}^{\text{agg-zk}}$.
- (v) **Send $R_i$ and $k_i$:**
    - $B_i$ sends $(\text{prove, sid, pid}_i, R_i, \text{ct}_3; k_i, \eta_{\text{mask}_3})$ to $\mathcal{F}_
      {\text{LEncDL}}^{\text{agg-zk}}$.

(b) **Second Round:**

- (i) **Receive Proofs:**
    - $B_i$ receives $(\text{proof, sid} \| \gamma, \text{ct}_1, \text{ct}_2)$ from $\mathcal{F}_
      {\text{LEncDH}[pk, \text{ctkey}]}^{\text{agg-zk}}$ and $(\text{proof, sid, R, ct}_3)$ from $\mathcal{F}_
      {\text{LEncDL}}^{\text{agg-zk}}$.
- (ii) **Malicious Check:**
    - If $B_i$ receives $(\text{malicious, sid, U'})$, it records the malicious parties and aborts.
- (iii) **Compute Combined Ciphertext:**
    - $B_i$ computes $\text{ct}_4 = \text{AHE.Eval}(pk, f_i', \text{ct}_1, \eta_{\text{mask}_4})$ where $f_i'(
      x) = k_i \cdot x$.
- (iv) **Send Proofs:**
    - $B_i$ sends $(\text{prove, sid} \| k, \text{pid}_i, \text{ct}_3, \text{ct}_4; k_i, \eta_{\text{mask}_3},
      \eta_{\text{mask}_4})$ to $\mathcal{F}_{\text{LEncDH}[pk, \text{ct}_1]}^{\text{agg-zk}}$.

(c) **Proof Verification:**

- $B_i$ receives $(\text{proof, sid} \| k, \text{ct}_3, \text{ct}_4)$ from $\mathcal{F}_
  {\text{LEncDH}[pk, \text{ct}_1]}^{\text{agg-zk}}$. If valid, continues; otherwise, records the malicious parties and
  aborts.

#### 3. Alice's Verification:

(a) **Verify $R_B$ and $\text{ct}_3$:**

- Alice receives $(\text{proof, sid, R}_B, \text{ct}_3)$ from $\mathcal{F}_{\text{LEncDL}}^{\text{agg-zk}}$. If
  valid, continues; otherwise, aborts.
  (b) **Verify Combined Ciphertexts:**
- Alice receives $(\text{proof, sid, ct}_1, \text{ct}_2)$ from $\mathcal{F}_{\text{LEncDH}[pk, \text{ctkey}]
  }^{\text{agg-zk}}$. If valid, continues; otherwise, aborts.

#### 4. Output:

(a) **Alice Records:**

- Alice records $(\text{presign, sid, R}_B, \text{ct}_1, \text{ct}_2; k_A, \rho_1)$ where $\text{ct}_1$ and $
  \text{ct}_2$ are encryptions of $\gamma$ and $\gamma \cdot x_B$.
  (b) **Bob Records:**
- Bob records $(\text{presign, sid, R}_B, K_A, \text{ct}_3, \text{ct}_4)$, where $\text{ct}_4$ encrypts $
  \gamma \cdot k_B \mod q$.

### Summary:

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
