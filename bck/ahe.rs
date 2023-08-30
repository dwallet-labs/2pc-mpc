use num_traits::{Num, Pow};

/// An Additively Homomorphic Encryption scheme
/// is associated with an ensemble $\{\calK_\kappa\}_\kappa$ and
/// consists of four polynomial time algorithms: $\AHE=(\Gen, \Enc, \Dec, \Add)$ specified as follows:
/// 1.  $\Gen(1^\kappa, {\sf aux}) \to (pk; sk)$.
///     A probabilistic algorithm that is given a security parameter $1^\kappa$ and possibly some auxiliary information ${\sf aux}$ and samples a key-pair $(pk,sk)$ from $\calK_\kappa$.
///     In the following, we assume that the resulting $pk$ contains the description of the security parameter $1^\kappa$, the auxiliary information ${\sf aux}$, as well as the plaintext, randomness and ciphertext spaces $\calP_{pk}$, $\calR_{pk}$ and $\calC_{pk}$, respectively, where $\calP_{pk}$ is a $\ZZ$-module.
///
/// 2.  $\Enc(pk, \pt; \eta_{\sf enc}) \to \ct$.
///     A deterministic algorithm that on input a public key $pk$, a plaintext $\pt \in \calP_{pk}$ and randomness $\eta_{\sf enc} \in \calR_{pk}$, outputs a ciphertext $\ct \in \calC_{pk}$.
///     We define $\Enc(pk, \pt)$ as a probabilistic algorithm that first uniformly samples $\eta_{\sf enc} \in \calR_{pk}$ and then outputs $\Enc(pk, \pt; r)$.
///
/// 3.  $\Dec(sk, \ct) \to \pt$.
///     A deterministic algorithm that on input a secret key $sk$ and a ciphertext $\ct \in \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
///
/// 4.  $\Add(pk, \ct_1, \ct_2)\to \ct_3$.
///     A deterministic algorithm that on input a public key $pk$ and two ciphertexts $\ct_1, \ct_2\in\calC_{pk}$ outputs a ciphertext $\ct_3\in\calC_{pk}$ such that if $\ct_1=\Enc(pk, m_1, \eta_1)$ and $\ct_2=\Enc(pk, m_2, \eta_2)$ then $\ct_3=\Enc(pk, m_1+m_1, \eta_1+\eta_2)$, where $m_1+m_2$ and $\eta_1+\eta_2$ are over $\calP_{pk}$ and $\calR_{pk}$, respectively.
///     Imposing correctness will ensure that $\Add$ is a homomorphic addition. Note that efficient homomorphic scalar multiplication is implied by the $\Add$ operation (e.g., via double-and-add).
///
pub trait AdditivelyHomomorphicEncryption {
    type EncryptionKey;
    type DecryptionKey;

    type PlaintextElement; // An element of the plaintext space $\calP_{pk}$
    type CiphertextElement; // An element of the ciphertext space $\calC_{pk}$
    type RandomnessElement; // An element of the randomness space $\calR_{pk}$

    // TODO: should we define gen here? or just emit it entirely from this trait.

    // so obviously the ciphertext element is not in Zp, or that even if it is we shouldn't think of it like that because then arithmetic operations will not be well defined?

    // TODO: should we have the add function as Add for CiphertextElement instead? why is the public key needed to add ciphertexts? can't it be defered from the ciphertext?

    // TODO: use Integer not Num

    /// $\Enc(pk, \pt; \eta_{\sf enc}) \to \ct$.
    /// A deterministic algorithm that on input a public key $pk$, a plaintext $\pt \in \calP_{pk}$ and randomness $\eta_{\sf enc} \in \calR_{pk}$, outputs a ciphertext $\ct \in \calC_{pk}$.
    /// We define $\Enc(pk, \pt)$ as a probabilistic algorithm that first uniformly samples $\eta_{\sf enc} \in \calR_{pk}$ and then outputs $\Enc(pk, \pt; r)$.
    ///
    fn encrypt(
        public_key: &Self::EncryptionKey, // $\pk \in \calP_{pk}$ the public key to encrypt to
        plaintext: &Self::PlaintextElement, // $\pt \in \calP_{pk}$ the plaintext to encrypt
        randomness: &Self::RandomnessElement, // $\eta_{\sf enc} \in \calR_{pk}$ the randomness with which to randomize the encryption TODO: should this be called a nonce? should I indicate this should be used once?
    ) -> Self::CiphertextElement; // $\ct \in \calC_{pk}$ the outputted ciphertext

    /// $\Dec(sk, \ct) \to \pt$.
    /// A deterministic algorithm that on input a secret key $sk$ and a ciphertext $\ct \in \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
    ///
    fn decrypt(
        secret_key: &Self::DecryptionKey,
        ciphertext: &Self::CiphertextElement, // $\ct \in \calC_{pk}$ the outputted ciphertext
    ) -> Self::PlaintextElement;

    /// $\Add(pk, \ct_1, \ct_2)\to \ct_3$.
    /// A deterministic algorithm that on input a public key $pk$ and two ciphertexts $\ct_1, \ct_2\in\calC_{pk}$ outputs a ciphertext $\ct_3\in\calC_{pk}$ such that if $\ct_1=\Enc(pk, m_1, \eta_1)$ and $\ct_2=\Enc(pk, m_2, \eta_2)$ then $\ct_3=\Enc(pk, m_1+m_1, \eta_1+\eta_2)$, where $m_1+m_2$ and $\eta_1+\eta_2$ are over $\calP_{pk}$ and $\calR_{pk}$, respectively.
    /// Imposing correctness will ensure that $\Add$ is a homomorphic addition.
    ///
    /// Note that efficient homomorphic scalar multiplication is implied by the $\Add$ operation (e.g., via double-and-add).
    ///
    fn add(
        public_key: &Self::EncryptionKey, // $\pk \in \calP_{pk}$ the public key to encrypt to
        left_ciphertext: &Self::CiphertextElement, // $\ct \in \calC_{pk}$ the left ciphertext to add to
        right_ciphertext: &Self::CiphertextElement, // $\ct \in \calC_{pk}$ the right ciphertext to add
    ) -> Self::CiphertextElement; // $\ct \in \calC_{pk}$ the outputted ciphertext which is the sum of `left_ciphertext` and `right_ciphertext`

    fn scalar_mul<T: Num>(
        public_key: &Self::EncryptionKey, // $\pk \in \calP_{pk}$ the public key to encrypt to
        scalar: T,                        // $a \in\ZZ$
        ciphertext: &Self::CiphertextElement, // $\ct \in \calC_{pk}$ the outputted ciphertext
    ) -> Self::CiphertextElement;

    // Multiplies each scalar-ciphertext pair and sums them up
    fn apply_linear_transformation<T: Num>(
        public_key: &Self::EncryptionKey, // $\pk \in \calP_{pk}$ the public key to encrypt to
        ciphertexts_with_coeffecients: Vec<(T, Self::CiphertextElement)>, // $ (a_i, \ct) \in\ZZ * \calC_{pk} $ the outputted ciphertext
    ) -> Self::CiphertextElement;
}
