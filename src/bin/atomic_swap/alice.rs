use as_for_fde::{AS_scheme, Sigma, Sigma_prime, Scheme, Sign_scheme};
use k256::{elliptic_curve::ff::Field, ProjectivePoint, Scalar};
use rand_core::OsRng;

/// `Alice` represents a party in an atomic swap protocol.
/// She holds a secret key `sk`, a temporary scalar `t`, and uses a selected signature `Scheme`.
pub struct Alice {
    /// Secret key
    sk: Scalar,
    /// Public key (derived from `sk`)
    pub pk: ProjectivePoint,
    /// Temporary secret used for adaptor signing
    t: Scalar,
    /// Public counterpart of `t`
    pub T: ProjectivePoint,
    /// The cryptographic signing scheme used (e.g., Schnorr or ECDSA)
    scheme: Scheme,
}

impl Alice {
    /// Constructs a new `Alice` instance by randomly generating her secret key `sk` and adaptor secret `t`.  
    /// It also computes the corresponding public keys `pk` and `T`, and stores the chosen signature scheme.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The cryptographic signature scheme to use.
    ///
    /// # Returns
    ///
    /// * A new `Alice` instance.
    pub fn new(scheme: Scheme) -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;

        let t = Scalar::random(&mut OsRng);
        let T = ProjectivePoint::GENERATOR * t;

        Self {
            sk,
            pk,
            t,
            T,
            scheme,
        }
    }

    /// Generates a pre-signature (`Sigma_prime`) for a given transaction `tx`.  
    /// Returns the pre-signature and the corresponding tweak point `T`.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction or message string to be signed.
    ///
    /// # Returns
    ///
    /// * A tuple containing:
    ///   - The pre-signature (`Sigma_prime`)
    ///   - The tweak point `T`
    pub fn generate_presig(&self, tx: &str) -> (Sigma_prime, ProjectivePoint) {
        let r_prime = Scalar::random(&mut OsRng);
        let sigma_prime = self.scheme.pre_sign(&self.sk, tx, &self.T, &r_prime);
        (sigma_prime, self.T)
    }

    /// Verifies a pre-signature against a provided public key and transaction.
    ///
    /// # Arguments
    ///
    /// * `sigma_prime` - The pre-signature to verify.
    /// * `pk` - The public key claimed to have generated the pre-signature.
    /// * `tx` - The transaction or message being verified.
    ///
    /// # Returns
    ///
    /// * `true` if the pre-signature is valid; `false` otherwise.
    pub fn verify_presig(&self, sigma_prime: &Sigma_prime, pk: &ProjectivePoint, tx: &str) -> bool {
        self.scheme.verify_pre_sign(pk, tx, &self.T, sigma_prime)
    }

    /// Generates Alice's full signature for a transaction, and adapts a pre-signature from Bob
    /// into a full signature using Alice's secret `t`.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction or message to sign.
    /// * `sigma_prime_b` - Bob’s pre-signature to be adapted.
    ///
    /// # Returns
    ///
    /// * A tuple containing:
    ///   - Alice’s full signature (`Sigma`)
    ///   - The adapted full signature for Bob (`Sigma`)
    pub fn generate_sig_and_adapt(&self, tx: &str, sigma_prime_b: &Sigma_prime) -> (Sigma, Sigma) {
        let r_a = Scalar::random(&mut OsRng);
        let sigma_a = self.scheme.sign(&self.sk, tx, &r_a);
        let sigma_b = self.scheme.adapt_signature(sigma_prime_b, &self.t);

        (sigma_a, sigma_b)
    }
}
