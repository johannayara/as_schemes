use as_for_fde::{AS_scheme, Sigma, Sigma_prime, Scheme, Sign_scheme};
use k256::{elliptic_curve::ff::Field, ProjectivePoint, Scalar};
use rand_core::OsRng;

/// `Bob` represents a party in an atomic swap protocol.
/// He holds a secret key `sk`, and uses a selected signature `Scheme`.
pub struct Bob {
    /// Secret key
    sk: Scalar,
    /// Public key (derived from `sk`)
    pub pk: ProjectivePoint,
    /// The cryptographic signing scheme used (e.g., Schnorr or ECDSA)
    scheme: Scheme,
}

impl Bob {
    /// Creates a new `Bob` instance with a randomly generated secret key.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The signing scheme to be used (e.g., `Scheme::Schnorr`, `Scheme::ECDSA`)
    ///
    /// # Returns
    ///
    /// * A new `Bob` instance with generated keys and the specified scheme.
    pub fn new(scheme: Scheme) -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;
        Self { sk, pk, scheme }
    }

    /// Generates a pre-signature `Sigma'` using Bob's secret key.
    ///
    /// # Arguments
    ///
    /// * `tx` - A string representing the transaction or message to be signed.
    /// * `T` - A public tweak point involved in adaptor signing.
    ///
    /// # Returns
    ///
    /// * A `Sigma_prime` representing the pre-signature.
    pub fn generate_presig(&self, tx: &str, T: &ProjectivePoint) -> Sigma_prime {
        let r_prime = Scalar::random(&mut OsRng);
        let sigma_prime = self.scheme.pre_sign(&self.sk, tx, T, &r_prime);
        sigma_prime
    }

    /// Verifies a given pre-signature against the expected public key and message.
    ///
    /// # Arguments
    ///
    /// * `sigma_prime` - The pre-signature to verify.
    /// * `pk` - The public key expected to have generated the pre-signature.
    /// * `tx` - The transaction/message the signature is bound to.
    /// * `T` - The tweak point used in the pre-signature.
    ///
    /// # Returns
    ///
    /// * `true` if the pre-signature is valid; `false` otherwise.
    pub fn verify_presig(
        &self,
        sigma_prime: &Sigma_prime,
        pk: &ProjectivePoint,
        tx: &str,
        T: &ProjectivePoint,
    ) -> bool {
        self.scheme.verify_pre_sign(pk, tx, T, sigma_prime)
    }

    /// Verifies two full signatures over the same message.
    ///
    /// # Arguments
    ///
    /// * `a_pk` - Alice's public key.
    /// * `tx` - The transaction/message being verified.
    /// * `sigma_a` - Alice's full signature.
    /// * `sigma_b` - Bob's own full signature.
    ///
    /// # Returns
    ///
    /// * `true` if both signatures are valid; `false` otherwise.
    pub fn verify_sign(
        &self,
        a_pk: &ProjectivePoint,
        tx: &str,
        sigma_a: &Sigma,
        sigma_b: &Sigma,
    ) -> bool {
        let is_a_correct = self.scheme.verify_sign(sigma_a, a_pk, tx);
        let is_b_correct = self.scheme.verify_sign(sigma_b, &self.pk, tx);
        is_a_correct && is_b_correct
    }

    /// Extracts the secret witness value `t` from a full signature and its corresponding pre-signature.
    ///
    /// # Arguments
    ///
    /// * `sigma` - The full signature.
    /// * `sigma_prime` - The pre-signature.
    ///
    /// # Returns
    ///
    /// * The extracted `Scalar` witness value `t`.
    pub fn extract_secret(&self, sigma: &Sigma, sigma_prime: &Sigma_prime) -> Scalar {
        let t = self.scheme.extract_witness(sigma, sigma_prime);
        t
    }

    /// Generates Bob’s full signature and adapts Alice’s pre-signature using a shared witness.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction/message to sign.
    /// * `sigma_prime_a` - Alice's pre-signature to adapt.
    /// * `t` - The shared secret used to adapt Alice’s pre-signature.
    ///
    /// # Returns
    ///
    /// * A tuple containing:
    ///     - Alice’s adapted full signature (`Sigma`)
    ///     - Bob’s newly generated full signature (`Sigma`)
    pub fn generate_sig_and_adapt(
        &self,
        tx: &str,
        sigma_prime_a: &Sigma_prime,
        t: &Scalar,
    ) -> (Sigma, Sigma) {
        let r_b = Scalar::random(&mut OsRng);
        let sigma_a = self.scheme.adapt_signature(sigma_prime_a, t);
        let sigma_b = self.scheme.sign(&self.sk, tx, &r_b);

        (sigma_a, sigma_b)
    }
}
