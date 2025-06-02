use as_for_fde::{AS_scheme, Delta, Delta_prime, Scheme, Sign_scheme};
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

    /// Generates a pre-signature `Delta'` using Bob's secret key.
    ///
    /// # Arguments
    ///
    /// * `tx` - A string representing the transaction or message to be signed.
    /// * `T` - A public tweak point involved in adaptor signing.
    ///
    /// # Returns
    ///
    /// * A `Delta_prime` representing the pre-signature.
    pub fn generate_presig(&self, tx: &str, T: &ProjectivePoint) -> Delta_prime {
        let r_prime = Scalar::random(&mut OsRng);
        let delta_prime = self.scheme.pre_sign(&self.sk, tx, T, &r_prime);
        delta_prime
    }

    /// Verifies a given pre-signature against the expected public key and message.
    ///
    /// # Arguments
    ///
    /// * `delta_prime` - The pre-signature to verify.
    /// * `pk` - The public key expected to have generated the pre-signature.
    /// * `tx` - The transaction/message the signature is bound to.
    /// * `T` - The tweak point used in the pre-signature.
    ///
    /// # Returns
    ///
    /// * `true` if the pre-signature is valid; `false` otherwise.
    pub fn verify_presig(
        &self,
        delta_prime: &Delta_prime,
        pk: &ProjectivePoint,
        tx: &str,
        T: &ProjectivePoint,
    ) -> bool {
        self.scheme.verify_pre_sign(pk, tx, T, delta_prime)
    }

    /// Verifies two full signatures over the same message.
    ///
    /// # Arguments
    ///
    /// * `a_pk` - Alice's public key.
    /// * `tx` - The transaction/message being verified.
    /// * `delta_a` - Alice's full signature.
    /// * `delta_b` - Bob's own full signature.
    ///
    /// # Returns
    ///
    /// * `true` if both signatures are valid; `false` otherwise.
    pub fn verify_sign(
        &self,
        a_pk: &ProjectivePoint,
        tx: &str,
        delta_a: &Delta,
        delta_b: &Delta,
    ) -> bool {
        let is_a_correct = self.scheme.verify_sign(delta_a, a_pk, tx);
        let is_b_correct = self.scheme.verify_sign(delta_b, &self.pk, tx);
        is_a_correct && is_b_correct
    }

    /// Extracts the secret witness value `t` from a full signature and its corresponding pre-signature.
    ///
    /// # Arguments
    ///
    /// * `delta` - The full signature.
    /// * `delta_prime` - The pre-signature.
    ///
    /// # Returns
    ///
    /// * The extracted `Scalar` witness value `t`.
    pub fn extract_secret(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        let t = self.scheme.extract_witness(delta, delta_prime);
        t
    }

    /// Generates Bob’s full signature and adapts Alice’s pre-signature using a shared witness.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction/message to sign.
    /// * `delta_prime_a` - Alice's pre-signature to adapt.
    /// * `t` - The shared secret used to adapt Alice’s pre-signature.
    ///
    /// # Returns
    ///
    /// * A tuple containing:
    ///     - Alice’s adapted full signature (`Delta`)
    ///     - Bob’s newly generated full signature (`Delta`)
    pub fn generate_sig_and_adapt(
        &self,
        tx: &str,
        delta_prime_a: &Delta_prime,
        t: &Scalar,
    ) -> (Delta, Delta) {
        let r_b = Scalar::random(&mut OsRng);
        let delta_a = self.scheme.adapt_signature(delta_prime_a, t);
        let delta_b = self.scheme.sign(&self.sk, tx, &r_b);

        (delta_a, delta_b)
    }
}
