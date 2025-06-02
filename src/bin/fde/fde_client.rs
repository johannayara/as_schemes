use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use as_for_fde::{AS_scheme, Delta, Delta_prime, Scheme, Sign_scheme};
use hex;
use k256::{elliptic_curve::ff::Field, ProjectivePoint, Scalar};
use rand_core::OsRng;
/// `Client` represents a buying party in fair data exchange protocol.
/// They hold a secret key `sk`, and use a selected signature `Scheme`.
pub struct Client {
    /// Client's secret key
    sk: Scalar,
    /// Client's public key, derived from `sk`
    pub pk: ProjectivePoint,
    /// The cryptographic signing scheme used (e.g., Schnorr or ECDSA)
    scheme: Scheme,
}

impl Client {
    /// Creates a new `Client` instance with random `sk`
    /// computes `pk`, and stores the chosen signature scheme.
    pub fn new(scheme: Scheme) -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;
        Self { sk, pk, scheme }
    }

    /// Generates a pre-signature (`Delta_prime`) for a given ciphertext `ct`.
    /// The ciphertext is hex-encoded before signing.
    ///
    /// # Arguments
    /// * `ct` - Ciphertext to be signed.
    /// * `server_pk` - The server's public key, used in the pre-signing process.
    /// # Returns
    /// The pre-signature and the tweak point `T`.
    pub fn generate_presig(&self, ct: &[u8], server_pk: &ProjectivePoint) -> Delta_prime {
        let r_prime = Scalar::random(&mut OsRng);
        let delta_prime = self
            .scheme
            .pre_sign(&self.sk, &hex::encode(ct), server_pk, &r_prime);
        delta_prime
    }

    /// Verifies the correctness of both the server's and client's signatures on the same ciphertext.
    ///
    /// # Arguments
    /// * `server_pk` - Server's public key.
    /// * `ct` - Ciphertext being verified.
    /// * `delta_s` - Signature from the server.
    /// * `delta_c` - Signature from the client.
    ///
    /// # Returns
    /// * `true` if both signatures are valid; `false` otherwise.
    pub fn verify_sign(
        &self,
        server_pk: &ProjectivePoint,
        ct: &[u8],
        delta_s: &Delta,
        delta_c: &Delta,
    ) -> bool {
        let is_s_correct = self
            .scheme
            .verify_sign(delta_s, server_pk, &hex::encode(ct));
        let is_c_correct = self.scheme.verify_sign(delta_c, &self.pk, &hex::encode(ct));
        is_c_correct && is_s_correct
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

    /// Decrypts ciphertext `ct` using a derived key `sk` (scalar) and a given nonce.
    ///
    /// # Arguments
    /// * `ct` - The ciphertext to decrypt.
    /// * `sk` - A scalar used as the decryption key (derived from a witness or shared secret).
    /// * `nonce_bytes` - A 96-bit nonce required by AES-GCM.
    ///
    /// # Panics
    /// Will panic if decryption fails or the result is not valid UTF-8.
    pub fn decrypt_data(&self, ct: &[u8], sk: &Scalar, nonce_bytes: &[u8]) -> String {
        let key_bytes = sk.to_bytes();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext: Vec<u8> = cipher.decrypt(nonce, ct).expect("decryption failed");
        String::from_utf8(plaintext).expect("Invalid UTF8 character in plaintext")
    }
}
