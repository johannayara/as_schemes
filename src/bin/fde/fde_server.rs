use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use hex;
use k256::{elliptic_curve::ff::Field, ProjectivePoint, Scalar};

use rand_core::OsRng;

use as_for_fde::{AS_scheme, Sigma, Sigma_prime, Scheme, Sign_scheme};
/// `Server` represents a data provider in fair data exchange (FDE) protocol.  
/// It holds two secret keys:
/// - One for encrypting data (`sk`)
/// - One for signing (`sk_s`)
/// And uses a selected cryptographic signature `Scheme`.
pub struct Server {
    /// Secret encryption key (used for AES encryption and adaptor signing)
    sk: Scalar,
    /// Public key corresponding to `sk`
    pub pk: ProjectivePoint,
    /// Secret signing key (used for generating actual signatures)
    sk_s: Scalar,
    /// Public key corresponding to `sk_s`
    pub pk_s: ProjectivePoint,
    /// The cryptographic signature scheme in use (e.g., Schnorr or ECDSA)
    scheme: Scheme,
}

impl Server {
    /// Constructs a new `Server` instance with randomly generated secret keys  
    /// for both encryption and signing. Also computes their corresponding public keys.
    ///
    /// # Arguments
    ///
    /// * `scheme` - The cryptographic signature scheme to be used by the server.
    ///
    /// # Returns
    ///
    /// * A new `Server` instance.
    pub fn new(scheme: Scheme) -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;
        let sk_s = Scalar::random(&mut OsRng);
        let pk_s = ProjectivePoint::GENERATOR * sk_s;
        Self {
            sk,
            pk,
            sk_s,
            pk_s,
            scheme,
        }
    }

    /// Encrypts the provided plaintext using AES-256-GCM with `sk` as the symmetric key.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext data to encrypt.
    ///
    /// # Returns
    ///
    /// * A tuple containing:
    ///   - The encrypted ciphertext as a byte vector.
    ///   - The randomly generated 12-byte nonce used during encryption.
    pub fn encrypt_data(&self, plaintext: &str) -> (Vec<u8>, [u8; 12]) {
        let key_bytes = self.sk.to_bytes();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(&key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("encryption failed");

        // Convert nonce to [u8; 12]
        let nonce_array: [u8; 12] = *nonce.as_ref();

        (ciphertext, nonce_array)
    }

    /// Verifies a client's pre-signature over a ciphertext using the server’s public key.
    ///
    /// # Arguments
    ///
    /// * `sigma_prime` - The client’s pre-signature.
    /// * `pk_c` - The client’s public key.
    /// * `ct` - The encrypted ciphertext (used as the message).
    ///
    /// # Returns
    ///
    /// * `true` if the pre-signature is valid; `false` otherwise.
    pub fn verify_presig(
        &self,
        sigma_prime: &Sigma_prime,
        pk_c: &ProjectivePoint,
        ct: &[u8],
    ) -> bool {
        self.scheme
            .verify_pre_sign(pk_c, &hex::encode(ct), &self.pk, sigma_prime)
    }

    /// Generates a full signature using the signing key `sk_s`, and adapts a client’s pre-signature  
    /// into a full signature using the encryption key `sk`.
    ///
    /// # Arguments
    ///
    /// * `ct` - The ciphertext to sign (used as the message).
    /// * `sigma_prime` - The client’s pre-signature to be adapted.
    ///
    /// # Returns
    ///
    /// * A tuple containing:
    ///   - The server’s full signature (`Sigma`).
    ///   - The adapted signature derived from the client’s pre-signature (`Sigma`).
    pub fn generate_sig_and_adapt(&self, ct: &[u8], sigma_prime: &Sigma_prime) -> (Sigma, Sigma) {
        let r_s = Scalar::random(&mut OsRng);
        let sigma_s = self.scheme.sign(&self.sk_s, &hex::encode(ct), &r_s);
        let sigma_c = self.scheme.adapt_signature(sigma_prime, &self.sk);

        (sigma_s, sigma_c)
    }
}
