
use k256::{elliptic_curve::{ff::Field},ProjectivePoint, Scalar};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key 
};
use hex;

use rand_core::OsRng;

use as_for_fde::{ AS_scheme, Delta, Delta_prime, Scheme, Sign_scheme};

pub struct Server {
    sk: Scalar,
    pub pk: ProjectivePoint,
    sk_s: Scalar,
    pub pk_s: ProjectivePoint,
    scheme: Scheme
}

impl Server {
    pub fn new(scheme:Scheme) -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;
        let sk_s = Scalar::random(&mut OsRng);
        let pk_s = ProjectivePoint::GENERATOR * sk_s;
        Self { sk, pk, sk_s, pk_s, scheme}
    }

    pub fn encrypt_data(&self, plaintext: &str) -> (Vec<u8>, [u8; 12]) {
        let key_bytes = self.sk.to_bytes();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(&key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("encryption failed");

        // Convert nonce to [u8; 12]
        let nonce_array: [u8; 12] = *nonce.as_ref();

        (ciphertext, nonce_array)
    }


    pub fn verify_presig(&self, delta_prime: &Delta_prime, pk_c: &ProjectivePoint, ct: &[u8]) -> bool {
        self.scheme.verify_pre_sign(pk_c, &hex::encode(ct), &self.pk, delta_prime)
    }

    pub fn generate_sig_and_adapt(&self, ct: &[u8], delta_prime: &Delta_prime) -> (Delta, Delta) {

        // Server Schnorr signature
        let r_s = Scalar::random(&mut OsRng);
        let delta_s = self.scheme.sign(&self.sk_s, &hex::encode(ct), &r_s);
        let delta_c = self.scheme.adapt_signature(delta_prime, &self.sk);

        (delta_s, delta_c)
    }
}
