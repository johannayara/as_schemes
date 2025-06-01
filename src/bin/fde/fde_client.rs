use k256::{elliptic_curve::{ff::Field},ProjectivePoint, Scalar};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key 
};
use hex;
use rand_core::OsRng;
use as_for_fde::{AS_scheme, Delta, Delta_prime, Schnorr, Sign_scheme};

pub struct Client {
    sk_c: Scalar,
    pub pk_c: ProjectivePoint,
}

impl Client {
    pub fn new() -> Self {
        let sk_c = Scalar::random(&mut OsRng);
        let pk_c = ProjectivePoint::GENERATOR * sk_c;
        Self { sk_c, pk_c }
    }

    pub fn generate_presig(&self, ct: &[u8], server_pk: &ProjectivePoint) -> Delta_prime {
        let schnorr = Schnorr;
        let r_prime = Scalar::random(&mut OsRng);
        let delta_prime = schnorr.pre_sign(&self.sk_c, &hex::encode(ct), server_pk, &r_prime);
        delta_prime
    }
    
    pub fn verify_sign(&self, server_pk: &ProjectivePoint, ct: &[u8], delta_s: &Delta, delta_c: &Delta) -> bool{
        let schnorr = Schnorr;
        let is_s_correct = schnorr.verify_sign(delta_s,server_pk, &hex::encode(ct));
        let is_c_correct = schnorr.verify_sign(delta_c, &self.pk_c, &hex::encode(ct));
        is_c_correct && is_s_correct
    }

    pub fn extract_secret(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        let schnorr = Schnorr;
        let t = schnorr.extract_witness(delta, delta_prime);
        t
    }

    pub fn decrypt_data(&self, ct: &[u8], sk: &Scalar, nonce_bytes: &[u8]) -> String {
        let key_bytes = sk.to_bytes();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext: Vec<u8> = cipher.decrypt(nonce, ct).expect("decryption failed");
        String::from_utf8(plaintext).expect("Invalid UTF8 character in plaintext")
    }
}
