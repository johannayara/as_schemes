use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint}, ProjectivePoint, Scalar, U256
};
use sha2::{Digest, Sha256};

use crate::{Delta, Delta_prime, AS_scheme, Sign_scheme};

#[derive(Clone)]
pub struct Schnorr;

impl Sign_scheme for Schnorr{
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta {
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }
        let R = ProjectivePoint::GENERATOR * k;
        let P = ProjectivePoint::GENERATOR * p;
        let e = self.hash_challenge(&R, &P, m);
        let s = k + e * p;
        let mut delta = Delta::default();
        delta.s = s;
        delta.R = R;
        delta
    }
    fn verify_sign(&self, delta: &Delta, P: &ProjectivePoint, m: &str) -> bool {
        let e = self.hash_challenge(&delta.R, P, m); // compute hash
        let lhs = ProjectivePoint::GENERATOR * delta.s; // multiply pre-signature by curve generator
        let rhs = delta.R + *P * e; // compute R + H(R|P|m)P
        lhs == rhs 
    }
}

impl AS_scheme for Schnorr {
    // Hash function H(R' || P || m)
    fn hash_challenge(&self, R: &ProjectivePoint, P: &ProjectivePoint, message: &str) -> Scalar {
        if message.is_empty() {
            panic!("Message cannot be empty.");
        }
        let mut hasher = Sha256::new(); //init hasher 
        hasher.update(R.to_affine().to_encoded_point(false).as_bytes()); // add R
        hasher.update(P.to_affine().to_encoded_point(false).as_bytes()); // add P 
        hasher.update(message.as_bytes()); // add message 
        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }
    // PreSign: (s', R') = PreSign(p, m, T, r′)
    // p: secret key
    // m : message
    // tweak point T = tG
    //nonce r′
    fn pre_sign(
        &self,
        p: &Scalar,
        m: &str,
        T: &ProjectivePoint,
        r_prime: &Scalar
    ) -> Delta_prime {
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }
        let R_prime = ProjectivePoint::GENERATOR * r_prime + T;
        let P = ProjectivePoint::GENERATOR * p;
        let e = self.hash_challenge(&R_prime, &P, m);
        let s_prime = *r_prime + e * p;
        let mut delta_prime = Delta_prime::default();
        delta_prime.s_prime = s_prime;
        delta_prime.R_prime = R_prime;
        delta_prime
    }

    /// VerifyPreSign: b = Verify(P, m, T, s', R′)
    // P : public key
    fn verify_pre_sign(
        &self,
        P: &ProjectivePoint,
        m: &str,
        T: &ProjectivePoint,
        delta_prime: &Delta_prime)
        -> bool{
            let e = self.hash_challenge(&delta_prime.R_prime, &P, m); // compute hash
            let lhs = ProjectivePoint::GENERATOR * delta_prime.s_prime; // multiply pre-signature by curve generator
            let rhs = delta_prime.R_prime - T + *P * e; // compute R'-T + H(R'|P|m)P
            lhs == rhs 
    }

    /// Adapt: s = s' + t
    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta {
        let mut delta = Delta::default();
        delta.s = delta_prime.s_prime + (*t);
        delta.R = delta_prime.R_prime;
        delta

    }

    /// Extract: t = s - s'
    fn extract_witness(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        delta.s - delta_prime.s_prime
    }
}
