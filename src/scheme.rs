use crate::{Delta, Delta_prime, AS_scheme, Sign_scheme, ECDSA, Schnorr};
use k256::{ProjectivePoint, Scalar};

#[derive(Clone)]
pub enum Scheme {
    Schnorr(Schnorr),
    ECDSA(ECDSA),
}



impl Sign_scheme for Scheme {
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta {
        match self {
            Scheme::Schnorr(s) => s.sign(p, m, k),
            Scheme::ECDSA(e) => e.sign(p, m, k),
        }
    }

    fn verify_sign(&self, delta: &Delta, P: &ProjectivePoint, m: &str) -> bool {
        match self {
            Scheme::Schnorr(s) => s.verify_sign(delta, P, m),
            Scheme::ECDSA(e) => e.verify_sign(delta, P, m),
        }
    }
}

impl AS_scheme for Scheme {
    fn pre_sign(&self, p: &Scalar, m: &str, T: &ProjectivePoint, k: &Scalar) -> Delta_prime {
        match self {
            Scheme::Schnorr(s) => s.pre_sign(p, m, T, k),
            Scheme::ECDSA(e) => e.pre_sign(p, m, T, k),
        }
    }

    fn verify_pre_sign(&self, P: &ProjectivePoint, m: &str, T: &ProjectivePoint, delta_prime: &Delta_prime) -> bool {
        match self {
            Scheme::Schnorr(s) => s.verify_pre_sign(P, m, T, delta_prime),
            Scheme::ECDSA(e) => e.verify_pre_sign(P, m, T, delta_prime),
        }
    }

    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta {
        match self {
            Scheme::Schnorr(s) => s.adapt_signature(delta_prime, t),
            Scheme::ECDSA(e) => e.adapt_signature(delta_prime, t),
        }
    }

    fn extract_witness(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        match self {
            Scheme::Schnorr(s) => s.extract_witness(delta, delta_prime),
            Scheme::ECDSA(e) => e.extract_witness(delta, delta_prime),
        }
    }

    fn hash_challenge(&self, R: &ProjectivePoint, P: &ProjectivePoint, message: &str) -> Scalar {
        match self {
            Scheme::Schnorr(s) => s.hash_challenge(R, P, message),
            Scheme::ECDSA(e) => e.hash_challenge(R, P, message),
        }
    }
}
