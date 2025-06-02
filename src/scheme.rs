use crate::{AS_scheme, Sigma, Sigma_prime, Schnorr, Sign_scheme, ECDSA};
use k256::{ProjectivePoint, Scalar};

#[derive(Clone)]
pub enum Scheme {
    Schnorr(Schnorr),
    ECDSA(ECDSA),
}

impl Sign_scheme for Scheme {
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Sigma {
        match self {
            Scheme::Schnorr(s) => s.sign(p, m, k),
            Scheme::ECDSA(e) => e.sign(p, m, k),
        }
    }

    fn verify_sign(&self, sigma: &Sigma, P: &ProjectivePoint, m: &str) -> bool {
        match self {
            Scheme::Schnorr(s) => s.verify_sign(sigma, P, m),
            Scheme::ECDSA(e) => e.verify_sign(sigma, P, m),
        }
    }
}

impl AS_scheme for Scheme {
    fn pre_sign(&self, p: &Scalar, m: &str, T: &ProjectivePoint, k: &Scalar) -> Sigma_prime {
        match self {
            Scheme::Schnorr(s) => s.pre_sign(p, m, T, k),
            Scheme::ECDSA(e) => e.pre_sign(p, m, T, k),
        }
    }

    fn verify_pre_sign(
        &self,
        P: &ProjectivePoint,
        m: &str,
        T: &ProjectivePoint,
        sigma_prime: &Sigma_prime,
    ) -> bool {
        match self {
            Scheme::Schnorr(s) => s.verify_pre_sign(P, m, T, sigma_prime),
            Scheme::ECDSA(e) => e.verify_pre_sign(P, m, T, sigma_prime),
        }
    }

    fn adapt_signature(&self, sigma_prime: &Sigma_prime, t: &Scalar) -> Sigma {
        match self {
            Scheme::Schnorr(s) => s.adapt_signature(sigma_prime, t),
            Scheme::ECDSA(e) => e.adapt_signature(sigma_prime, t),
        }
    }

    fn extract_witness(&self, sigma: &Sigma, sigma_prime: &Sigma_prime) -> Scalar {
        match self {
            Scheme::Schnorr(s) => s.extract_witness(sigma, sigma_prime),
            Scheme::ECDSA(e) => e.extract_witness(sigma, sigma_prime),
        }
    }

    fn hash_challenge(&self, R: &ProjectivePoint, P: &ProjectivePoint, message: &str) -> Scalar {
        match self {
            Scheme::Schnorr(s) => s.hash_challenge(R, P, message),
            Scheme::ECDSA(e) => e.hash_challenge(R, P, message),
        }
    }
}
