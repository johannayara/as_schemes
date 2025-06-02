#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

pub mod ecdsa;
pub mod scheme;
pub mod schnorr;
pub mod utils;

pub use ecdsa::ECDSA;
pub use scheme::Scheme;
pub use schnorr::Schnorr;

use k256::{ProjectivePoint, Scalar};

// Common structs

#[derive(Debug)]
pub struct Delta_prime {
    pub s_prime: Scalar,
    pub R_prime: ProjectivePoint,
    pub Z: ProjectivePoint,
    pub pi: Pi,
}

impl Default for Delta_prime {
    fn default() -> Self {
        Self {
            s_prime: Scalar::ZERO,
            R_prime: ProjectivePoint::IDENTITY,
            Z: ProjectivePoint::IDENTITY,
            pi: Pi::default(),
        }
    }
}

#[derive(Debug)]
pub struct Delta {
    pub s: Scalar,
    pub R: ProjectivePoint,
}

impl Default for Delta {
    fn default() -> Self {
        Self {
            s: Scalar::ZERO,
            R: ProjectivePoint::IDENTITY,
        }
    }
}

#[derive(Debug)]
pub struct Pi {
    pub e: Scalar,
    pub i: Scalar,
}

impl Default for Pi {
    fn default() -> Self {
        Self {
            e: Scalar::ZERO,
            i: Scalar::ZERO,
        }
    }
}

// Traits

pub trait ZKP {
    fn compute_challenge(
        &self,
        P: &ProjectivePoint,
        Z: &ProjectivePoint,
        T: &ProjectivePoint,
        J: &ProjectivePoint,
        J_prime: &ProjectivePoint,
    ) -> Scalar;
    fn gen_proof(
        &self,
        p: &Scalar,
        Z: &ProjectivePoint,
        P: &ProjectivePoint,
        T: &ProjectivePoint,
    ) -> Pi;
    fn verify_proof(
        &self,
        P: &ProjectivePoint,
        Z: &ProjectivePoint,
        T: &ProjectivePoint,
        pi: &Pi,
    ) -> bool;
}

pub trait AS_scheme {
    fn hash_challenge(&self, R: &ProjectivePoint, P: &ProjectivePoint, message: &str) -> Scalar;
    fn pre_sign(&self, p: &Scalar, m: &str, T: &ProjectivePoint, r_prime: &Scalar) -> Delta_prime;
    fn verify_pre_sign(
        &self,
        P: &ProjectivePoint,
        m: &str,
        T: &ProjectivePoint,
        delta_prime: &Delta_prime,
    ) -> bool;
    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta;
    fn extract_witness(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar;
}

pub trait Sign_scheme {
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta;
    fn verify_sign(&self, delta: &Delta, P: &ProjectivePoint, m: &str) -> bool;
}
