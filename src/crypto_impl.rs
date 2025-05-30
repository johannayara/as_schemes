#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use k256::{
    elliptic_curve::{ff::Field, ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint, PrimeField}, AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256
};
use sha2::{Digest, Sha256};

use rand_core::OsRng;

pub struct Delta_prime {
    pub s_prime: Scalar,
    pub R_prime: ProjectivePoint,
    pub Z: ProjectivePoint,
    pub pi: Pi,
}
/// Pre-signature output for adaptor signature scheme
/// Contains s', R', auxiliary point Z, and a zero-knowledge proof `pi`
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

/// Standard signature structure
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

/// Zero-knowledge proof struct
/// Proves knowledge of a scalar `p` such that Z = T * p
pub struct Pi{
    e: Scalar,
    i: Scalar,
}
impl Default for Pi{
    fn default() -> Self {
        Self { e: Scalar::ZERO, i: Scalar::ZERO }
    }
}

/// Trait for constructing and verifying zero-knowledge proofs
pub trait ZKP {
    fn compute_challenge(&self, P: &ProjectivePoint, Z: &ProjectivePoint,T:&ProjectivePoint, J: &ProjectivePoint, J_prime: &ProjectivePoint) -> Scalar;
    fn gen_proof(&self, p: &Scalar, Z: &ProjectivePoint, P: &ProjectivePoint, T: &ProjectivePoint) -> Pi;
    fn verify_proof(&self, P: &ProjectivePoint, Z: &ProjectivePoint, T: &ProjectivePoint, pi: &Pi) -> bool;
}




/// Trait defining adaptor signature operations
pub trait AS_scheme {
    fn hash_challenge(&self, R: &ProjectivePoint, P: &ProjectivePoint, message: &str) -> Scalar;
    /**
     * Generates a pre-signature (s', R') using the secret key, message, and tweak point.
     *
     * # Arguments
     * * `p` - Secret key.
     * * `m` - Message.
     * * `T` - Tweak point.
     * * `r_prime` - Ephemeral scalar (random nonce).
     */
    fn pre_sign(
        &self,
        p: &Scalar,
        m: &str,
        T: &ProjectivePoint,
        r_prime: &Scalar
    ) -> Delta_prime;
        /**
     * Verifies a pre-signature with respect to a public key, message, and tweak point.
     *
     * # Returns
     * * `bool` - True if valid, false otherwise.
     */
    fn verify_pre_sign(
        &self,
        P: &ProjectivePoint,
        m: &str,
        T: &ProjectivePoint,
        delta_prime: &Delta_prime
    ) -> bool;
    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta;
    fn extract_witness(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar;
}
pub trait Sign_scheme{
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta;
    fn verify_sign(&self, delta: &Delta, P: &ProjectivePoint, m: &str) -> bool;
}






