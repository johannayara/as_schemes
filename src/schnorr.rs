use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    ProjectivePoint, Scalar, U256,
};
use sha2::{Digest, Sha256};

use crate::{AS_scheme, Delta, Delta_prime, Sign_scheme};

/// `Schnorr` implements the Schnorr digital signature scheme and its adaptor variant.
#[derive(Clone)]
pub struct Schnorr;

impl Sign_scheme for Schnorr {
    /// Signs a message `m` using secret key `p` and nonce `k`.
    ///
    /// # Arguments
    /// * `p` - Secret signing key
    /// * `m` - Message to sign
    /// * `k` - Random nonce
    ///
    /// # Returns
    /// * `Delta` - Standard Schnorr signature `(s, R)`
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta {
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }
        let R = ProjectivePoint::GENERATOR * k;
        let P = ProjectivePoint::GENERATOR * p;
        let e = self.hash_challenge(&R, &P, m);
        let s = k + e * p;
        Delta { s, R }
    }

    /// Verifies a standard Schnorr signature.
    ///
    /// # Arguments
    /// * `delta` - Signature `(s, R)` to verify
    /// * `P` - Public key corresponding to the secret key `p`
    /// * `m` - Message that was signed
    ///
    /// # Returns
    /// * `bool` - True if the signature is valid
    fn verify_sign(&self, delta: &Delta, P: &ProjectivePoint, m: &str) -> bool {
        let e = self.hash_challenge(&delta.R, P, m); // compute hash
        let lhs = ProjectivePoint::GENERATOR * delta.s; // multiply pre-signature by curve generator
        let rhs = delta.R + *P * e; // compute R + H(R|P|m)P
        lhs == rhs
    }
}

impl AS_scheme for Schnorr {
    /// Computes a challenge scalar using a hash of `(R || P || m)`.
    ///
    /// # Arguments
    /// * `R` - Commitment point
    /// * `P` - Public key
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// * `Scalar` - Challenge derived from hash
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

    /// Creates a Schnorr adaptor pre-signature `(s', R')` with a tweak point `T = tG`.
    ///
    /// # Arguments
    /// * `p` - Secret key
    /// * `m` - Message to sign
    /// * `T` - Tweak point (derived from secret witness `t`)
    /// * `r_prime` - Random nonce
    ///
    /// # Returns
    /// * `Delta_prime` - Adaptor pre-signature
    fn pre_sign(&self, p: &Scalar, m: &str, T: &ProjectivePoint, r_prime: &Scalar) -> Delta_prime {
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }
        let R_prime = ProjectivePoint::GENERATOR * r_prime + T;
        let P = ProjectivePoint::GENERATOR * p;
        let e = self.hash_challenge(&R_prime, &P, m);
        let s_prime = *r_prime + e * p;
        Delta_prime {
            s_prime,
            R_prime,
            ..Default::default()
        }
    }

    /// Verifies a Schnorr adaptor pre-signature.
    ///
    /// # Arguments
    /// * `P` - Signer's public key
    /// * `m` - Message
    /// * `T` - Tweak point used in pre-signature
    /// * `delta_prime` - Adaptor pre-signature `(s', R')`
    ///
    /// # Returns
    /// * `bool` - True if pre-signature is valid
    fn verify_pre_sign(
        &self,
        P: &ProjectivePoint,
        m: &str,
        T: &ProjectivePoint,
        delta_prime: &Delta_prime,
    ) -> bool {
        let e = self.hash_challenge(&delta_prime.R_prime, &P, m); // compute hash
        let lhs = ProjectivePoint::GENERATOR * delta_prime.s_prime; // multiply pre-signature by curve generator
        let rhs = delta_prime.R_prime - T + *P * e; // compute R'-T + H(R'|P|m)P
        lhs == rhs
    }

    /// Adapts a pre-signature into a valid signature using secret witness `t`.
    ///
    /// # Arguments
    /// * `delta_prime` - Pre-signature `(s', R')`
    /// * `t` - Secret tweak scalar
    ///
    /// # Returns
    /// * `Delta` - Final adapted signature `(s, R)` such that $s = s' + t$
    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta {
        let s = delta_prime.s_prime + (*t);
        Delta {
            s,
            R: delta_prime.R_prime,
        }
    }

    /// Extracts the witness `t` used to adapt the pre-signature into the full signature.
    ///
    /// # Arguments
    /// * `delta` - Final signature `(s, R)`
    /// * `delta_prime` - Pre-signature `(s', R')`
    ///
    /// # Returns
    /// * `Scalar` - Extracted secret tweak `t` such that $t = s - s'$
    fn extract_witness(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        delta.s - delta_prime.s_prime
    }
}
