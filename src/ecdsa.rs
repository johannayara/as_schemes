use k256::{
    elliptic_curve::{ff::Field, ops::Reduce, sec1::ToEncodedPoint},
    ProjectivePoint, Scalar, U256,
};
use sha2::{Digest, Sha256};

use rand_core::OsRng;

use crate::utils::{get_x, invert_scalar};
use crate::{AS_scheme, Sigma, Sigma_prime, Pi, Sign_scheme, ZKP};

/// `ECDSA` implements the Elliptic Curve Digital Signature Algorithm and its adaptor variant,
/// including its zero-knowledge proof.
#[derive(Clone)]
pub struct ECDSA;
impl ZKP for ECDSA {
    /// Computes a Fiat–Shamir challenge `e` for a zero-knowledge proof,
    /// using public data and hashing it to a scalar.
    ///
    /// # Arguments
    /// * `P` - Public key corresponding to secret `p`
    /// * `Z` - Tweaked public key (T * p)
    /// * `T` - Tweak point
    /// * `J`, `J_prime` - Commitment points used in the proof
    ///
    /// # Returns
    /// * `Scalar` - The derived challenge value
    fn compute_challenge(
        &self,
        P: &ProjectivePoint,
        Z: &ProjectivePoint,
        T: &ProjectivePoint,
        J: &ProjectivePoint,
        J_prime: &ProjectivePoint,
    ) -> Scalar {
        let mut hasher = Sha256::new(); //init hasher
        hasher.update(
            ProjectivePoint::GENERATOR
                .to_affine()
                .to_encoded_point(false)
                .as_bytes(),
        ); // add G
        hasher.update(T.to_affine().to_encoded_point(false).as_bytes()); // add T
        hasher.update(P.to_affine().to_encoded_point(false).as_bytes()); // add P
        hasher.update(Z.to_affine().to_encoded_point(false).as_bytes()); // add Z
        hasher.update(J.to_affine().to_encoded_point(false).as_bytes()); // add J
        hasher.update(J_prime.to_affine().to_encoded_point(false).as_bytes()); // add J'
        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }

    /// Generates a zero-knowledge proof `Pi` that the prover has set `Z ` such that $\log_T(Z) = \log_G(P)$.
    ///
    /// # Arguments
    /// * `p` - Secret scalar
    /// * `Z` - Public commitment (T * p)
    /// * `P` - Public key (G * p)
    /// * `T` - Tweak point
    ///
    /// # Returns
    /// * `Pi` - The generated zero-knowledge proof
    fn gen_proof(
        &self,
        p: &Scalar,
        Z: &ProjectivePoint,
        P: &ProjectivePoint,
        T: &ProjectivePoint,
    ) -> Pi {
        let j = Scalar::random(&mut OsRng);
        let J = ProjectivePoint::GENERATOR * j;
        let J_prime = *T * j;
        let e = self.compute_challenge(P, Z, T, &J, &J_prime);
        let i = j + e * p;
        Pi { e: e, i: i }
    }

    /// Verifies a zero-knowledge proof that a prover has set `Z ` such that $\log_T(Z) = \log_G(P)$.
    ///
    /// # Arguments
    /// * `P` - Public key
    /// * `Z` - Tweaked public key
    /// * `T` - Tweak point
    /// * `pi` - Proof object
    ///
    /// # Returns
    /// * `bool` - True if proof is valid, false otherwise
    fn verify_proof(
        &self,
        P: &ProjectivePoint,
        Z: &ProjectivePoint,
        T: &ProjectivePoint,
        pi: &Pi,
    ) -> bool {
        let J = ProjectivePoint::GENERATOR * pi.i - (*P * pi.e);
        let J_prime = *T * pi.i - (*Z * pi.e);
        let e_bis = self.compute_challenge(P, Z, T, &J, &J_prime);
        e_bis == pi.e
    }
}
impl Sign_scheme for ECDSA {
    /// Generates a standard ECDSA-style signature.
    ///
    /// # Arguments
    /// * `p` - Secret key scalar
    /// * `m` - Message to be signed
    /// * `k` - Random nonce scalar
    ///
    /// # Returns
    /// * `Sigma` - Signature containing `(s, R)`
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Sigma {
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }
        let R = ProjectivePoint::GENERATOR * k;
        let P = ProjectivePoint::GENERATOR * p;
        let r_x = get_x(&R);
        let e = self.hash_challenge(&R, &P, m);
        let k_inv = invert_scalar(k);
        let s = k_inv * (e + *p * r_x);
        Sigma { s: s, R: R }
    }

    /// Verifies a standard ECDSA signature.
    ///
    /// # Arguments
    /// * `sigma` - Signature to verify
    /// * `P` - Signer's public key
    /// * `m` - Message that was signed
    ///
    /// # Returns
    /// * `bool` - True if valid, false otherwise
    fn verify_sign(&self, sigma: &Sigma, P: &ProjectivePoint, m: &str) -> bool {
        let r_x = get_x(&sigma.R);
        let e: Scalar = self.hash_challenge(&sigma.R, P, m);
        let s_inv = invert_scalar(&sigma.s);
        let rhs_point: ProjectivePoint = (ProjectivePoint::GENERATOR * e + *P * r_x) * s_inv;
        let rhs = get_x(&rhs_point);
        r_x == rhs
    }
}

impl AS_scheme for ECDSA {
    /// Hashes a message into a challenge scalar.
    ///
    /// # Arguments
    /// * `message` - The message to hash
    ///
    /// # Returns
    /// * `Scalar` - Hash challenge scalar
    fn hash_challenge(&self, _R: &ProjectivePoint, _P: &ProjectivePoint, message: &str) -> Scalar {
        if message.is_empty() {
            panic!("Message cannot be empty.");
        }
        let mut hasher = Sha256::new(); //init hasher
        hasher.update(message.as_bytes()); // add message
        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }

    /// Produces an adaptor pre-signature `Sigma'` with a ZK proof of correctness.
    ///
    /// # Arguments
    /// * `p` - Secret key
    /// * `m` - Message
    /// * `T` - Tweak point
    /// * `k` - Random nonce
    ///
    /// # Returns
    /// * `Sigma_prime` - Adaptor pre-signature
    fn pre_sign(&self, p: &Scalar, m: &str, T: &ProjectivePoint, k: &Scalar) -> Sigma_prime {
        // s' = k⁻1(H(m)+r'_xtP)
        // R' = k·T
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }

        let R_prime: ProjectivePoint = T * k;
        let R_prime_x = get_x(&R_prime);

        let P: ProjectivePoint = ProjectivePoint::GENERATOR * p;

        let e = self.hash_challenge(&R_prime, &P, m);
        let k_inv = invert_scalar(&k);
        let s_prime = k_inv * (e + R_prime_x * p);
        let Z = T * p;
        Sigma_prime {
            s_prime,
            R_prime,
            Z,
            pi: self.gen_proof(p, &Z, &P, T),
            ..Default::default()
        }
    }

    /// Verifies the validity of an adaptor pre-signature.
    ///
    /// # Arguments
    /// * `P` - Public key
    /// * `m` - Message
    /// * `T` - Tweak point
    /// * `sigma_prime` - Pre-signature
    ///
    /// # Returns
    /// * `bool` - True if pre-signature is valid
    fn verify_pre_sign(
        &self,
        P: &ProjectivePoint,
        m: &str,
        T: &ProjectivePoint,
        sigma_prime: &Sigma_prime,
    ) -> bool {
        let r_prime_x = get_x(&sigma_prime.R_prime);

        let s_prime_inv = invert_scalar(&sigma_prime.s_prime);
        let e: Scalar = self.hash_challenge(&sigma_prime.R_prime, &P, m);
        let rhs_point: ProjectivePoint = (*T * e + sigma_prime.Z * r_prime_x) * s_prime_inv;
        let rhs = get_x(&rhs_point);

        r_prime_x == rhs && self.verify_proof(P, &sigma_prime.Z, T, &sigma_prime.pi)
    }

    /// Adapts a pre-signature `Sigma'` into a valid full signature using secret `t`.
    ///
    /// # Arguments
    /// * `sigma_prime` - Pre-signature
    /// * `t` - Tweak scalar used to adapt the signature
    ///
    /// # Returns
    /// * `Sigma` - Final adapted signature (s,R) such that $s = s' t^{-1}$
    fn adapt_signature(&self, sigma_prime: &Sigma_prime, t: &Scalar) -> Sigma {
        let t_inv = invert_scalar(t);
        let s = sigma_prime.s_prime * t_inv;
        Sigma {
            s,
            R: sigma_prime.R_prime,
        }
    }

    /// Extracts the secret tweak `t` from a known signature and its pre-signature form.
    ///
    /// # Arguments
    /// * `sigma` - Final signature
    /// * `sigma_prime` - Pre-signature
    ///
    /// # Returns
    /// * `Scalar` - Extracted secret tweak `t` such that $t = s' s^{-1}$
    fn extract_witness(&self, sigma: &Sigma, sigma_prime: &Sigma_prime) -> Scalar {
        let s_inv: Scalar = invert_scalar(&sigma.s);
        sigma_prime.s_prime * s_inv
    }
}
