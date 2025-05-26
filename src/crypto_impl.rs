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

pub struct Pi{
    e: Scalar,
    i: Scalar,
}
impl Default for Pi{
    fn default() -> Self {
        Self { e: Scalar::ZERO, i: Scalar::ZERO }
    }
}

pub trait ZKP {
    fn compute_challenge(&self, P: &ProjectivePoint, Z: &ProjectivePoint, J: &ProjectivePoint, J_prime: &ProjectivePoint) -> Scalar;
    fn gen_proof(&self, p: &Scalar, Z: &ProjectivePoint, P: &ProjectivePoint, T: &ProjectivePoint) -> Pi;
    fn verify_proof(&self, P: &ProjectivePoint, Z: &ProjectivePoint, T: &ProjectivePoint, pi: &Pi) -> bool;
}

fn get_x(W: &ProjectivePoint) -> Scalar{
    let w_x = match Scalar::from_repr(W.to_affine().x()).into_option() {
            Some(s) => s,
            None => {
                eprintln!("Invalid x-coordinate of R': cannot convert to Scalar.");
                return Scalar::ZERO;
            }
        };
    return w_x;
}

fn invert_scalar(s: &Scalar) -> Scalar{
    let s_inv = match s.invert().into_option() {
            Some(inv) => inv,
            None => {
                eprintln!("s' is not invertible (possibly zero).");
                return Scalar::ZERO;
            }
        };
    return s_inv;
}


impl ZKP for ECDSA{
    fn compute_challenge(&self, P: &ProjectivePoint, Z: &ProjectivePoint, J: &ProjectivePoint, J_prime: &ProjectivePoint) -> Scalar {
        let mut hasher = Sha256::new(); //init hasher 
        hasher.update(P.to_affine().to_encoded_point(false).as_bytes()); // add P
        hasher.update(Z.to_affine().to_encoded_point(false).as_bytes()); // add Z
        hasher.update(J.to_affine().to_encoded_point(false).as_bytes()); // add J
        hasher.update(J_prime.to_affine().to_encoded_point(false).as_bytes()); // add J'
        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }
    fn gen_proof(&self, p: &Scalar, Z: &ProjectivePoint, P: &ProjectivePoint, T: &ProjectivePoint) -> Pi{
        let j = Scalar::random(&mut OsRng); 
        let J = ProjectivePoint::GENERATOR * j;
        let J_prime = *T * j;
        let e = self.compute_challenge(P, Z, &J, &J_prime);
        let i = j + e*p;

        let  pi = Pi{
            e: e,
            i: i,
        };
        pi
    }

    fn verify_proof(&self, P: &ProjectivePoint, Z: &ProjectivePoint, T: &ProjectivePoint, pi: &Pi) -> bool{
        let J = ProjectivePoint::GENERATOR * pi.i - (*P * pi.e);
        let J_prime = *T * pi.i - (*Z * pi.e);
        let e_bis = self.compute_challenge(P, Z, &J, &J_prime);
        e_bis == pi.e
    }
}

pub trait AS_scheme {
    fn hash_challenge(&self, R: &ProjectivePoint, P: &ProjectivePoint, message: &str) -> Scalar;
    fn pre_sign(
        &self,
        p: &Scalar,
        m: &str,
        T: &ProjectivePoint,
        r_prime: &Scalar
    ) -> Delta_prime;
    fn verify_pre_sign(
        &self,
        P: &ProjectivePoint,
        m: &str,
        T: &ProjectivePoint,
        delta_prime: &Delta_prime
    ) -> bool;
    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta;
    fn extract_witness(&self, s: &Delta, delta_prime: &Delta_prime) -> Scalar;
}
pub trait Sign_scheme{
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta;
    fn verify_sign(&self, delta: &Delta, P: &ProjectivePoint, m: &str) -> bool;
}

impl Sign_scheme for Schnorr{
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta {
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

impl Sign_scheme for ECDSA{
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta {
        let R = ProjectivePoint::GENERATOR * k;
        let P = ProjectivePoint::GENERATOR * p;
        let r_x = get_x(&R);
        let e = self.hash_challenge(&R, &P, m);
        let k_inv = invert_scalar(k);
        let s = k_inv * (e + *p * r_x);
        let delta = Delta { s: s, R: R };
        delta
    }

    fn verify_sign(&self, delta: &Delta, P: &ProjectivePoint, m: &str) -> bool {
        let r_x = get_x(&delta.R);
        let e: Scalar = self.hash_challenge(&delta.R ,P, m);
        let s_inv = invert_scalar(&delta.s);
        let rhs_point: ProjectivePoint = (ProjectivePoint::GENERATOR * e + *P * r_x) * s_inv;
        let rhs = get_x(&rhs_point);
        r_x == rhs
    }
}
pub struct Schnorr;
pub struct ECDSA;

impl AS_scheme for Schnorr {
    // Hash function H(R' || P || m)
    fn hash_challenge(&self, R: &ProjectivePoint, P: &ProjectivePoint, message: &str) -> Scalar {
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


impl AS_scheme for ECDSA{
    fn hash_challenge(&self, _R: &ProjectivePoint, _P: &ProjectivePoint, message: &str) -> Scalar {
        let mut hasher = Sha256::new(); //init hasher 
        hasher.update(message.as_bytes()); // add message 
        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }
    fn pre_sign(
            &self,
            p: &Scalar,
            m: &str,
            T: &ProjectivePoint,
            k: &Scalar,
        ) -> Delta_prime {
        // s' = k⁻1(H(m)+r'_xtP)
        // R' = k·T
        let R_prime: ProjectivePoint = T * k;
        let r_affine : AffinePoint = R_prime.to_affine();
        let R_prime_x = Scalar::from_repr(r_affine.x()).unwrap();


        let P: ProjectivePoint = ProjectivePoint :: GENERATOR * p;

        let e = self.hash_challenge(&R_prime, &P, m);
        let k_inv = k.invert().unwrap();
        let s_prime = k_inv * (e + R_prime_x * p);
        let mut delta_prime = Delta_prime::default();
        delta_prime.s_prime = s_prime;
        delta_prime.R_prime = R_prime;
        delta_prime.Z = T*p;
        delta_prime.pi = self.gen_proof(&p, &delta_prime.Z, &P, &T);
        delta_prime
    }
    fn verify_pre_sign(
            &self,
            P: &ProjectivePoint,
            m: &str,
            T: &ProjectivePoint,
            delta_prime: &Delta_prime,
        ) -> bool {
        let r_affine : AffinePoint = delta_prime.R_prime.to_affine();

        let lhs: FieldBytes = r_affine.x();
        
        // Try converting x-coordinate to Scalar
        let r_prime_x = match Scalar::from_repr(r_affine.x()).into_option() {
            Some(s) => s,
            None => {
                eprintln!("Invalid x-coordinate of R': cannot convert to Scalar.");
                return false;
            }
        };

        // Try inverting s'
        let s_prime_inv = match delta_prime.s_prime.invert().into_option() {
            Some(inv) => inv,
            None => {
                eprintln!("s' is not invertible (possibly zero).");
                return false;
            }
        };
        //let s_prime_inv: Scalar = delta_prime.s_prime.invert().unwrap();
        let e: Scalar = self.hash_challenge(&delta_prime.R_prime, &P, m);
        let rhs_point: ProjectivePoint = (*T * e + delta_prime.Z * r_prime_x) * s_prime_inv;
        let rhs = rhs_point.to_affine().x();

        lhs == rhs  && self.verify_proof(P, &delta_prime.Z, T, &delta_prime.pi)
    }
    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta {
        let mut delta = Delta::default();
        let t_inv: Scalar = t.invert().unwrap();

        delta.s = delta_prime.s_prime * (t_inv);
        delta.R = delta_prime.R_prime;
        delta
    }

    fn extract_witness(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        let s_inv: Scalar = delta.s.invert().unwrap();
        delta_prime.s_prime * s_inv
    }


}
