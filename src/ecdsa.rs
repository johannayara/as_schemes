use k256::{
    elliptic_curve::{ff::Field, ops::Reduce, sec1::ToEncodedPoint}, ProjectivePoint, Scalar, U256
};
use sha2::{Digest, Sha256};

use rand_core::OsRng;

use crate::{Delta, Delta_prime, Pi, ZKP, AS_scheme, Sign_scheme};
use crate::utils::{get_x, invert_scalar};


pub struct ECDSA;
impl ZKP for ECDSA{
    fn compute_challenge(&self, P: &ProjectivePoint, Z: &ProjectivePoint, T:&ProjectivePoint, J: &ProjectivePoint, J_prime: &ProjectivePoint) -> Scalar {
        let mut hasher = Sha256::new(); //init hasher 
        hasher.update(ProjectivePoint::GENERATOR.to_affine().to_encoded_point(false).as_bytes()); // add G
        hasher.update(T.to_affine().to_encoded_point(false).as_bytes()); // add T
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
        let e = self.compute_challenge(P, Z, T, &J, &J_prime);
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
        let e_bis = self.compute_challenge(P, Z, T, &J, &J_prime);
        e_bis == pi.e
    }
}
impl Sign_scheme for ECDSA{
    fn sign(&self, p: &Scalar, m: &str, k: &Scalar) -> Delta {
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }
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

impl AS_scheme for ECDSA{
    fn hash_challenge(&self, _R: &ProjectivePoint, _P: &ProjectivePoint, message: &str) -> Scalar {
        if message.is_empty() {
            panic!("Message cannot be empty.");
        }
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
        if m.is_empty() {
            panic!("Message cannot be empty.");
        }

        let R_prime: ProjectivePoint = T * k;
        let R_prime_x = get_x(&R_prime);


        let P: ProjectivePoint = ProjectivePoint :: GENERATOR * p;

        let e = self.hash_challenge(&R_prime, &P, m);
        let k_inv = invert_scalar(&k);
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
        
        let r_prime_x = get_x(&delta_prime.R_prime);

        let s_prime_inv = invert_scalar(&delta_prime.s_prime);
        let e: Scalar = self.hash_challenge(&delta_prime.R_prime, &P, m);
        let rhs_point: ProjectivePoint = (*T * e + delta_prime.Z * r_prime_x) * s_prime_inv;
        let rhs = get_x(&rhs_point);

        r_prime_x == rhs  && self.verify_proof(P, &delta_prime.Z, T, &delta_prime.pi)
    }
    fn adapt_signature(&self, delta_prime: &Delta_prime, t: &Scalar) -> Delta {
        let mut delta = Delta::default();
        let t_inv: Scalar = invert_scalar(t);

        delta.s = delta_prime.s_prime * (t_inv);
        delta.R = delta_prime.R_prime;
        delta
    }

    fn extract_witness(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        let s_inv: Scalar = invert_scalar(&delta.s);
        delta_prime.s_prime * s_inv
    }


}
