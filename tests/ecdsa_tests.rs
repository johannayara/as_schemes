#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

#[cfg(test)]
mod tests {
    use super::*;
    use as_for_fde::{ECDSA, Delta, Delta_prime, AS_scheme, Sign_scheme};
    use rand_core::OsRng;
    use k256::{
        elliptic_curve::{ff::Field}, ProjectivePoint, Scalar
    };
    

    #[test]
    fn sign_works() {
        let ecdsa: ECDSA = ECDSA;
        // Keys
        let p: Scalar = Scalar::random(&mut OsRng); // secret key
        let P: ProjectivePoint = ProjectivePoint::GENERATOR * &p; // public key

        let t: Scalar = Scalar::random(&mut OsRng); // tweak
        let _T: ProjectivePoint = ProjectivePoint::GENERATOR * &t; // tweak point

        let _r_prime: Scalar = Scalar::random(&mut OsRng); // nonce
        let k: Scalar = Scalar::random(&mut OsRng); // nonce

        let message: &str = "Adaptor signature message"; //our message 
        // Sign 
        let delta: Delta = schnorr.sign(&p, message, &k);
        assert!(schnorr.verify_sign( &delta, &P, message));
        println!("Signature verified ✅");
    }
}


