#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

#[cfg(test)]
mod tests {
    use as_for_fde::{AS_scheme, Delta, Delta_prime, Sign_scheme, ECDSA};
    use k256::{elliptic_curve::ff::Field, ProjectivePoint, Scalar};
    use rand_core::OsRng;

    #[test]
    fn sign_works() {
        let ecdsa: ECDSA = ECDSA;
        // Keys
        let p: Scalar = Scalar::random(&mut OsRng); // secret key
        let P: ProjectivePoint = ProjectivePoint::GENERATOR * &p; // public key

        let t: Scalar = Scalar::random(&mut OsRng); // tweak
        let _T: ProjectivePoint = ProjectivePoint::GENERATOR * &t; // tweak point

        let k: Scalar = Scalar::random(&mut OsRng); // nonce

        let message: &str = "Testing message for ecdsa"; //our message
                                                         // Sign
        let delta: Delta = ecdsa.sign(&p, message, &k);
        assert!(ecdsa.verify_sign(&delta, &P, message));
        println!("Signature verified ✅");
    }
    #[test]
    fn signature_fails_when_s_tampered() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let P = ProjectivePoint::GENERATOR * &p;
        let k = Scalar::random(&mut OsRng);
        let message = "Message";

        let mut delta = ecdsa.sign(&p, message, &k);
        delta.s += Scalar::ONE; // tamper

        assert!(!ecdsa.verify_sign(&delta, &P, message));
    }
    #[test]
    fn signature_fails_when_R_tampered() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let P = ProjectivePoint::GENERATOR * &p;
        let k = Scalar::random(&mut OsRng);
        let message = "Another message";

        let mut delta = ecdsa.sign(&p, message, &k);
        delta.R = delta.R + ProjectivePoint::GENERATOR; // tamper

        assert!(!ecdsa.verify_sign(&delta, &P, message));
    }

    #[test]
    fn signature_fails_on_wrong_message() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let P = ProjectivePoint::GENERATOR * &p;
        let k = Scalar::random(&mut OsRng);
        let message = "Original";
        let fake_message = "Tampered";

        let delta = ecdsa.sign(&p, message, &k);
        assert!(!ecdsa.verify_sign(&delta, &P, fake_message));
    }
    #[test]
    fn proof_verification_fails_if_tampered() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let P = ProjectivePoint::GENERATOR * &p;
        let t = Scalar::random(&mut OsRng);
        let T = ProjectivePoint::GENERATOR * &t;
        let k = Scalar::random(&mut OsRng);
        let message = "ZK test";

        let mut delta_prime = ecdsa.pre_sign(&p, message, &T, &k);
        delta_prime.pi.e += Scalar::ONE; // tamper the proof

        assert!(!ecdsa.verify_pre_sign(&P, message, &T, &delta_prime));
    }

    #[test]
    fn pre_sign_works() {
        let ecdsa: ECDSA = ECDSA;
        // Keys
        let p: Scalar = Scalar::random(&mut OsRng); // secret key
        let P: ProjectivePoint = ProjectivePoint::GENERATOR * &p; // public key

        let t: Scalar = Scalar::random(&mut OsRng); // tweak
        let T: ProjectivePoint = ProjectivePoint::GENERATOR * &t; // tweak point

        let k: Scalar = Scalar::random(&mut OsRng); // nonce

        let message: &str = "Test message for ecdsa pre-sign"; //our message
                                                               // Pre-sign
        let delta_prime: Delta_prime = ecdsa.pre_sign(&p, message, &T, &k);
        assert!(ecdsa.verify_pre_sign(&P, message, &T, &delta_prime,));
        println!("Pre-signature verified ✅");
    }

    #[test]
    fn adapt_sign_works() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let P = ProjectivePoint::GENERATOR * &p;
        let t = Scalar::random(&mut OsRng);
        let T = ProjectivePoint::GENERATOR * &t;
        let k = Scalar::random(&mut OsRng);
        let message = "Adapting signature";

        let delta_prime = ecdsa.pre_sign(&p, message, &T, &k);
        let delta = ecdsa.adapt_signature(&delta_prime, &t);

        assert!(ecdsa.verify_sign(&delta, &P, message));
    }
    #[test]
    fn witness_extraction_works() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let t = Scalar::random(&mut OsRng);
        let T = ProjectivePoint::GENERATOR * &t;
        let k = Scalar::random(&mut OsRng);
        let message = "Extract witness test";

        let delta_prime = ecdsa.pre_sign(&p, message, &T, &k);
        let delta = ecdsa.adapt_signature(&delta_prime, &t);
        let extracted = ecdsa.extract_witness(&delta, &delta_prime);

        assert_eq!(extracted, t);
    }

    #[test]
    #[should_panic(expected = "Message cannot be empty.")]
    fn sign_fails_on_empty_message() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);
        let _ = ecdsa.sign(&p, "", &k);
    }

    #[test]
    #[should_panic(expected = "Message cannot be empty.")]
    fn presign_fails_on_empty_message() {
        let ecdsa = ECDSA;
        let p = Scalar::random(&mut OsRng);
        let t = Scalar::random(&mut OsRng);
        let T = ProjectivePoint::GENERATOR * &t;
        let k = Scalar::random(&mut OsRng);
        let _ = ecdsa.pre_sign(&p, "", &T, &k);
    }
}
