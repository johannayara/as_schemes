#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use as_for_fde::{AS_scheme, Sigma, Sigma_prime, Schnorr, Sign_scheme, ECDSA};
use k256::{elliptic_curve::ff::Field, ProjectivePoint, Scalar};
use rand_core::OsRng;
fn main() {
    // Schnorr
    let schnorr: Schnorr = Schnorr;

    // Keys
    let p: Scalar = Scalar::random(&mut OsRng); // secret key
    let P: ProjectivePoint = ProjectivePoint::GENERATOR * &p; // public key

    let t: Scalar = Scalar::random(&mut OsRng); // tweak
    let T: ProjectivePoint = ProjectivePoint::GENERATOR * &t; // tweak point

    let r_prime: Scalar = Scalar::random(&mut OsRng); // nonce
    let k: Scalar = Scalar::random(&mut OsRng); // nonce

    let message: &str = "Adaptor signature message"; //our message
                                                     // Sign
    let sigma: Sigma = schnorr.sign(&p, message, &k);
    println!("s = {:?},\nR = {:?} ", sigma.s, sigma.R);
    // Verify signature
    assert!(schnorr.verify_sign(&sigma, &P, message));
    println!("Signature verified ✅");

    // Pre-sign
    let sigma_prime: Sigma_prime = schnorr.pre_sign(&p, message, &T, &r_prime);
    println!(
        "s_prime = {:?}, R_prime = {:?}",
        sigma_prime.s_prime, sigma_prime.R_prime
    );

    // Verify pre-signature
    assert!(schnorr.verify_pre_sign(&P, message, &T, &sigma_prime));
    println!("Pre-signature verified ✅");

    // Adapt signature
    let sigma: Sigma = schnorr.adapt_signature(&sigma_prime, &t);
    println!("Full signature scalar: {:?}", sigma.s);
    // Verify signature
    assert!(schnorr.verify_sign(&sigma, &P, message));
    println!("Signature verified ✅");
    // Extract witness
    let t_extracted: Scalar = schnorr.extract_witness(&sigma, &sigma_prime);
    assert_eq!(t_extracted, t);
    println!("Extracted tweak matches ✅");
    print!("\n");
    println!("Start ECDSA :");

    // ECDSA
    let ecdsa: ECDSA = ECDSA;

    // Sign
    let sigma: Sigma = ecdsa.sign(&p, message, &k);
    println!("s = {:?},\nR = {:?} ", sigma.s, sigma.R);
    // Verify signature
    assert!(ecdsa.verify_sign(&sigma, &P, message));
    println!("Signature verified ✅");

    // Pre-sign
    let sigma_prime: Sigma_prime = ecdsa.pre_sign(&p, message, &T, &r_prime);
    println!(
        "s_prime = {:?},\nR_prime = {:?}",
        sigma_prime.s_prime, sigma_prime.R_prime
    );

    // Adapt signature
    let sigma: Sigma = ecdsa.adapt_signature(&sigma_prime, &t);
    println!("Full signature scalar: {:?},\nR = {:?}", sigma.s, sigma.R);
    assert!(ecdsa.verify_sign(&sigma, &P, message));
    println!("Signature verified ✅");

    // Extract witness
    let t_extracted: Scalar = ecdsa.extract_witness(&sigma, &sigma_prime);
    assert_eq!(t_extracted, t);
    println!("Extracted tweak matches ✅");

    // Verify pre-signature
    assert!(ecdsa.verify_pre_sign(&P, message, &T, &sigma_prime));
    println!("Pre-signature verified ✅");
}
