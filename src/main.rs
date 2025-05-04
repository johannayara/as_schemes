use k256::{
    Scalar, ProjectivePoint, PublicKey,
    elliptic_curve::{sec1::ToEncodedPoint},
};
use sha2::{Sha256, Digest};

/// Hash function H(R' || P || m)
fn hash_challenge(R: &ProjectivePoint, P: &ProjectivePoint, message: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(R.to_affine().to_encoded_point(false).as_bytes());
    hasher.update(P.to_affine().to_encoded_point(false).as_bytes());
    hasher.update(message);
    Scalar::from_bytes_reduced(hasher.finalize().into())
}

/// PreSign: (s', R') = PreSign(p, m, T, r′)
pub fn pre_sign(
    p: &Scalar,                 // secret key
    m: &[u8],                   // message
    T: &ProjectivePoint,        // tweak point T = tG
    r_prime: &Scalar            // nonce r′
) -> (Scalar, ProjectivePoint) {
    let R_prime = ProjectivePoint::generator() * r_prime + T;
    let P = ProjectivePoint::generator() * p;
    let e = hash_challenge(&R_prime, &P, m);
    let s_prime = *r_prime + e * p;
    (s_prime, R_prime)
}

/// VerifyPreSign: b = Verify(P, m, T, s', R′)
pub fn verify_pre_sign(
    P: &ProjectivePoint,        // public key
    m: &[u8],
    T: &ProjectivePoint,
    s_prime: &Scalar,
    R_prime: &ProjectivePoint
) -> bool {
    let e = hash_challenge(R_prime, P, m);
    let lhs = ProjectivePoint::generator() * s_prime;
    let rhs = *R_prime - T + *P * e;
    lhs == rhs
}

/// Adapt: s = s' + t
pub fn adapt_signature(s_prime: &Scalar, t: &Scalar) -> Scalar {
    s_prime + t
}

/// Extract: t = s - s'
pub fn extract_witness(s: &Scalar, s_prime: &Scalar) -> Scalar {
    s - s_prime
}

fn main() {
    use rand_core::OsRng;
    // Schnorr 
    // Keys
    let p = Scalar::random(&mut OsRng);           // secret key
    let P = ProjectivePoint::generator() * &p;    // public key

    let t = Scalar::random(&mut OsRng);           // tweak
    let T = ProjectivePoint::generator() * &t;    // tweak point

    let r_prime = Scalar::random(&mut OsRng);     // nonce
    let message = b"Adaptor signature message";

    // Pre-sign
    let (s_prime, R_prime) = pre_sign(&p, message, &T, &r_prime);

    // Verify pre-signature
    assert!(verify_pre_sign(&P, message, &T, &s_prime, &R_prime));
    println!("Pre-signature verified ✅");

    // Adapt signature
    let s = adapt_signature(&s_prime, &t);
    println!("Full signature scalar: {:?}", s);

    // Extract witness
    let t_extracted = extract_witness(&s, &s_prime);
    assert_eq!(t_extracted, t);
    println!("Extracted tweak matches ✅");
}