use k256::{elliptic_curve::{ff::Field},ProjectivePoint, Scalar};
use rand_core::OsRng;
use as_for_fde::{AS_scheme, Delta, Delta_prime, Schnorr, Sign_scheme};

pub struct Bob {
    sk: Scalar,
    pub pk: ProjectivePoint,
}

impl Bob {
    pub fn new() -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;
        Self { sk, pk }
    }

    pub fn generate_presig(&self, tx: &str, T: &ProjectivePoint) -> Delta_prime {
        let schnorr = Schnorr;
        let r_prime = Scalar::random(&mut OsRng);
        let delta_prime = schnorr.pre_sign(&self.sk, tx, T, &r_prime);
        delta_prime
    }

    pub fn verify_presig(&self, delta_prime: &Delta_prime, pk: &ProjectivePoint, tx: &str, T: &ProjectivePoint) -> bool {
        let schnorr = Schnorr;
        schnorr.verify_pre_sign(pk, tx, T, delta_prime)
    }

    pub fn verify_sign(&self, alice_pk: &ProjectivePoint, tx: &str, delta_a: &Delta, delta_b: &Delta) -> bool{
        let schnorr = Schnorr;
        let is_a_correct = schnorr.verify_sign(delta_a, alice_pk, tx);
        let is_b_correct = schnorr.verify_sign(delta_b, &self.pk, tx);
        is_a_correct && is_b_correct
    }

    pub fn extract_secret(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        let schnorr = Schnorr;
        let t = schnorr.extract_witness(delta, delta_prime);
        t
    }

    pub fn generate_sig_and_adapt(&self, tx: &str, delta_prime_a: &Delta_prime, t: &Scalar) -> (Delta, Delta) {
        let schnorr = Schnorr;

        // Alice Schnorr signature
        let r_b = Scalar::random(&mut OsRng);
        let delta_a = schnorr.adapt_signature(delta_prime_a, t);
        let delta_b = schnorr.sign(&self.sk, tx, &r_b);

        (delta_a, delta_b)
    }


}
