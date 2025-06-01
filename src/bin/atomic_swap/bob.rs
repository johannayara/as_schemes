use k256::{elliptic_curve::{ff::Field},ProjectivePoint, Scalar};
use rand_core::OsRng;
use as_for_fde::{ AS_scheme, Delta, Delta_prime, Scheme, Sign_scheme};

pub struct Bob {
    sk: Scalar,
    pub pk: ProjectivePoint,
    scheme: Scheme,
}

impl Bob {
    pub fn new(scheme: Scheme) -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;
        Self { sk, pk, scheme }
    }

    pub fn generate_presig(&self, tx: &str, T: &ProjectivePoint) -> Delta_prime {
        let r_prime = Scalar::random(&mut OsRng);
        let delta_prime = self.scheme.pre_sign(&self.sk, tx, T, &r_prime);
        delta_prime
    }

    pub fn verify_presig(&self, delta_prime: &Delta_prime, pk: &ProjectivePoint, tx: &str, T: &ProjectivePoint) -> bool {
        self.scheme.verify_pre_sign(pk, tx, T, delta_prime)
    }

    pub fn verify_sign(&self, alice_pk: &ProjectivePoint, tx: &str, delta_a: &Delta, delta_b: &Delta) -> bool{
        let is_a_correct = self.scheme.verify_sign(delta_a, alice_pk, tx);
        let is_b_correct = self.scheme.verify_sign(delta_b, &self.pk, tx);
        is_a_correct && is_b_correct
    }

    pub fn extract_secret(&self, delta: &Delta, delta_prime: &Delta_prime) -> Scalar {
        let t = self.scheme.extract_witness(delta, delta_prime);
        t
    }

    pub fn generate_sig_and_adapt(&self, tx: &str, delta_prime_a: &Delta_prime, t: &Scalar) -> (Delta, Delta) {
        // Alice Schnorr signature
        let r_b = Scalar::random(&mut OsRng);
        let delta_a = self.scheme.adapt_signature(delta_prime_a, t);
        let delta_b = self.scheme.sign(&self.sk, tx, &r_b);

        (delta_a, delta_b)
    }


}
