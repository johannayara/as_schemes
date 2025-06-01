use k256::{elliptic_curve::{ff::Field},ProjectivePoint, Scalar};
use rand_core::OsRng;
use as_for_fde::{AS_scheme, Delta, Delta_prime, Schnorr, Sign_scheme};

pub struct Alice {
    sk: Scalar,
    pub pk: ProjectivePoint,
    t: Scalar,
    pub T: ProjectivePoint,
}

impl Alice {
    pub fn new() -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = ProjectivePoint::GENERATOR * sk;
        let t = Scalar::random(&mut OsRng);
        let T = ProjectivePoint::GENERATOR * t;
        Self { sk, pk, t, T }
    }

    pub fn generate_presig(&self, tx: &str) -> (Delta_prime, ProjectivePoint) {
        let schnorr = Schnorr;
        let r_prime = Scalar::random(&mut OsRng);
        let delta_prime = schnorr.pre_sign(&self.sk, tx, &self.T, &r_prime);
        (delta_prime, self.T)
    }

    pub fn verify_presig(&self, delta_prime: &Delta_prime, pk: &ProjectivePoint, tx: &str) -> bool {
        let schnorr = Schnorr;
        schnorr.verify_pre_sign(pk, tx,&self.T, delta_prime)
    }

    pub fn generate_sig_and_adapt(&self, tx: &str, delta_prime_b: &Delta_prime) -> (Delta, Delta) {
        let schnorr = Schnorr;

        // Alice Schnorr signature
        let r_a = Scalar::random(&mut OsRng);
        let delta_a = schnorr.sign(&self.sk, tx, &r_a);
        let delta_b = schnorr.adapt_signature(delta_prime_b, &self.t);

        (delta_a, delta_b)
    }

}
