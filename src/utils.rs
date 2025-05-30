use k256::{
    elliptic_curve::{ point::AffineCoordinates, PrimeField}, ProjectivePoint, Scalar
};


/** 
 * Extracts the x-coordinate from a projective point and converts it to a scalar.
 * 
 * # Arguments
 * * `W` - ProjectivePoint to extract x-coordinate from.
 * 
 * # Returns
 * * `Scalar` - The x-coordinate as a scalar, or `Scalar::ZERO` if invalid.
 */
pub fn get_x(W: &ProjectivePoint) -> Scalar{
    let w_x = match Scalar::from_repr(W.to_affine().x()).into_option() {
            Some(s) => s,
            None => {
                eprintln!("Invalid x-coordinate of R': cannot convert to Scalar.");
                return Scalar::ZERO;
            }
        };
    return w_x;
}

/**
 * Safely computes the modular inverse of a scalar.
 *
 * # Arguments
 * * `s` - The scalar to invert.
 *
 * # Returns
 * * `Scalar` - The inverse of the scalar, or `Scalar::ZERO` if not invertible.
 */
pub fn invert_scalar(s: &Scalar) -> Scalar{
    let s_inv = match s.invert().into_option() {
            Some(inv) => inv,
            None => {
                eprintln!("s' is not invertible (possibly zero).");
                return Scalar::ZERO;
            }
        };
    return s_inv;
}
