use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let mut scalar = Scalar::from_bytes_mod_order(*secret);
    let point = (&scalar * &ED25519_BASEPOINT_TABLE).compress();
    scalar.zeroize();
    point.to_bytes()
}
