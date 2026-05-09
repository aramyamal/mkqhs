use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective, g1::Config as G1Config};
use ark_ec::AffineRepr;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::field_hashers::DefaultFieldHasher;
use sha2::Sha256;

use crate::errors::AlgebraError;

pub type Scalar = Fr;
pub type G1 = G1Projective;
pub type G2 = G2Projective;
pub type GT = <Bls12_381 as Pairing>::TargetField;

pub fn scalar_zero() -> Scalar {
    use ark_ff::Zero;
    Scalar::zero()
}

pub fn scalar_inverse(s: &Scalar) -> Option<Scalar> {
    use ark_ff::Field;
    s.inverse()
}

pub fn scalar_to_u64(s: &Scalar) -> Option<u64> {
    use ark_ff::PrimeField;
    let b = s.into_bigint();
    Some(b.0[0])
}

pub fn g1_gen() -> G1 {
    G1::generator()
}

pub fn g2_gen() -> G2 {
    G2::generator()
}

pub fn pairing(a: &G1, b: &G2) -> GT {
    Bls12_381::pairing(a, b).0
}

pub type H2G1 =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<G1Config>>;

pub fn make_h2g1(dst: &'static [u8]) -> Result<H2G1, AlgebraError> {
    H2G1::new(dst).map_err(|e| AlgebraError::HashToCurve(Box::new(e)))
}

pub fn hash_to_g1_with(hasher: &H2G1, msg: &[u8]) -> Result<G1, AlgebraError> {
    let p = hasher
        .hash(msg)
        .map_err(|e| AlgebraError::HashToCurve(Box::new(e)))?;
    Ok(p.into_group())
}

// NOTE: This might be a better approach then using map_err
// impl From<HashToCurveError> for AlgebraError {
//     fn from(e: HashToCurveError) -> Self {
//         AlgebraError::HashToCurve(Box::new(e))
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::Zero;

    fn hash_to_g1(dst: &'static [u8], msg: &[u8]) -> Result<G1, AlgebraError> {
        let h = make_h2g1(dst)?;
        hash_to_g1_with(&h, msg)
    }

    #[test]
    fn hash_to_g1_smoke() {
        let dst = b"hejsan";
        let msg = b"hello";

        let p = hash_to_g1(dst, msg).expect("hash_to_g1 failed");
        assert!(!p.is_zero());

        let a = p.into_affine();
        assert!(a.is_on_curve());
        assert!(a.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn hash_to_g1_properties() {
        let dst = b"hejsan";
        let msg = b"hello";

        // deterministic for same inputs
        let p1 = hash_to_g1(dst, msg).unwrap();
        let p2 = hash_to_g1(dst, msg).unwrap();
        assert_eq!(p1, p2);

        // domain separation changes output
        let p3 = hash_to_g1(b"hejsansvejsan", msg).unwrap();
        assert_ne!(p1, p3);
    }
}
