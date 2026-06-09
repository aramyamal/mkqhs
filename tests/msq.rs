use std::collections::HashMap;

use ark_ff::{Field, Zero};
use ark_std::{UniformRand, test_rng};

use mkqhs::{
    api::Scalar,
    mkqhs_br_msq::{keygen, sign},
    params::Params,
    testing::{MsqScheme, Qhs1Msq, Qhs2Msq},
    types::{Label, QuadProgramMsq, Tag},
};

const K: usize = 8;

// TODO: Add tests for forgeries that pass the sum checks but not the pairing checks

fn rand_tag<R: ark_std::rand::RngCore>(rng: &mut R) -> Tag<K> {
    let mut b = [0u8; K];
    rng.try_fill_bytes(&mut b).unwrap();
    Tag(b)
}

fn test_linear<T: MsqScheme<K, 0>>() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk, pk) = keygen(&pp, &mut rng).unwrap();
    let msg = Scalar::rand(&mut rng);
    let lab = Label::new(sk.id(), rand_tag(&mut rng));
    let share = sign(&pp, &sk, lab, msg).unwrap();
    let program = QuadProgramMsq::<K, 0>::new(
        vec![Scalar::from(1u64)],
        vec![Scalar::zero()],
        vec![[]],
        vec![[]],
        vec![lab],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![share]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk.id(), pk);
    assert!(T::verify(&pp, &program, &pks, msg, &sig).unwrap());
}

fn test_square<T: MsqScheme<K, 0>>() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk, pk) = keygen(&pp, &mut rng).unwrap();
    let msg = Scalar::rand(&mut rng);
    let lab = Label::new(sk.id(), rand_tag(&mut rng));
    let share = sign(&pp, &sk, lab, msg).unwrap();
    let program = QuadProgramMsq::<K, 0>::new(
        vec![Scalar::zero()],
        vec![Scalar::from(1u64)],
        vec![[]],
        vec![[]],
        vec![lab],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![share]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk.id(), pk);
    assert!(T::verify(&pp, &program, &pks, msg.square(), &sig).unwrap());
}

fn test_sum_of_squares<T: MsqScheme<K, 0>>() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk, pk) = keygen(&pp, &mut rng).unwrap();
    let m1 = Scalar::rand(&mut rng);
    let m2 = Scalar::rand(&mut rng);
    let lab1 = Label::new(sk.id(), rand_tag(&mut rng));
    let lab2 = Label::new(sk.id(), rand_tag(&mut rng));
    let sh1 = sign(&pp, &sk, lab1, m1).unwrap();
    let sh2 = sign(&pp, &sk, lab2, m2).unwrap();
    let program = QuadProgramMsq::<K, 0>::new(
        vec![Scalar::zero(), Scalar::zero()],
        vec![Scalar::from(1u64), Scalar::from(1u64)],
        vec![[], []],
        vec![[], []],
        vec![lab1, lab2],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![sh1, sh2]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk.id(), pk);
    assert!(T::verify(&pp, &program, &pks, m1.square() + m2.square(), &sig).unwrap());
}

fn test_quadratic_two_users<T: MsqScheme<K, 1>>() {
    // $f(m_A, m_B) = m_A \cdot m_B$ via rank-1: $\mathbf u = (1,0)^\top$, $\mathbf v = (0,1)^\top$
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk_a, pk_a) = keygen(&pp, &mut rng).unwrap();
    let (sk_b, pk_b) = keygen(&pp, &mut rng).unwrap();
    let m_a = Scalar::rand(&mut rng);
    let m_b = Scalar::rand(&mut rng);
    let lab_a = Label::new(sk_a.id(), rand_tag(&mut rng));
    let lab_b = Label::new(sk_b.id(), rand_tag(&mut rng));
    let sh_a = sign(&pp, &sk_a, lab_a, m_a).unwrap();
    let sh_b = sign(&pp, &sk_b, lab_b, m_b).unwrap();
    let program = QuadProgramMsq::<K, 1>::new(
        vec![Scalar::zero(), Scalar::zero()],
        vec![Scalar::zero(), Scalar::zero()],
        vec![[Scalar::from(1u64)], [Scalar::zero()]],
        vec![[Scalar::zero()], [Scalar::from(1u64)]],
        vec![lab_a, lab_b],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![sh_a, sh_b]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk_a.id(), pk_a);
    pks.insert(pk_b.id(), pk_b);
    assert!(T::verify(&pp, &program, &pks, m_a * m_b, &sig).unwrap());
}

fn test_wrong_msg_rejected<T: MsqScheme<K, 0>>() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk, pk) = keygen(&pp, &mut rng).unwrap();
    let msg = Scalar::rand(&mut rng);
    let lab = Label::new(sk.id(), rand_tag(&mut rng));
    let share = sign(&pp, &sk, lab, msg).unwrap();
    let program = QuadProgramMsq::<K, 0>::new(
        vec![Scalar::from(1u64)],
        vec![Scalar::zero()],
        vec![[]],
        vec![[]],
        vec![lab],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![share]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk.id(), pk);
    assert!(!T::verify(&pp, &program, &pks, msg + Scalar::from(1u64), &sig).unwrap());
}

// $f(\mathbf{m}) = \langle \mathbf{m}_A, \mathbf{m}_B \rangle = m_0 m_2 + m_1 m_3$
// via rank-2: $\mathbf{u} = (e_0, e_1)$, $\mathbf{v} = (e_2, e_3)$
fn test_rank2_dot_product<T: MsqScheme<K, 2>>() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk0, pk0) = keygen(&pp, &mut rng).unwrap();
    let (sk1, pk1) = keygen(&pp, &mut rng).unwrap();
    let (sk2, pk2) = keygen(&pp, &mut rng).unwrap();
    let (sk3, pk3) = keygen(&pp, &mut rng).unwrap();
    let m0 = Scalar::rand(&mut rng);
    let m1 = Scalar::rand(&mut rng);
    let m2 = Scalar::rand(&mut rng);
    let m3 = Scalar::rand(&mut rng);
    let lab0 = Label::new(sk0.id(), rand_tag(&mut rng));
    let lab1 = Label::new(sk1.id(), rand_tag(&mut rng));
    let lab2 = Label::new(sk2.id(), rand_tag(&mut rng));
    let lab3 = Label::new(sk3.id(), rand_tag(&mut rng));
    let sh0 = sign(&pp, &sk0, lab0, m0).unwrap();
    let sh1 = sign(&pp, &sk1, lab1, m1).unwrap();
    let sh2 = sign(&pp, &sk2, lab2, m2).unwrap();
    let sh3 = sign(&pp, &sk3, lab3, m3).unwrap();
    // r=0: left = m_0, right = m_2; r=1: left = m_1, right = m_3
    let one = Scalar::from(1u64);
    let zero = Scalar::zero();
    let program = QuadProgramMsq::<K, 2>::new(
        vec![zero; 4],
        vec![zero; 4],
        vec![[one, zero], [zero, one], [zero; 2], [zero; 2]],
        vec![[zero; 2], [zero; 2], [one, zero], [zero, one]],
        vec![lab0, lab1, lab2, lab3],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![sh0, sh1, sh2, sh3]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk0.id(), pk0);
    pks.insert(pk1.id(), pk1);
    pks.insert(pk2.id(), pk2);
    pks.insert(pk3.id(), pk3);
    assert!(T::verify(&pp, &program, &pks, m0 * m2 + m1 * m3, &sig).unwrap());
}

// $f(\mathbf{m}) = m_0 + m_1^2 + m_2 \cdot m_3$ — linear, square, and cross-product combined
fn test_mixed_r1<T: MsqScheme<K, 1>>() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk0, pk0) = keygen(&pp, &mut rng).unwrap();
    let (sk1, pk1) = keygen(&pp, &mut rng).unwrap();
    let (sk2, pk2) = keygen(&pp, &mut rng).unwrap();
    let (sk3, pk3) = keygen(&pp, &mut rng).unwrap();
    let m0 = Scalar::rand(&mut rng);
    let m1 = Scalar::rand(&mut rng);
    let m2 = Scalar::rand(&mut rng);
    let m3 = Scalar::rand(&mut rng);
    let lab0 = Label::new(sk0.id(), rand_tag(&mut rng));
    let lab1 = Label::new(sk1.id(), rand_tag(&mut rng));
    let lab2 = Label::new(sk2.id(), rand_tag(&mut rng));
    let lab3 = Label::new(sk3.id(), rand_tag(&mut rng));
    let sh0 = sign(&pp, &sk0, lab0, m0).unwrap();
    let sh1 = sign(&pp, &sk1, lab1, m1).unwrap();
    let sh2 = sign(&pp, &sk2, lab2, m2).unwrap();
    let sh3 = sign(&pp, &sk3, lab3, m3).unwrap();
    let one = Scalar::from(1u64);
    let zero = Scalar::zero();
    // a=[1,0,0,0], b=[0,1,0,0], u[2][0]=1, v[3][0]=1
    let program = QuadProgramMsq::<K, 1>::new(
        vec![one, zero, zero, zero],
        vec![zero, one, zero, zero],
        vec![[zero], [zero], [one], [zero]],
        vec![[zero], [zero], [zero], [one]],
        vec![lab0, lab1, lab2, lab3],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![sh0, sh1, sh2, sh3]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk0.id(), pk0);
    pks.insert(pk1.id(), pk1);
    pks.insert(pk2.id(), pk2);
    pks.insert(pk3.id(), pk3);
    assert!(T::verify(&pp, &program, &pks, m0 + m1.square() + m2 * m3, &sig).unwrap());
}

// Variance: $f = \sum_i m_i^2 - \tfrac{1}{n}\bigl(\sum_i m_i\bigr)^2$
// via $b_i = 1$, $u_i = 1$, $v_i = -\tfrac{1}{n}$ for all $i$.
fn test_variance<T: MsqScheme<K, 1>>() {
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let (sk0, pk0) = keygen(&pp, &mut rng).unwrap();
    let (sk1, pk1) = keygen(&pp, &mut rng).unwrap();
    let (sk2, pk2) = keygen(&pp, &mut rng).unwrap();
    let m0 = Scalar::rand(&mut rng);
    let m1 = Scalar::rand(&mut rng);
    let m2 = Scalar::rand(&mut rng);
    let lab0 = Label::new(sk0.id(), rand_tag(&mut rng));
    let lab1 = Label::new(sk1.id(), rand_tag(&mut rng));
    let lab2 = Label::new(sk2.id(), rand_tag(&mut rng));
    let sh0 = sign(&pp, &sk0, lab0, m0).unwrap();
    let sh1 = sign(&pp, &sk1, lab1, m1).unwrap();
    let sh2 = sign(&pp, &sk2, lab2, m2).unwrap();
    let one = Scalar::from(1u64);
    let zero = Scalar::zero();
    let n_inv = Scalar::from(3u64).inverse().unwrap();
    let neg_n_inv = -n_inv;
    let program = QuadProgramMsq::<K, 1>::new(
        vec![zero, zero, zero],
        vec![one, one, one],
        vec![[one], [one], [one]],
        vec![[neg_n_inv], [neg_n_inv], [neg_n_inv]],
        vec![lab0, lab1, lab2],
    )
    .unwrap();
    let sig = T::eval(&pp, &program, vec![sh0, sh1, sh2]).unwrap();
    let mut pks = HashMap::new();
    pks.insert(pk0.id(), pk0);
    pks.insert(pk1.id(), pk1);
    pks.insert(pk2.id(), pk2);
    let expected = m0.square() + m1.square() + m2.square() - n_inv * (m0 + m1 + m2).square();
    assert!(T::verify(&pp, &program, &pks, expected, &sig).unwrap());
}

// $f(\mathbf{m}) = \sum_{r=0}^{7} \bigl(\sum_i u_{i,r} m_i\bigr)\bigl(\sum_j v_{j,r} m_j\bigr)$
// with dense random $u, v \in \mathbb{F}^{4 \times 8}$ — genuinely rank-8 bilinear form
fn test_rank8_dense<T: MsqScheme<K, 8>>() {
    const N: usize = 4;
    let pp = Params::<K>::new();
    let mut rng = test_rng();
    let zero = Scalar::zero();

    let mut sks = Vec::new();
    let mut pks_map = HashMap::new();
    let mut msgs = [zero; N];
    let mut labs = Vec::new();
    for i in 0..N {
        let (sk, pk) = keygen(&pp, &mut rng).unwrap();
        let lab = Label::new(sk.id(), rand_tag(&mut rng));
        msgs[i] = Scalar::rand(&mut rng);
        pks_map.insert(pk.id(), pk);
        labs.push(lab);
        sks.push(sk);
    }

    let shares: Vec<_> = sks
        .iter()
        .zip(labs.iter())
        .zip(msgs.iter())
        .map(|((sk, &lab), &msg)| sign(&pp, sk, lab, msg).unwrap())
        .collect();

    let u: [[Scalar; 8]; N] =
        std::array::from_fn(|_| std::array::from_fn(|_| Scalar::rand(&mut rng)));
    let v: [[Scalar; 8]; N] =
        std::array::from_fn(|_| std::array::from_fn(|_| Scalar::rand(&mut rng)));

    let program =
        QuadProgramMsq::<K, 8>::new(vec![zero; N], vec![zero; N], u.to_vec(), v.to_vec(), labs)
            .unwrap();

    let sig = T::eval(&pp, &program, shares).unwrap();
    let expected: Scalar = (0..8)
        .map(|r| {
            let lu: Scalar = (0..N).map(|i| u[i][r] * msgs[i]).sum();
            let lv: Scalar = (0..N).map(|i| v[i][r] * msgs[i]).sum();
            lu * lv
        })
        .sum();
    assert!(T::verify(&pp, &program, &pks_map, expected, &sig).unwrap());
}

macro_rules! scheme_tests {
    ($mod:ident, $scheme:ty) => {
        mod $mod {
            use super::*;
            #[test]
            fn linear() {
                super::test_linear::<$scheme>();
            }
            #[test]
            fn square() {
                super::test_square::<$scheme>();
            }
            #[test]
            fn sum_of_squares() {
                super::test_sum_of_squares::<$scheme>();
            }
            #[test]
            fn quadratic_two_users() {
                super::test_quadratic_two_users::<$scheme>();
            }
            #[test]
            fn wrong_msg_rejected() {
                super::test_wrong_msg_rejected::<$scheme>();
            }
            #[test]
            fn rank2_dot_product() {
                super::test_rank2_dot_product::<$scheme>();
            }
            #[test]
            fn mixed_r1() {
                super::test_mixed_r1::<$scheme>();
            }
            #[test]
            fn variance() {
                super::test_variance::<$scheme>();
            }
            #[test]
            fn rank8_dense() {
                super::test_rank8_dense::<$scheme>();
            }
        }
    };
}

scheme_tests!(mkqhs_br_msq, Qhs1Msq);
scheme_tests!(mkqhs_cbr_msq, Qhs2Msq);
