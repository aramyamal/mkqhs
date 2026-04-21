use std::collections::HashMap;

use crate::{
    algebra::{G1, GT, Scalar, g1_gen, g2_gen, hash_to_g1_with, pairing},
    errors::ProtocolError,
    params::Params,
    types::{Id, Label, LabeledProgram, PublicKey, SecretKey, SignAggr, SignShare},
};

use ark_bls12_381::Bls12_381;
use ark_ec::{CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_std::{UniformRand, Zero, rand::RngCore};

pub fn keygen<const K: usize, R: RngCore>(
    _pp: &Params<K>,
    rng: &mut R,
) -> Result<(SecretKey<K>, PublicKey<K>), ProtocolError> {
    let mut id_bytes = [0u8; K];
    rng.try_fill_bytes(&mut id_bytes)
        .map_err(|e| ProtocolError::Rng(e.to_string()))?;
    let id = Id(id_bytes);

    let mut x = Scalar::rand(rng);
    while x.is_zero() {
        x = Scalar::rand(rng);
    }
    let sk = SecretKey::new(id, x);

    let g2x = g2_gen() * x;

    let pk = PublicKey::new(id, g2x);

    Ok((sk, pk))
}

pub fn sign<const K: usize>(
    pp: &Params<K>,
    sk: &SecretKey<K>,
    label: Label<K>,
    msg: Scalar,
) -> Result<SignShare<K>, ProtocolError> {
    let label_bytes = label.to_bytes();
    let h = hash_to_g1_with(pp.h2g1_label(), &label_bytes)?;

    let gamma = (h + g1_gen() * msg) * (*sk.value());

    Ok(SignShare::new(sk.id(), gamma, msg))
}

fn organize<const K: usize>(labels: &[Label<K>]) -> (Vec<Id<K>>, Vec<Vec<usize>>) {
    let mut ord_ids: Vec<Id<K>> = Vec::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut id_to_idx: HashMap<Id<K>, usize> = HashMap::with_capacity(labels.len());

    // O(n) pass to build all
    for (i, lab) in labels.iter().enumerate() {
        let id = lab.id();
        let j = *id_to_idx.entry(id).or_insert_with(|| {
            let j = ord_ids.len();
            ord_ids.push(id);
            groups.push(Vec::new());
            j
        });
        groups[j].push(i);
    }

    (ord_ids, groups)
}

pub fn eval<const K: usize>(
    _pp: &Params<K>,
    program: &LabeledProgram<K>,
    sign_shares: Vec<SignShare<K>>,
) -> Result<SignAggr<K>, ProtocolError> {
    let coeffs = program.coeffs();
    let labels = program.labels();

    if coeffs.len() != labels.len() || coeffs.len() != sign_shares.len() {
        return Err(ProtocolError::InvalidInput(
            "coeffs/labels/sign_shares length mismatch".to_string(),
        ));
    }

    let gamma_bases: Vec<_> = sign_shares.iter().map(|s| s.gamma().into_affine()).collect();
    let gamma = G1::msm_unchecked(&gamma_bases, coeffs);

    let (ord_ids, groups) = organize(labels);

    let mus: Vec<Scalar> = groups
        .iter()
        .map(|idxs| idxs.iter().map(|&i| coeffs[i] * sign_shares[i].mu()).sum())
        .collect();

    SignAggr::new(gamma, ord_ids, mus)
}

pub fn verify<const K: usize>(
    pp: &Params<K>,
    program: &LabeledProgram<K>,
    pks: &HashMap<Id<K>, PublicKey<K>>,
    msg: Scalar,
    sign_aggr: &SignAggr<K>,
) -> Result<bool, ProtocolError> {
    // ver1: check $\sum_j \mu_j = m$
    let mu_sum: Scalar = sign_aggr.mus().iter().sum();
    if mu_sum != msg {
        return Ok(false);
    }

    // create id to index table
    let ord_ids = sign_aggr.ord_ids();
    let mut id_to_j: HashMap<Id<K>, usize> = HashMap::with_capacity(ord_ids.len());
    for (j, &id) in ord_ids.iter().enumerate() {
        id_to_j.insert(id, j);
    }

    // initialize A_j = g1_gen * mu_j
    let mut a: Vec<G1> = sign_aggr
        .mus()
        .iter()
        .map(|mu_j| g1_gen() * *mu_j)
        .collect();

    // per-group MSM: collect bases and scalars for each signer group
    let n_groups = ord_ids.len();
    let mut msm_bases: Vec<Vec<_>> = vec![Vec::new(); n_groups];
    let mut msm_scalars: Vec<Vec<Scalar>> = vec![Vec::new(); n_groups];
    for (i, lab) in program.labels().iter().enumerate() {
        let j = *id_to_j.get(&lab.id()).ok_or_else(|| {
            ProtocolError::InvalidInput("program label id not in signature ord_ids".to_string())
        })?;
        let f_i = program.coeffs()[i];
        if f_i.is_zero() {
            continue;
        }
        let h_i = hash_to_g1_with(pp.h2g1_label(), &lab.to_bytes())?;
        msm_bases[j].push(h_i.into_affine());
        msm_scalars[j].push(f_i);
    }
    for j in 0..n_groups {
        if !msm_bases[j].is_empty() {
            a[j] += G1::msm_unchecked(&msm_bases[j], &msm_scalars[j]);
        }
    }

    // collect G1/G2 affine points then call multi_pairing
    let mut g2_pts = Vec::with_capacity(n_groups);
    for id_j in ord_ids.iter() {
        let pk = pks.get(id_j).ok_or_else(|| {
            ProtocolError::InvalidInput("missing public key for ord_id".to_string())
        })?;
        g2_pts.push(pk.value().into_affine());
    }
    let g1_pts: Vec<_> = a.iter().map(|p| p.into_affine()).collect();
    let c: GT = Bls12_381::multi_pairing(g1_pts, g2_pts).0;

    let lhs: GT = pairing(sign_aggr.gamma(), &g2_gen());

    // ver2: $e(\gamma, g_2) = \prod_j e(A_j, \mathrm{pk}_j)$
    Ok(lhs == c)
}

#[cfg(test)]
mod tests {
    use crate::types::Tag;

    use super::*;

    use ark_std::{UniformRand, test_rng};

    fn rand_tag<const K: usize, R: RngCore>(rng: &mut R) -> Tag<K> {
        let mut b = [0u8; K];
        rng.try_fill_bytes(&mut b).unwrap();
        Tag(b)
    }

    mod keygen_tests {

        use super::*;

        #[test]
        fn keygen_smoke() {
            let pp = Params::<32>::new();
            let mut rng = ark_std::test_rng();
            let (_sk, pk) = keygen(&pp, &mut rng).expect("keygen failed");
            assert_eq!(pk.id().0.len(), 32);
        }
    }

    mod organize_tests {

        use super::*;

        #[test]
        fn smoke() {
            const K: usize = 8;
            let mut rng = test_rng();

            // build labels with repeated ids in a known pattern:
            // ids: A,B,A,C,B,A  => ord_ids should be [A,B,C]
            let id_a = Id::<K>([1u8; K]);
            let id_b = Id::<K>([2u8; K]);
            let id_c = Id::<K>([3u8; K]);

            let labels = vec![
                Label::new(id_a, rand_tag::<K, _>(&mut rng)),
                Label::new(id_b, rand_tag::<K, _>(&mut rng)),
                Label::new(id_a, rand_tag::<K, _>(&mut rng)),
                Label::new(id_c, rand_tag::<K, _>(&mut rng)),
                Label::new(id_b, rand_tag::<K, _>(&mut rng)),
                Label::new(id_a, rand_tag::<K, _>(&mut rng)),
            ];

            let (ord_ids, groups) = organize(&labels);

            assert_eq!(ord_ids, vec![id_a, id_b, id_c]);
            assert_eq!(groups.len(), ord_ids.len());

            // 1. groups cover all indices exactly once
            let mut seen = vec![false; labels.len()];
            for idxs in &groups {
                for &i in idxs {
                    assert!(i < labels.len());
                    assert!(!seen[i], "index {i} appears in multiple groups");
                    seen[i] = true;
                }
            }
            assert!(
                seen.iter().all(|b| *b == true),
                "some indices are not covered"
            );

            // 2. each group corresponds to its id
            for (j, id) in ord_ids.iter().enumerate() {
                for &i in &groups[j] {
                    assert_eq!(labels[i].id(), *id);
                }
            }
        }
    }

    mod eval_tests {

        use super::*;

        #[test]
        fn smoke() {
            const K: usize = 8;

            let pp = Params::<K>::new();
            let mut rng = test_rng();

            // one user, one message, coeff=1 => eval should reproduce the same mu
            let (sk, _pk) = keygen(&pp, &mut rng).expect("keygen failed");

            let tag = rand_tag::<K, _>(&mut rng);
            let label = Label::new(sk.id(), tag);
            let msg = Scalar::rand(&mut rng);

            let share = sign(&pp, &sk, label, msg).expect("sign failed");

            // labeled program with n=1, f1=1
            let program = LabeledProgram::new(vec![Scalar::from(1)], vec![label])
                .expect("labeled program build failed");

            let aggr = eval(&pp, &program, vec![share.clone()]).expect("eval failed");

            // gamma should match share.gamma (since coeff=1)
            assert_eq!(aggr.gamma(), share.gamma());
            // ord_ids should contain just that signer
            assert_eq!(aggr.ord_ids(), &[sk.id()]);
            // mu list should contain just msg
            assert_eq!(aggr.mus(), &[msg]);
        }

        #[test]
        fn single_user_weighted_sum() {
            // one user, 3 messages, coeffs = [2, 3, 5]
            // expected: gamma = γ1*2 + γ2*3 + γ3*5, mu = 2*m1 + 3*m2 + 5*m3
            const K: usize = 8;
            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk, _pk) = keygen(&pp, &mut rng).unwrap();

            let msgs: Vec<Scalar> = (0..3).map(|_| Scalar::rand(&mut rng)).collect();
            let tags: Vec<Tag<K>> = (0..3).map(|_| rand_tag::<K, _>(&mut rng)).collect();
            let labels: Vec<Label<K>> = tags.iter().map(|t| Label::new(sk.id(), *t)).collect();

            let shares: Vec<SignShare<K>> = labels
                .iter()
                .zip(msgs.iter())
                .map(|(l, m)| sign(&pp, &sk, *l, *m).unwrap())
                .collect();

            let coeffs = vec![Scalar::from(2), Scalar::from(3), Scalar::from(5)];

            let program = LabeledProgram::new(coeffs.clone(), labels).unwrap();
            let aggr = eval(&pp, &program, shares.clone()).unwrap();

            // Only one signer
            assert_eq!(aggr.ord_ids().len(), 1);
            assert_eq!(aggr.ord_ids()[0], sk.id());

            // mu should equal weighted sum of messages
            let expected_mu: Scalar = coeffs.iter().zip(msgs.iter()).map(|(f, m)| *f * *m).sum();
            assert_eq!(aggr.mus()[0], expected_mu);

            // gamma should equal weighted sum of gammas
            let expected_gamma: G1 = coeffs
                .iter()
                .zip(shares.iter())
                .fold(G1::zero(), |acc, (f, sh)| acc + *sh.gamma() * *f);
            assert_eq!(*aggr.gamma(), expected_gamma);
        }

        #[test]
        fn two_users_one_msg_each() {
            // two users, one message each, coeffs = [1, 1]
            const K: usize = 8;
            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk_a, _pk_a) = keygen(&pp, &mut rng).unwrap();
            let (sk_b, _pk_b) = keygen(&pp, &mut rng).unwrap();

            let msg_a = Scalar::rand(&mut rng);
            let msg_b = Scalar::rand(&mut rng);

            let lab_a = Label::new(sk_a.id(), rand_tag::<K, _>(&mut rng));
            let lab_b = Label::new(sk_b.id(), rand_tag::<K, _>(&mut rng));

            let sh_a = sign(&pp, &sk_a, lab_a, msg_a).unwrap();
            let sh_b = sign(&pp, &sk_b, lab_b, msg_b).unwrap();

            let coeffs = vec![Scalar::from(1), Scalar::from(1)];
            let program = LabeledProgram::new(coeffs, vec![lab_a, lab_b]).unwrap();
            let aggr = eval(&pp, &program, vec![sh_a.clone(), sh_b.clone()]).unwrap();

            // two different signers
            assert_eq!(aggr.ord_ids().len(), 2);
            assert_eq!(aggr.ord_ids()[0], sk_a.id());
            assert_eq!(aggr.ord_ids()[1], sk_b.id());

            // gamma should be the sum of gammas (coeff=1)
            assert_eq!(*aggr.gamma(), *sh_a.gamma() + *sh_b.gamma());

            // each mu should just be the original message (coeff=1, one msg per user)
            assert_eq!(aggr.mus()[0], msg_a);
            assert_eq!(aggr.mus()[1], msg_b);
        }

        #[test]
        fn two_users_multiple_msgs() {
            // user A signs m1, m2
            // user B signs m3
            // labels order: [A, B, A] => ord_ids = [A, B]
            // coeffs = [2, 3, 4]
            // mu_A = 2*m1 + 4*m3_A, mu_B = 3*m2_B
            const K: usize = 8;
            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk_a, _) = keygen(&pp, &mut rng).unwrap();
            let (sk_b, _) = keygen(&pp, &mut rng).unwrap();

            let m1 = Scalar::rand(&mut rng);
            let m2 = Scalar::rand(&mut rng);
            let m3 = Scalar::rand(&mut rng);

            let lab1 = Label::new(sk_a.id(), rand_tag::<K, _>(&mut rng));
            let lab2 = Label::new(sk_b.id(), rand_tag::<K, _>(&mut rng));
            let lab3 = Label::new(sk_a.id(), rand_tag::<K, _>(&mut rng));

            let sh1 = sign(&pp, &sk_a, lab1, m1).unwrap();
            let sh2 = sign(&pp, &sk_b, lab2, m2).unwrap();
            let sh3 = sign(&pp, &sk_a, lab3, m3).unwrap();

            let coeffs = vec![Scalar::from(2), Scalar::from(3), Scalar::from(4)];
            let program = LabeledProgram::new(coeffs.clone(), vec![lab1, lab2, lab3]).unwrap();
            let aggr = eval(&pp, &program, vec![sh1.clone(), sh2.clone(), sh3.clone()]).unwrap();

            // ord_ids: A first, then B
            assert_eq!(aggr.ord_ids().len(), 2);
            assert_eq!(aggr.ord_ids()[0], sk_a.id());
            assert_eq!(aggr.ord_ids()[1], sk_b.id());

            // mu_A = 2*m1 + 4*m3
            let expected_mu_a = Scalar::from(2) * m1 + Scalar::from(4) * m3;
            assert_eq!(aggr.mus()[0], expected_mu_a);

            // mu_B = 3*m2
            let expected_mu_b = Scalar::from(3) * m2;
            assert_eq!(aggr.mus()[1], expected_mu_b);

            // gamma = 2*γ1 + 3*γ2 + 4*γ3
            let expected_gamma = *sh1.gamma() * Scalar::from(2)
                + *sh2.gamma() * Scalar::from(3)
                + *sh3.gamma() * Scalar::from(4);
            assert_eq!(*aggr.gamma(), expected_gamma);
        }

        #[test]
        fn zero_coefficients() {
            // coeff=0 should contribute nothing
            const K: usize = 8;
            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk, _) = keygen(&pp, &mut rng).unwrap();

            let m1 = Scalar::rand(&mut rng);
            let m2 = Scalar::rand(&mut rng);

            let lab1 = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));
            let lab2 = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));

            let sh1 = sign(&pp, &sk, lab1, m1).unwrap();
            let sh2 = sign(&pp, &sk, lab2, m2).unwrap();

            let coeffs = vec![Scalar::from(7), Scalar::zero()];
            let program = LabeledProgram::new(coeffs, vec![lab1, lab2]).unwrap();
            let aggr = eval(&pp, &program, vec![sh1.clone(), sh2]).unwrap();

            // mu should only reflect m1
            assert_eq!(aggr.mus()[0], Scalar::from(7) * m1);

            // gamma should only reflect sh1
            assert_eq!(*aggr.gamma(), *sh1.gamma() * Scalar::from(7));
        }

        #[test]
        fn length_mismatch_error() {
            const K: usize = 8;
            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk, _) = keygen(&pp, &mut rng).unwrap();

            let lab = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));
            let sh = sign(&pp, &sk, lab, Scalar::from(42)).unwrap();

            // 2 coeffs but 1 label
            assert!(
                LabeledProgram::new(vec![Scalar::from(1), Scalar::from(2)], vec![lab],).is_err()
            );

            // 1 coeff, 1 label, but 2 shares
            let program = LabeledProgram::new(vec![Scalar::from(1)], vec![lab]).unwrap();
            assert!(eval(&pp, &program, vec![sh.clone(), sh]).is_err());
        }
    }
    mod verify_tests {

        use super::*;

        #[test]
        fn smoke() {
            const K: usize = 8;

            let pp = Params::<K>::new();
            let mut rng = test_rng();

            // one signer
            let (sk, pk) = keygen(&pp, &mut rng).expect("keygen failed");

            let msg = Scalar::rand(&mut rng);
            let label = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));

            let share = sign(&pp, &sk, label, msg).expect("sign failed");

            // trivial linear program: f = 1
            let program = LabeledProgram::new(vec![Scalar::from(1)], vec![label])
                .expect("program build failed");

            let aggr = eval(&pp, &program, vec![share]).expect("eval failed");

            let mut pks = HashMap::new();
            pks.insert(pk.id(), pk);

            let result = verify(&pp, &program, &pks, msg, &aggr).expect("verify errored");

            assert!(result);
        }

        #[test]
        fn fails_on_wrong_message() {
            const K: usize = 8;

            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk, pk) = keygen(&pp, &mut rng).unwrap();

            let msg = Scalar::rand(&mut rng);
            let wrong_msg = Scalar::rand(&mut rng);

            let label = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));
            let share = sign(&pp, &sk, label, msg).unwrap();

            let program = LabeledProgram::new(vec![Scalar::from(1)], vec![label]).unwrap();

            let aggr = eval(&pp, &program, vec![share]).unwrap();

            let mut pks = HashMap::new();
            pks.insert(pk.id(), pk);

            let ok = verify(&pp, &program, &pks, wrong_msg, &aggr).unwrap();
            assert!(!ok);
        }

        #[test]
        fn missing_public_key_errors() {
            const K: usize = 8;

            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk, _pk) = keygen(&pp, &mut rng).unwrap();

            let msg = Scalar::rand(&mut rng);
            let label = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));

            let share = sign(&pp, &sk, label, msg).unwrap();

            let program = LabeledProgram::new(vec![Scalar::from(1)], vec![label]).unwrap();

            let aggr = eval(&pp, &program, vec![share]).unwrap();

            let pks = HashMap::new(); // empty!

            assert!(verify(&pp, &program, &pks, msg, &aggr).is_err());
        }

        #[test]
        fn fails_if_gamma_tampered() {
            const K: usize = 8;

            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk, pk) = keygen(&pp, &mut rng).unwrap();

            let msg = Scalar::rand(&mut rng);
            let label = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));

            let share = sign(&pp, &sk, label, msg).unwrap();

            let program = LabeledProgram::new(vec![Scalar::from(1)], vec![label]).unwrap();

            let mut aggr = eval(&pp, &program, vec![share]).unwrap();

            // tamper gamma
            *aggr.gamma_mut() += g1_gen();

            let mut pks = HashMap::new();
            pks.insert(pk.id(), pk);

            let ok = verify(&pp, &program, &pks, msg, &aggr).unwrap();
            assert!(!ok);
        }

        #[test]
        fn fails_if_mu_tampered() {
            const K: usize = 8;

            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk, pk) = keygen(&pp, &mut rng).unwrap();

            let msg = Scalar::rand(&mut rng);
            let label = Label::new(sk.id(), rand_tag::<K, _>(&mut rng));

            let share = sign(&pp, &sk, label, msg).unwrap();

            let program = LabeledProgram::new(vec![Scalar::from(1)], vec![label]).unwrap();

            let mut aggr = eval(&pp, &program, vec![share]).unwrap();

            // tamper mu
            aggr.mus_mut()[0] += Scalar::from(1);

            let mut pks = HashMap::new();
            pks.insert(pk.id(), pk);

            let ok = verify(&pp, &program, &pks, msg, &aggr).unwrap();
            assert!(!ok);
        }

        #[test]
        fn two_users() {
            const K: usize = 8;

            let pp = Params::<K>::new();
            let mut rng = test_rng();

            let (sk_a, pk_a) = keygen(&pp, &mut rng).unwrap();
            let (sk_b, pk_b) = keygen(&pp, &mut rng).unwrap();

            let msg_a = Scalar::rand(&mut rng);
            let msg_b = Scalar::rand(&mut rng);

            let lab_a = Label::new(sk_a.id(), rand_tag::<K, _>(&mut rng));
            let lab_b = Label::new(sk_b.id(), rand_tag::<K, _>(&mut rng));

            let sh_a = sign(&pp, &sk_a, lab_a, msg_a).unwrap();
            let sh_b = sign(&pp, &sk_b, lab_b, msg_b).unwrap();

            let coeffs = vec![Scalar::from(1), Scalar::from(1)];
            let program = LabeledProgram::new(coeffs, vec![lab_a, lab_b]).unwrap();

            let aggr = eval(&pp, &program, vec![sh_a, sh_b]).unwrap();

            let mut pks = HashMap::new();
            pks.insert(pk_a.id(), pk_a);
            pks.insert(pk_b.id(), pk_b);

            let expected_msg = msg_a + msg_b;

            let ok = verify(&pp, &program, &pks, expected_msg, &aggr).unwrap();
            assert!(ok);
        }
    }
}
