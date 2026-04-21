# mklhs

> **Work in progress.**

Research implementation of multi-key homomorphic signature (MKHS) schemes developed as part of an
ongoing thesis. Extends the baseline `mklhs` scheme of Aranha and Pagnin
([ePrint 2019/830](https://eprint.iacr.org/2019/830)) to bounded-rank quadratic evaluation.

**Research artifact. Not audited. Do not use in production.**

## Schemes

| Module           | Scheme                                                         | Status      |
| ---------------- | -------------------------------------------------------------- | ----------- |
| `mk_lhs`         | Multi-key linearly homomorphic signatures (Aranha–Pagnin 2019) | implemented |
| `mk_br_qhs1`     | Bounded-rank quadratic, baseline O(tR) signature size          | skeleton    |
| `mk_br_qhs2`     | Bounded-rank quadratic, compressed O(t+R) via Fiat–Shamir      | skeleton    |
| `mk_br_qhs1_msq` | `mk_br_qhs1` with message-squares extension                    | skeleton    |
| `mk_br_qhs2_msq` | `mk_br_qhs2` with message-squares extension                    | skeleton    |

## Based on

> Aranha, D. F., & Pagnin, E.  
> _The Simplest Multi-key Linearly Homomorphic Signature Scheme_  
> IACR Cryptology ePrint Archive, Paper 2019/830  
> https://eprint.iacr.org/2019/830

The quadratic schemes are contributions of an ongoing thesis.

## Dependencies

Built on [arkworks](https://arkworks.rs) with BLS12-381.
