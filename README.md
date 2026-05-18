# mkqhs

> **Work in progress.**

Research implementation of multi-key homomorphic signature (MKHS) schemes developed as part of an
ongoing thesis. Extends the baseline `mklhs` scheme of Aranha and Pagnin
([ePrint 2019/830](https://eprint.iacr.org/2019/830)) to bounded-rank quadratic evaluation.

**Research artifact. Not audited. Do not use in production.**

## Schemes

| Module          | Scheme                                                                              | Status      |
| --------------- | ----------------------------------------------------------------------------------- | ----------- |
| `mklhs`         | $\textsf{mklhs}$: Multi-key linearly homomorphic signatures (Aranha–Pagnin 2019)    | implemented |
| `mkqhs_br`      | $\textsf{mkqhs-}\textsf{br}$: Bounded-rank quadratic, baseline O(tR) signature size | skeleton    |
| `mkqhs_cbr`     | $\textsf{mkqhs-}\tilde{\textsf{br}}$: Bounded-rank quadratic, compressed O(t+R)     | skeleton    |
| `mkqhs_br_msq`  | `mkqhs_br` with message-squares extension                                           | implemented |
| `mkqhs_cbr_msq` | `mkqhs_cbr` with message-squares extension                                          | implemented |

## Based on

> Aranha, D. F., & Pagnin, E.  
> _The Simplest Multi-key Linearly Homomorphic Signature Scheme_  
> IACR Cryptology ePrint Archive, Paper 2019/830  
> https://eprint.iacr.org/2019/830

The quadratic schemes are contributions of an ongoing thesis.

## Examples

The `examples/` crate contains runnable demonstrations of the schemes on real data.

```
cargo example <name>
```

| Example              | Scheme         | Description                                                                                |
| -------------------- | -------------- | ------------------------------------------------------------------------------------------ |
| `variance`           | `mkqhs_br_msq` | Verifiable variance of the diabetes target variable across 10 signers                      |
| `euclidean_distance` | `mkqhs_br_msq` | Verifiable squared Euclidean distance between two randomly sampled patients (age, bmi, bp) |

### Dataset

Both examples use the [Efron–Hastie diabetes dataset](https://www4.stat.ncsu.edu/~boos/var.select/diabetes.html). On first run the file is downloaded and cached at `examples/data/diabetes.data`.

## Dependencies

Built on [arkworks](https://arkworks.rs) with BLS12-381.
