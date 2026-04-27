use std::collections::HashMap;

use crate::{
    algebra::{G1, G2, Scalar},
    errors::ProtocolError,
};

/// group label indices by signer identity; preserves first-seen order of ids.
pub(crate) fn organize<const K: usize>(labels: &[Label<K>]) -> (Vec<Id<K>>, Vec<Vec<usize>>) {
    let mut ord_ids: Vec<Id<K>> = Vec::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut id_to_idx: HashMap<Id<K>, usize> = HashMap::with_capacity(labels.len());

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

// ── Shared across all schemes ──────────────────────────────────────────────

/// Identity element $\mathsf{id} \in \mathsf{ID} \subset \{0,1\}^{8K}$
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub struct Id<const K: usize>(pub [u8; K]);

/// Tag $\tau \in \mathcal{T} \subset \{0,1\}^{8K}$
#[derive(Clone, Debug, Copy)]
pub struct Tag<const K: usize>(pub [u8; K]);

#[derive(Clone, Debug, Copy)]
pub struct Label<const K: usize> {
    pub id: Id<K>,
    pub tag: Tag<K>,
}

impl<const K: usize> Label<K> {
    pub fn new(id: Id<K>, tag: Tag<K>) -> Self {
        Self { id, tag }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * K);
        out.extend_from_slice(&self.id.0);
        out.extend_from_slice(&self.tag.0);
        out
    }

    pub fn id(&self) -> Id<K> {
        self.id
    }

    pub fn tag(&self) -> Tag<K> {
        self.tag
    }
}

#[derive(Clone, Debug)]
pub struct SecretKey<const K: usize> {
    id: Id<K>,
    value: Scalar,
}

impl<const K: usize> SecretKey<K> {
    pub const fn new(id: Id<K>, value: Scalar) -> Self {
        Self { id, value }
    }

    pub const fn id(&self) -> Id<K> {
        self.id
    }

    pub const fn value(&self) -> &Scalar {
        &self.value
    }

    pub fn into_parts(self) -> (Id<K>, Scalar) {
        (self.id, self.value)
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey<const K: usize> {
    id: Id<K>,
    value: G2,
}

impl<const K: usize> PublicKey<K> {
    pub const fn new(id: Id<K>, value: G2) -> Self {
        Self { id, value }
    }

    pub const fn id(&self) -> Id<K> {
        self.id
    }

    pub const fn value(&self) -> &G2 {
        &self.value
    }

    pub fn into_parts(self) -> (Id<K>, G2) {
        (self.id, self.value)
    }
}

// ── mk-lhs ────────────────────────────────────────────────────────────────

/// Individual signature share $\sigma_i = (\mathsf{id}_i, \gamma_i, \mu_i)$.
#[derive(Clone, Debug)]
pub struct SignShare<const K: usize> {
    id: Id<K>,
    gamma: G1,
    mu: Scalar,
}

impl<const K: usize> SignShare<K> {
    pub const fn new(id: Id<K>, gamma: G1, mu: Scalar) -> Self {
        Self { id, gamma, mu }
    }

    pub fn id(&self) -> Id<K> {
        self.id
    }

    pub fn gamma(&self) -> &G1 {
        &self.gamma
    }

    pub fn mu(&self) -> &Scalar {
        &self.mu
    }
}

/// Linear labeled program $\mathcal{P} = (f, \{\ell_i\})$ where $f = \{a_i\}$.
#[derive(Clone, Debug)]
pub struct LabeledProgram<const K: usize> {
    coeffs: Vec<Scalar>,
    labels: Vec<Label<K>>,
}

impl<const K: usize> LabeledProgram<K> {
    pub fn new(coeffs: Vec<Scalar>, labels: Vec<Label<K>>) -> Result<Self, ProtocolError> {
        if coeffs.len() != labels.len() {
            return Err(ProtocolError::InvalidInput(
                "coeffs and labels length mismatch".to_string(),
            ));
        }
        Ok(Self { coeffs, labels })
    }

    pub fn n(&self) -> usize {
        self.coeffs.len()
    }

    pub fn coeffs(&self) -> &[Scalar] {
        &self.coeffs
    }

    pub fn labels(&self) -> &[Label<K>] {
        &self.labels
    }
}

/// Aggregated evaluated signature $\tilde\sigma = (\gamma, \{\mu_{\mathsf{id}}\})$ for mk-lhs.
#[derive(Clone, Debug)]
pub struct SignAggr<const K: usize> {
    gamma: G1,
    mus: Vec<Scalar>,
}

impl<const K: usize> SignAggr<K> {
    pub fn new(gamma: G1, mus: Vec<Scalar>) -> Self {
        Self { gamma, mus }
    }

    pub const fn gamma(&self) -> &G1 {
        &self.gamma
    }

    pub fn mus(&self) -> &[Scalar] {
        &self.mus
    }

    pub fn into_parts(self) -> (G1, Vec<Scalar>) {
        (self.gamma, self.mus)
    }

    #[cfg(test)]
    pub(crate) fn gamma_mut(&mut self) -> &mut G1 {
        &mut self.gamma
    }

    #[cfg(test)]
    pub(crate) fn mus_mut(&mut self) -> &mut Vec<Scalar> {
        &mut self.mus
    }
}

// ── mk-br-qhs1 / mk-br-qhs2 ───────────────────────────────────────────────

/// Labeled quadratic program $\mathcal{P} = (f, \{\ell_i\})$ where
/// $f = \{a_i, \mathbf{u}_i, \mathbf{v}_i\}$ and the quadratic part has rank at most R.
#[derive(Clone, Debug)]
pub struct QuadProgram<const K: usize, const R: usize> {
    a: Vec<Scalar>,
    u: Vec<[Scalar; R]>,
    v: Vec<[Scalar; R]>,
    labels: Vec<Label<K>>,
}

impl<const K: usize, const R: usize> QuadProgram<K, R> {
    pub fn new(
        a: Vec<Scalar>,
        u: Vec<[Scalar; R]>,
        v: Vec<[Scalar; R]>,
        labels: Vec<Label<K>>,
    ) -> Result<Self, ProtocolError> {
        let n = labels.len();
        if a.len() != n || u.len() != n || v.len() != n {
            return Err(ProtocolError::InvalidInput(
                "a/u/v/labels length mismatch".to_string(),
            ));
        }
        Ok(Self { a, u, v, labels })
    }

    pub fn n(&self) -> usize {
        self.labels.len()
    }

    pub fn a(&self) -> &[Scalar] {
        &self.a
    }

    pub fn u(&self) -> &[[Scalar; R]] {
        &self.u
    }

    pub fn v(&self) -> &[[Scalar; R]] {
        &self.v
    }

    pub fn labels(&self) -> &[Label<K>] {
        &self.labels
    }
}

/// Evaluated signature for mk-br-qhs1 (baseline, O(tR) size).
///
/// $\tilde\sigma = (\tilde\gamma, \{\tilde\mu_{\mathsf{id}}\})$ where
/// $\tilde\gamma = (\gamma^{(a)}, \{\gamma_r^{(u)}, \gamma_r^{(v)}\}_{r=1}^R)$ and
/// $\tilde\mu_{\mathsf{id}} = (\mu_{\mathsf{id}}^{(a)}, \boldsymbol\mu_{\mathsf{id}}^{(u)}, \boldsymbol\mu_{\mathsf{id}}^{(v)})$.
#[derive(Clone, Debug)]
pub struct QuadEvalSig1<const K: usize, const R: usize> {
    gamma_a: G1,
    gamma_u: [G1; R],
    gamma_v: [G1; R],
    mu_a: Vec<Scalar>,      // len t
    mu_u: Vec<[Scalar; R]>, // t × R
    mu_v: Vec<[Scalar; R]>, // t × R
}

impl<const K: usize, const R: usize> QuadEvalSig1<K, R> {
    pub fn new(
        gamma_a: G1,
        gamma_u: [G1; R],
        gamma_v: [G1; R],
        mu_a: Vec<Scalar>,
        mu_u: Vec<[Scalar; R]>,
        mu_v: Vec<[Scalar; R]>,
    ) -> Result<Self, ProtocolError> {
        if mu_u.len() != mu_a.len() || mu_v.len() != mu_a.len() {
            return Err(ProtocolError::InvalidInput(
                "QuadEvalSig1 length mismatch".to_string(),
            ));
        }
        Ok(Self {
            gamma_a,
            gamma_u,
            gamma_v,
            mu_a,
            mu_u,
            mu_v,
        })
    }

    pub fn gamma_a(&self) -> &G1 {
        &self.gamma_a
    }
    pub fn gamma_u(&self) -> &[G1; R] {
        &self.gamma_u
    }
    pub fn gamma_v(&self) -> &[G1; R] {
        &self.gamma_v
    }
    pub fn mu_a(&self) -> &[Scalar] {
        &self.mu_a
    }
    pub fn mu_u(&self) -> &[[Scalar; R]] {
        &self.mu_u
    }
    pub fn mu_v(&self) -> &[[Scalar; R]] {
        &self.mu_v
    }
}

/// Evaluated signature for mk-br-qhs2 (compressed, O(t + R) size).
///
/// $\tilde\sigma = (\tilde\gamma, \{\tilde\mu_{\mathsf{id}}\}, \boldsymbol\mu^{(u)}, \boldsymbol\mu^{(v)})$ where
/// $\tilde\mu_{\mathsf{id}} = (\mu_{\mathsf{id}}^{(a)}, \tilde\mu_{\mathsf{id}}^{(u,v)})$.
#[derive(Clone, Debug)]
pub struct QuadEvalSig2<const K: usize, const R: usize> {
    gamma_a: G1,
    gamma_u: [G1; R],
    gamma_v: [G1; R],
    mu_a: Vec<Scalar>,  // len t
    mu_uv: Vec<Scalar>, // len t — compressed per-id quadratic component
    mu_u_global: [Scalar; R],
    mu_v_global: [Scalar; R],
}

impl<const K: usize, const R: usize> QuadEvalSig2<K, R> {
    pub fn new(
        gamma_a: G1,
        gamma_u: [G1; R],
        gamma_v: [G1; R],
        mu_a: Vec<Scalar>,
        mu_uv: Vec<Scalar>,
        mu_u_global: [Scalar; R],
        mu_v_global: [Scalar; R],
    ) -> Result<Self, ProtocolError> {
        if mu_uv.len() != mu_a.len() {
            return Err(ProtocolError::InvalidInput(
                "QuadEvalSig2 length mismatch".to_string(),
            ));
        }
        Ok(Self {
            gamma_a,
            gamma_u,
            gamma_v,
            mu_a,
            mu_uv,
            mu_u_global,
            mu_v_global,
        })
    }

    pub fn gamma_a(&self) -> &G1 {
        &self.gamma_a
    }
    pub fn gamma_u(&self) -> &[G1; R] {
        &self.gamma_u
    }
    pub fn gamma_v(&self) -> &[G1; R] {
        &self.gamma_v
    }
    pub fn mu_a(&self) -> &[Scalar] {
        &self.mu_a
    }
    pub fn mu_uv(&self) -> &[Scalar] {
        &self.mu_uv
    }
    pub fn mu_u_global(&self) -> &[Scalar; R] {
        &self.mu_u_global
    }
    pub fn mu_v_global(&self) -> &[Scalar; R] {
        &self.mu_v_global
    }
}

// ── Message-squares variants ───────────────────────────────────────────────

/// Signature share with message-squares component:
/// $\sigma_i = (\mathsf{id}_i, \gamma_i, \gamma_i', \mu_i)$ where
/// $\gamma_i = (H_1(\ell_i) \cdot g_1^{m_i})^{\mathsf{sk}}$ and
/// $\gamma_i' = (H_2(\ell_i) \cdot g_1^{m_i^2})^{\mathsf{sk}}$.
#[derive(Clone, Debug)]
pub struct SignShareMsq<const K: usize> {
    id: Id<K>,
    gamma: G1,
    gamma_sq: G1,
    mu: Scalar,
}

impl<const K: usize> SignShareMsq<K> {
    pub const fn new(id: Id<K>, gamma: G1, gamma_sq: G1, mu: Scalar) -> Self {
        Self {
            id,
            gamma,
            gamma_sq,
            mu,
        }
    }

    pub fn id(&self) -> Id<K> {
        self.id
    }
    pub fn gamma(&self) -> &G1 {
        &self.gamma
    }
    pub fn gamma_sq(&self) -> &G1 {
        &self.gamma_sq
    }
    pub fn mu(&self) -> &Scalar {
        &self.mu
    }
}

/// Labeled quadratic program with message-squares coefficients $b_i$:
/// $f = \{a_i, b_i, \mathbf{u}_i, \mathbf{v}_i\}$.
#[derive(Clone, Debug)]
pub struct QuadProgramMsq<const K: usize, const R: usize> {
    a: Vec<Scalar>,
    b: Vec<Scalar>,
    u: Vec<[Scalar; R]>,
    v: Vec<[Scalar; R]>,
    labels: Vec<Label<K>>,
}

impl<const K: usize, const R: usize> QuadProgramMsq<K, R> {
    pub fn new(
        a: Vec<Scalar>,
        b: Vec<Scalar>,
        u: Vec<[Scalar; R]>,
        v: Vec<[Scalar; R]>,
        labels: Vec<Label<K>>,
    ) -> Result<Self, ProtocolError> {
        let n = labels.len();
        if a.len() != n || b.len() != n || u.len() != n || v.len() != n {
            return Err(ProtocolError::InvalidInput(
                "a/b/u/v/labels length mismatch".to_string(),
            ));
        }
        Ok(Self { a, b, u, v, labels })
    }

    pub fn n(&self) -> usize {
        self.labels.len()
    }
    pub fn a(&self) -> &[Scalar] {
        &self.a
    }
    pub fn b(&self) -> &[Scalar] {
        &self.b
    }
    pub fn u(&self) -> &[[Scalar; R]] {
        &self.u
    }
    pub fn v(&self) -> &[[Scalar; R]] {
        &self.v
    }
    pub fn labels(&self) -> &[Label<K>] {
        &self.labels
    }
}

/// Evaluated signature for mk-br-qhs1-msq (O(tR) size).
/// Same structure as [`QuadEvalSig1`] but with $\gamma^{(a,b)}$ and $\mu^{(a,b)}$
/// absorbing the square terms.
#[derive(Clone, Debug)]
pub struct QuadEvalSig1Msq<const K: usize, const R: usize> {
    gamma_ab: G1,
    gamma_u: [G1; R],
    gamma_v: [G1; R],
    mu_ab: Vec<Scalar>,     // len t
    mu_u: Vec<[Scalar; R]>, // t × R
    mu_v: Vec<[Scalar; R]>, // t × R
}

impl<const K: usize, const R: usize> QuadEvalSig1Msq<K, R> {
    pub fn new(
        gamma_ab: G1,
        gamma_u: [G1; R],
        gamma_v: [G1; R],
        mu_ab: Vec<Scalar>,
        mu_u: Vec<[Scalar; R]>,
        mu_v: Vec<[Scalar; R]>,
    ) -> Result<Self, ProtocolError> {
        if mu_u.len() != mu_ab.len() || mu_v.len() != mu_ab.len() {
            return Err(ProtocolError::InvalidInput(
                "QuadEvalSig1Msq length mismatch".to_string(),
            ));
        }
        Ok(Self {
            gamma_ab,
            gamma_u,
            gamma_v,
            mu_ab,
            mu_u,
            mu_v,
        })
    }

    pub fn gamma_ab(&self) -> &G1 {
        &self.gamma_ab
    }
    pub fn gamma_u(&self) -> &[G1; R] {
        &self.gamma_u
    }
    pub fn gamma_v(&self) -> &[G1; R] {
        &self.gamma_v
    }
    pub fn mu_ab(&self) -> &[Scalar] {
        &self.mu_ab
    }
    pub fn mu_u(&self) -> &[[Scalar; R]] {
        &self.mu_u
    }
    pub fn mu_v(&self) -> &[[Scalar; R]] {
        &self.mu_v
    }
}

/// Evaluated signature for mk-br-qhs2-msq (O(t + R) size).
/// Same structure as [`QuadEvalSig2`] but with $\gamma^{(a,b)}$ and $\mu^{(a,b)}$.
#[derive(Clone, Debug)]
pub struct QuadEvalSig2Msq<const K: usize, const R: usize> {
    gamma_ab: G1,
    gamma_u: [G1; R],
    gamma_v: [G1; R],
    mu_ab: Vec<Scalar>, // len t
    mu_uv: Vec<Scalar>, // len t
    mu_u_global: [Scalar; R],
    mu_v_global: [Scalar; R],
}

impl<const K: usize, const R: usize> QuadEvalSig2Msq<K, R> {
    pub fn new(
        gamma_ab: G1,
        gamma_u: [G1; R],
        gamma_v: [G1; R],
        mu_ab: Vec<Scalar>,
        mu_uv: Vec<Scalar>,
        mu_u_global: [Scalar; R],
        mu_v_global: [Scalar; R],
    ) -> Result<Self, ProtocolError> {
        if mu_uv.len() != mu_ab.len() {
            return Err(ProtocolError::InvalidInput(
                "QuadEvalSig2Msq length mismatch".to_string(),
            ));
        }
        Ok(Self {
            gamma_ab,
            gamma_u,
            gamma_v,
            mu_ab,
            mu_uv,
            mu_u_global,
            mu_v_global,
        })
    }

    pub fn gamma_ab(&self) -> &G1 {
        &self.gamma_ab
    }
    pub fn gamma_u(&self) -> &[G1; R] {
        &self.gamma_u
    }
    pub fn gamma_v(&self) -> &[G1; R] {
        &self.gamma_v
    }
    pub fn mu_ab(&self) -> &[Scalar] {
        &self.mu_ab
    }
    pub fn mu_uv(&self) -> &[Scalar] {
        &self.mu_uv
    }
    pub fn mu_u_global(&self) -> &[Scalar; R] {
        &self.mu_u_global
    }
    pub fn mu_v_global(&self) -> &[Scalar; R] {
        &self.mu_v_global
    }
}
