use crate::algebra::{H2G1, make_h2g1};

pub const DST_H2G1_LABEL: &[u8] = b"MKLHS-AP-2019-830:ELL->G1:BLS12-381:V01";
/// second hash function domain tag, used by the message-squares (msq) variants.
pub const DST_H2G1_LABEL2: &[u8] = b"MSQ:ELL2->G1:BLS12-381:V01";

pub struct Params<const K: usize> {
    dst_h2g1_label: &'static [u8],
    h2g1_label: H2G1,
    h2g1_label2: H2G1,
}

impl<const K: usize> Params<K> {
    pub fn new() -> Self {
        let h2g1_label = make_h2g1(DST_H2G1_LABEL).expect("invalid DST");
        let h2g1_label2 = make_h2g1(DST_H2G1_LABEL2).expect("invalid DST");
        Self {
            dst_h2g1_label: DST_H2G1_LABEL,
            h2g1_label,
            h2g1_label2,
        }
    }

    pub const fn dst_h2g1_label(&self) -> &'static [u8] {
        self.dst_h2g1_label
    }

    pub fn h2g1_label(&self) -> &H2G1 {
        &self.h2g1_label
    }

    pub fn h2g1_label2(&self) -> &H2G1 {
        &self.h2g1_label2
    }
}
