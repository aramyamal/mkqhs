//! Dataset loading with local file cache.

use std::fs;
use std::path::Path;

const DIABETES_URL: &str = "https://www4.stat.ncsu.edu/~boos/var.select/diabetes.tab.txt";
const DIABETES_CACHE: &str = "examples/data/diabetes.data";

/// All columns of the Efron-Hastie diabetes dataset (n = 442).
pub struct DiabetesDataset {
    pub age: Vec<f64>,
    pub sex: Vec<f64>,
    pub bmi: Vec<f64>,
    pub bp: Vec<f64>,
    pub s1: Vec<f64>,
    pub s2: Vec<f64>,
    pub s3: Vec<f64>,
    pub s4: Vec<f64>,
    pub s5: Vec<f64>,
    pub s6: Vec<f64>,
    pub y: Vec<f64>,
}

impl DiabetesDataset {
    pub fn len(&self) -> usize {
        self.y.len()
    }
}

/// On first call the raw file is downloaded and saved to `data/diabetes.data`.
/// Subsequent calls read from that cache without using internet.
pub fn load_diabetes() -> DiabetesDataset {
    let cache = Path::new(DIABETES_CACHE);

    let raw = if cache.exists() {
        eprintln!("Loading diabetes dataset from cache ({DIABETES_CACHE})...");
        fs::read_to_string(cache).expect("failed to read cache file")
    } else {
        eprintln!("Downloading diabetes dataset from {DIABETES_URL}...");
        let body = ureq::get(DIABETES_URL)
            .call()
            .expect("failed to download dataset")
            .into_string()
            .expect("failed to read response");
        fs::create_dir_all("examples/data").expect("failed to create examples/data/ directory");
        fs::write(cache, &body).expect("failed to write cache file");
        eprintln!("  Saved to {DIABETES_CACHE}");
        body
    };

    parse_diabetes(&raw)
}

fn parse_diabetes(raw: &str) -> DiabetesDataset {
    let mut age = Vec::new();
    let mut sex = Vec::new();
    let mut bmi = Vec::new();
    let mut bp = Vec::new();
    let mut s1 = Vec::new();
    let mut s2 = Vec::new();
    let mut s3 = Vec::new();
    let mut s4 = Vec::new();
    let mut s5 = Vec::new();
    let mut s6 = Vec::new();
    let mut y = Vec::new();

    for line in raw.lines().skip(1).filter(|l| !l.trim().is_empty()) {
        let cols: Vec<f64> = line
            .split('\t')
            .map(|c| c.trim().parse::<f64>().expect("invalid value"))
            .collect();
        assert_eq!(cols.len(), 11, "expected 11 columns");
        age.push(cols[0]);
        sex.push(cols[1]);
        bmi.push(cols[2]);
        bp.push(cols[3]);
        s1.push(cols[4]);
        s2.push(cols[5]);
        s3.push(cols[6]);
        s4.push(cols[7]);
        s5.push(cols[8]);
        s6.push(cols[9]);
        y.push(cols[10]);
    }

    DiabetesDataset {
        age,
        sex,
        bmi,
        bp,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        y,
    }
}
