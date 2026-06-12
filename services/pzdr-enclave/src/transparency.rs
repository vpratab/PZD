//! transparency.rs — RFC 6962 (Certificate Transparency) Merkle transparency log.
//!
//! Replaces the previous decorative Merkle "tower" that could emit a root but no
//! third-party-verifiable proofs. This module produces:
//!   - inclusion proofs   (prove a deletion-proof is recorded at a root)
//!   - consistency proofs  (prove the ledger is append-only / non-equivocating)
//!   - signed checkpoints  (signed tree heads an auditor pins)
//!
//! Hashing is byte-identical to `tools/pzdr_verify.py` and the conformance
//! vectors in `tools/conformance/`:
//!     leaf_hash(entry)  = SHA256(0x00 || entry)
//!     node_hash(l, r)   = SHA256(0x01 || l || r)
//!
//! The Python reference is the executable spec; these algorithms were validated
//! against it over all trees up to size 40 (every index, every consistency pair)
//! and against the committed golden vectors. The unit tests below re-prove it.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(entry);
    h.finalize().into()
}

pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (RFC 6962 split point).
fn split(n: usize) -> usize {
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest(b"").into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

fn inclusion(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut p = inclusion(&leaves[..k], m);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = inclusion(&leaves[k..], m - k);
        p.push(mth(&leaves[..k]));
        p
    }
}

fn subproof(m: usize, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if b { Vec::new() } else { vec![mth(leaves)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// Append-only transparency log.
#[derive(Default)]
pub struct TransparencyLog {
    leaves: Vec<Hash>,
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append a canonical-JSON entry; returns its index.
    pub fn append(&mut self, entry: &[u8]) -> usize {
        let idx = self.leaves.len();
        self.leaves.push(leaf_hash(entry));
        idx
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    pub fn root(&self) -> Hash {
        mth(&self.leaves)
    }

    pub fn root_at(&self, size: usize) -> Option<Hash> {
        (size <= self.leaves.len()).then(|| mth(&self.leaves[..size]))
    }

    /// Audit path proving leaf `idx` is included under the current root.
    pub fn inclusion_path(&self, idx: usize) -> Option<Vec<Hash>> {
        (idx < self.leaves.len()).then(|| inclusion(&self.leaves, idx))
    }

    /// Consistency proof from a past tree of size `m` to the current tree.
    pub fn consistency_path(&self, m: usize) -> Option<Vec<Hash>> {
        if m > self.leaves.len() {
            return None;
        }
        if m == 0 {
            return Some(Vec::new());
        }
        if m == self.leaves.len() {
            return Some(Vec::new());
        }
        Some(subproof(m, &self.leaves, true))
    }

    pub fn leaf_at(&self, idx: usize) -> Option<Hash> {
        self.leaves.get(idx).copied()
    }
}

/// Verify an inclusion proof (mirrors pzdr_verify.verify_inclusion).
#[cfg(test)]
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    size: usize,
    path: &[Hash],
    root: &Hash,
) -> bool {
    if index >= size || size == 0 {
        return false;
    }
    let mut f_n = index;
    let mut s_n = size - 1;
    let mut h = *leaf;
    for sib in path {
        if f_n % 2 == 1 || f_n == s_n {
            h = node_hash(sib, &h);
            while f_n.is_multiple_of(2) && f_n != 0 {
                f_n >>= 1;
                s_n >>= 1;
            }
        } else {
            h = node_hash(&h, sib);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    &h == root && s_n == 0
}

/// Verify a consistency proof between two signed tree heads
/// (mirrors pzdr_verify.verify_consistency exactly).
#[cfg(test)]
pub fn verify_consistency(
    first_size: usize,
    first_root: &Hash,
    second_size: usize,
    second_root: &Hash,
    proof: &[Hash],
) -> bool {
    if first_size > second_size {
        return false;
    }
    if first_size == second_size {
        return first_root == second_root && proof.is_empty();
    }
    if first_size == 0 {
        return true;
    }
    // pr = [first_root] + proof  when first_size is a power of two, else proof.
    let mut pr: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first_size & (first_size - 1) == 0 {
        pr.push(*first_root);
    }
    pr.extend_from_slice(proof);
    if pr.is_empty() {
        return false;
    }

    let mut f_n = first_size - 1;
    let mut s_n = second_size - 1;
    while f_n % 2 == 1 {
        f_n >>= 1;
        s_n >>= 1;
    }
    let mut fr = pr[0];
    let mut sr = pr[0];
    for c in &pr[1..] {
        if s_n == 0 {
            return false;
        }
        if f_n % 2 == 1 || f_n == s_n {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f_n.is_multiple_of(2) && f_n != 0 {
                f_n >>= 1;
                s_n >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    &fr == first_root && &sr == second_root && s_n == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: usize) -> Vec<u8> {
        format!("entry-{i}").into_bytes()
    }

    #[test]
    fn inclusion_round_trips_all_indices() {
        for n in 1..=40usize {
            let mut log = TransparencyLog::new();
            let entries: Vec<Vec<u8>> = (0..n).map(leaf).collect();
            for e in &entries {
                log.append(e);
            }
            let root = log.root();
            for (m, entry) in entries.iter().enumerate() {
                let path = log.inclusion_path(m).unwrap();
                let lh = leaf_hash(entry);
                assert!(verify_inclusion(&lh, m, n, &path, &root), "n={n} m={m}");
                // negative: a tampered first path node must fail
                if !path.is_empty() {
                    let mut bad = path.clone();
                    bad[0][0] ^= 0x01;
                    assert!(!verify_inclusion(&lh, m, n, &bad, &root));
                }
            }
        }
    }

    #[test]
    fn consistency_round_trips_and_rejects_forks() {
        for n in 1..=40usize {
            let mut log = TransparencyLog::new();
            for i in 0..n {
                log.append(&leaf(i));
            }
            let root = log.root();
            for m in 1..=n {
                let mut sub = TransparencyLog::new();
                for i in 0..m {
                    sub.append(&leaf(i));
                }
                let proof = log.consistency_path(m).unwrap();
                assert!(
                    verify_consistency(m, &sub.root(), n, &root, &proof),
                    "n={n} m={m}"
                );
                // negative: rewriting the last leaf must break consistency
                if m < n {
                    let mut forked = TransparencyLog::new();
                    for i in 0..n - 1 {
                        forked.append(&leaf(i));
                    }
                    forked.append(b"FORK");
                    let fr = forked.root();
                    if fr != root {
                        assert!(!verify_consistency(m, &sub.root(), n, &fr, &proof));
                    }
                }
            }
        }
    }
}
