//! EXP-D3-03-E-R1 — in-circuit two-event Sequential mixed transition prototype.
//!
//! Independent additive circuit: A/B/C stay frozen.  Keeps the same 8 public
//! instances and reuses the A/B/C canonical-root, Poseidon, Merkle-opening and
//! 64-bit-pair gadgets.
//!
//! Core relation (all constraints, no host pre-checks):
//!   * fixed two event slots; `active`/`is_grant`/`is_revoke` are boolean flags
//!     with `is_grant + is_revoke = active` and prefix-monotone active slots;
//!   * event 1's GR/RR inputs are copy-constrained to event 0's OUTPUT root cells
//!     (`S0 -> S1 -> S2`), never read from witness;
//!   * Grant branch reopens parent from the event's input GR (gated by is_grant),
//!     child slot empty, scope/prefix/parent/epoch semantics as in B;
//!   * Revoke branch reopens target grant from the event's input GR and writes a
//!     revoke leaf into RR while GR stays unchanged (gated by is_revoke);
//!   * both branches' event commitments are recomputed in-circuit and bound to
//!     the batch slot by gated equality; D_E / C_prev / C_next follow A exactly.
//!
//! Honest boundaries: category-II SHA-256 mapping, canonical slot layout, Bridge
//! checkpoint and freshness remain external trust.  NOT an ALLOW/DENY proof, NOT
//! Cascade / three-event / Batch-Update / recursion / history-completeness proof.

use std::convert::TryInto;

use ff::Field;
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
        Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas::Base as F;

use super::b_constants::{bit_weight, d_event_b, d_grant_b, d_node_b, DEPTH};
use super::b_types::{GrantFieldsB, OpeningB};
use super::c_constants::{d_revoke_c, TYPE_REVOKE};
use super::constants::{
    batch_pad, d_batch, d_state, policy_id, transition_version, MAX_EVENTS, PALLAS_P_BE,
};
use super::e_r1_constants::{MAX_ACTIVE_EVENTS, TYPE_GRANT};
use super::e_r1_types::{EventWitnessR1, TransitionWitnessR1};
use super::e_r1_uniqueness::neq_inv;

const BITS: usize = 256;
const U64: usize = 64;

#[derive(Clone, Debug)]
pub struct TransitionConfigR1 {
    poseidon: Pow5Config<F, 3, 2>,
    // canonical field gadget
    b_bit: Column<Advice>,
    pref: Column<Advice>,
    ltacc: Column<Advice>,
    acc: Column<Advice>,
    p_bit: Column<Fixed>,
    weight: Column<Fixed>,
    scratch: Column<Advice>,
    // control / batch
    active_col: Column<Advice>,
    flag_grant: Column<Advice>,
    flag_revoke: Column<Advice>,
    slot_col: Column<Advice>,
    n_col: Column<Advice>,
    instance: Column<Instance>,
    // Merkle path
    path_dir: Column<Advice>,
    path_sib: Column<Advice>,
    path_cur: Column<Advice>,
    path_left: Column<Advice>,
    path_right: Column<Advice>,
    // 64-bit pair
    bit_a: Column<Advice>,
    bit_b: Column<Advice>,
    acc_a: Column<Advice>,
    acc_b: Column<Advice>,
    pref_cmp: Column<Advice>,
    less_cmp: Column<Advice>,
    bit_weight_col: Column<Fixed>,
    // gated equality
    gate_flag: Column<Advice>,
    gate_l: Column<Advice>,
    gate_r: Column<Advice>,
    // state transition
    st_in: Column<Advice>,
    st_new: Column<Advice>,
    st_flag: Column<Advice>,
    st_out: Column<Advice>,
    // selectors
    q_bool_bit: Selector,
    q_cmp: Selector,
    q_final: Selector,
    q_bind_policy: Selector,
    q_bind_version: Selector,
    q_bool_active: Selector,
    q_slotpad: Selector,
    q_mono: Selector,
    q_count: Selector,
    q_bool_flag: Selector,
    q_type_split: Selector,
    q_path_bool: Selector,
    q_path_select: Selector,
    q_pair_bool: Selector,
    q_acc_a: Selector,
    q_acc_b: Selector,
    q_grant_valid: Selector,
    q_scope: Selector,
    q_prefix: Selector,
    q_epoch: Selector,
    q_epoch_final: Selector,
    q_epoch_plus_one: Selector,
    q_gate_eq: Selector,
    q_state: Selector,
    // E-R1 full-tree scan
    scan_fl: Column<Advice>,
    scan_lv: Column<Advice>,
    scan_hs: Column<Advice>,
    scan_bf: Column<Advice>,
    scan_ia: Column<Advice>,
    scan_ib: Column<Advice>,
    scan_inv: Column<Advice>,
    q_scan_bool: Selector,
    q_scan_leaf: Selector,
    q_scan_neq: Selector,
}

fn bit_weights256() -> Vec<F> {
    let mut w = vec![F::ZERO; BITS];
    w[BITS - 1] = F::ONE;
    for t in (0..BITS - 1).rev() {
        w[t] = w[t + 1] * F::from(2u64);
    }
    w
}

fn p_bits256() -> Vec<u64> {
    let mut out = Vec::with_capacity(BITS);
    for byte in PALLAS_P_BE.iter() {
        for k in 0..8 {
            out.push(u64::from((byte >> (7 - k)) & 1));
        }
    }
    out
}

fn assign_value<Fp: ff::Field>(
    region: &mut Region<'_, F>,
    column: Column<Advice>,
    row: usize,
    label: &'static str,
    value: F,
    known: bool,
) -> Result<AssignedCell<F, F>, Error> {
    let _ = std::marker::PhantomData::<Fp>;
    let v = if known {
        Value::known(value)
    } else {
        Value::unknown()
    };
    region.assign_advice(|| label, column, row, || v)
}

fn copy_equal<L: Layouter<F>>(
    layouter: &mut L,
    left: &AssignedCell<F, F>,
    right: &AssignedCell<F, F>,
) -> Result<(), Error> {
    layouter.assign_region(
        || "copy constraint",
        |mut region| region.constrain_equal(left.cell(), right.cell()),
    )
}

fn assign_root_encoding(
    cfg: &TransitionConfigR1,
    region: &mut Region<'_, F>,
    bytes: [u8; 32],
    known: bool,
) -> Result<AssignedCell<F, F>, Error> {
    let weights = bit_weights256();
    let pbits = p_bits256();
    let mut bits = [0u64; BITS];
    for (i, byte) in bytes.iter().enumerate() {
        for k in 0..8 {
            bits[i * 8 + k] = u64::from((byte >> (7 - k)) & 1);
        }
    }
    let mut pref = [F::ZERO; BITS + 1];
    pref[0] = F::ONE;
    let mut less = [F::ZERO; BITS + 1];
    let mut acc = [F::ZERO; BITS + 1];
    for t in 0..BITS {
        let b = F::from(bits[t]);
        let p = F::from(pbits[t]);
        pref[t + 1] = pref[t] * (F::ONE - (b - p) * (b - p));
        less[t + 1] = less[t] + pref[t] * (F::ONE - b) * p;
        acc[t + 1] = acc[t] + b * weights[t];
    }
    for t in 0..BITS {
        let b = F::from(bits[t]);
        assign_value::<F>(region, cfg.b_bit, t, "root_bit", b, known)?;
        cfg.q_bool_bit.enable(region, t)?;
        region.assign_fixed(|| "p_bit", cfg.p_bit, t, || Value::known(F::from(pbits[t])))?;
        region.assign_fixed(|| "weight", cfg.weight, t, || Value::known(weights[t]))?;
        cfg.q_cmp.enable(region, t)?;
    }
    let mut root_cell: Option<AssignedCell<F, F>> = None;
    for (col, values, label) in [
        (cfg.pref, &pref, "pref"),
        (cfg.ltacc, &less, "ltacc"),
        (cfg.acc, &acc, "acc"),
    ] {
        for t in 0..=BITS {
            let cell = assign_value::<F>(region, col, t, label, values[t], known)?;
            if col == cfg.acc && t == BITS {
                root_cell = Some(cell);
            }
        }
    }
    cfg.q_final.enable(region, BITS)?;
    assign_value::<F>(region, cfg.b_bit, BITS, "bit_sentinel", F::ZERO, known)?;
    root_cell.ok_or(Error::Synthesis)
}

fn hash_words<L: Layouter<F>, const N: usize>(
    cfg: &TransitionConfigR1,
    mut layouter: L,
    name: &'static str,
    words: [AssignedCell<F, F>; N],
) -> Result<AssignedCell<F, F>, Error> {
    let chip = Pow5Chip::construct(cfg.poseidon.clone());
    let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<N>, 3, 2>::init(
        chip,
        layouter.namespace(|| format!("{name}_init")),
    )?;
    hasher.hash(layouter.namespace(|| format!("{name}_hash")), words)
}

#[derive(Clone, Copy)]
enum PairMode {
    Scope,
    Prefix,
    Epoch,
    State,
}

fn assign_pair_u64(
    cfg: &TransitionConfigR1,
    region: &mut Region<'_, F>,
    a: u64,
    b: u64,
    known: bool,
    mode: PairMode,
) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
    let mut acc_a = [F::ZERO; U64 + 1];
    let mut acc_b = [F::ZERO; U64 + 1];
    let mut pref = [F::ZERO; U64 + 1];
    let mut less = [F::ZERO; U64 + 1];
    pref[0] = F::ONE;
    for i in 0..U64 {
        let ba = ((a >> (U64 - 1 - i)) & 1) as u64;
        let bb = ((b >> (U64 - 1 - i)) & 1) as u64;
        let wa = bit_weight(i, U64);
        acc_a[i + 1] = acc_a[i] + F::from(ba) * wa;
        acc_b[i + 1] = acc_b[i] + F::from(bb) * wa;
        let diff = F::from(ba) - F::from(bb);
        pref[i + 1] = pref[i] * (F::ONE - diff * diff);
        less[i + 1] = less[i] + pref[i] * (F::ONE - F::from(ba)) * F::from(bb);
    }
    for i in 0..U64 {
        let ba = ((a >> (U64 - 1 - i)) & 1) as u64;
        let bb = ((b >> (U64 - 1 - i)) & 1) as u64;
        assign_value::<F>(region, cfg.bit_a, i, "bit_a", F::from(ba), known)?;
        assign_value::<F>(region, cfg.bit_b, i, "bit_b", F::from(bb), known)?;
        assign_value::<F>(region, cfg.acc_a, i, "acc_a", acc_a[i], known)?;
        assign_value::<F>(region, cfg.acc_b, i, "acc_b", acc_b[i], known)?;
        region.assign_fixed(
            || "bw",
            cfg.bit_weight_col,
            i,
            || Value::known(bit_weight(i, U64)),
        )?;
        cfg.q_pair_bool.enable(region, i)?;
        cfg.q_acc_a.enable(region, i)?;
        cfg.q_acc_b.enable(region, i)?;
        match mode {
            PairMode::Scope => cfg.q_scope.enable(region, i)?,
            PairMode::Prefix => cfg.q_prefix.enable(region, i)?,
            PairMode::Epoch | PairMode::State => {
                assign_value::<F>(region, cfg.pref_cmp, i, "pref", pref[i], known)?;
                assign_value::<F>(region, cfg.less_cmp, i, "less", less[i], known)?;
                cfg.q_epoch.enable(region, i)?;
            }
        }
    }
    let acc_a_final = assign_value::<F>(region, cfg.acc_a, U64, "acc_a_final", acc_a[U64], known)?;
    let acc_b_final = assign_value::<F>(region, cfg.acc_b, U64, "acc_b_final", acc_b[U64], known)?;
    assign_value::<F>(region, cfg.bit_a, U64, "bit_a_sentinel", F::ZERO, known)?;
    assign_value::<F>(region, cfg.bit_b, U64, "bit_b_sentinel", F::ZERO, known)?;
    match mode {
        PairMode::Epoch | PairMode::State => {
            assign_value::<F>(region, cfg.pref_cmp, U64, "pref_final", pref[U64], known)?;
            assign_value::<F>(region, cfg.less_cmp, U64, "less_final", less[U64], known)?;
            cfg.q_epoch_final.enable(region, U64)?;
        }
        _ => {}
    }
    Ok((acc_a_final, acc_b_final))
}

fn assign_grant_words(
    cfg: &TransitionConfigR1,
    region: &mut Region<'_, F>,
    g: &GrantFieldsB,
    known: bool,
) -> Result<[AssignedCell<F, F>; 9], Error> {
    let words = [
        d_grant_b(),
        g.id,
        g.issuer,
        g.subject,
        g.prefix_f(),
        F::from(g.scope),
        g.parent_key,
        F::from(g.epoch),
        F::ONE, // valid flag enforced by q_grant_valid
    ];
    let mut cells = Vec::with_capacity(9);
    for (i, word) in words.iter().enumerate() {
        cells.push(assign_value::<F>(
            region,
            cfg.scratch,
            i,
            "grant_word",
            *word,
            known,
        )?);
    }
    cfg.q_grant_valid.enable(region, 8)?;
    Ok(cells.try_into().unwrap())
}

struct OpeningResult {
    root: AssignedCell<F, F>,
    path: Vec<(AssignedCell<F, F>, AssignedCell<F, F>)>,
}

fn assign_opening_path<L: Layouter<F>>(
    cfg: &TransitionConfigR1,
    mut layouter: L,
    d_node_cell: AssignedCell<F, F>,
    leaf: AssignedCell<F, F>,
    open: &OpeningB,
    note: &'static str,
) -> Result<OpeningResult, Error> {
    let mut cur = leaf;
    let mut path = Vec::with_capacity(DEPTH);
    for level in 0..DEPTH {
        let dir_v = F::from(open.dir[level] as u64);
        let sib_v = open.sibling[level];
        let left_v = open.left[level];
        let right_v = open.right[level];
        let cur_v = open.cur[level];
        let (cur_cell, left, right, dir_cell, sib_cell) = layouter.assign_region(
            || format!("{note}_select_{level}"),
            |mut region| -> Result<_, Error> {
                let cur_cell = assign_value::<F>(&mut region, cfg.path_cur, 0, "cur", cur_v, true)?;
                let dir_cell = assign_value::<F>(&mut region, cfg.path_dir, 0, "dir", dir_v, true)?;
                let sib_cell =
                    assign_value::<F>(&mut region, cfg.path_sib, 0, "sibling", sib_v, true)?;
                let left = assign_value::<F>(&mut region, cfg.path_left, 0, "left", left_v, true)?;
                let right =
                    assign_value::<F>(&mut region, cfg.path_right, 0, "right", right_v, true)?;
                cfg.q_path_bool.enable(&mut region, 0)?;
                cfg.q_path_select.enable(&mut region, 0)?;
                Ok((cur_cell, left, right, dir_cell, sib_cell))
            },
        )?;
        copy_equal(&mut layouter, &cur_cell, &cur)?;
        cur = hash_words(
            cfg,
            layouter.namespace(|| format!("{note}_node_{level}")),
            "node",
            [d_node_cell.clone(), left, right],
        )?;
        path.push((dir_cell, sib_cell));
    }
    Ok(OpeningResult { root: cur, path })
}

/// Gated equality: when `flag = 1`, force `left == right`.  All three cells are
/// permuted into one row via unknown-value advice cells, then `flag*(left-right)=0`
/// is enforced.  This is how branch semantics are disabled for the inactive type.
fn gated_eq<L: Layouter<F>>(
    cfg: &TransitionConfigR1,
    layouter: &mut L,
    flag: &AssignedCell<F, F>,
    left: &AssignedCell<F, F>,
    right: &AssignedCell<F, F>,
    note: &'static str,
) -> Result<(), Error> {
    let fv = flag.value().copied();
    let lv = left.value().copied();
    let rv = right.value().copied();
    layouter.assign_region(
        || note,
        |mut region| -> Result<_, Error> {
            let f = region.assign_advice(|| "flag", cfg.gate_flag, 0, || fv)?;
            let l = region.assign_advice(|| "left", cfg.gate_l, 0, || lv)?;
            let r = region.assign_advice(|| "right", cfg.gate_r, 0, || rv)?;
            region.constrain_equal(flag.cell(), f.cell())?;
            region.constrain_equal(left.cell(), l.cell())?;
            region.constrain_equal(right.cell(), r.cell())?;
            cfg.q_gate_eq.enable(&mut region, 0)?;
            Ok(())
        },
    )
}

/// Assign one scan leaf cell and bind it to its preimage hash.
///
/// `nonempty` is a boolean flag.  When nonempty=1 the leaf value must equal
/// `hash_cell` (gated by q_scan_leaf); when nonempty=0 the leaf is forced to 0
/// because `lv = flag * hs`.  This is how an empty slot becomes a real zero
/// leaf inside the recomputed Merkle tree, not a prover-declared constant.
#[allow(clippy::too_many_arguments)]
fn assign_scan_leaf<L: Layouter<F>>(
    cfg: &TransitionConfigR1,
    layouter: &mut L,
    nonempty: bool,
    hash_value: F,
    hash_cell: &AssignedCell<F, F>,
    note: &'static str,
) -> Result<AssignedCell<F, F>, Error> {
    let fv = F::from(nonempty as u64);
    let lv_value = fv * hash_value;
    let hv = hash_cell.value().copied();
    layouter.assign_region(
        || note,
        |mut region| -> Result<_, Error> {
            region.assign_advice(|| "nonempty", cfg.scan_fl, 0, || Value::known(fv))?;
            let hs = region.assign_advice(|| "hash", cfg.scan_hs, 0, || hv)?;
            region.constrain_equal(hash_cell.cell(), hs.cell())?;
            let lv = region.assign_advice(|| "leaf", cfg.scan_lv, 0, || Value::known(lv_value))?;
            cfg.q_scan_bool.enable(&mut region, 0)?;
            cfg.q_scan_leaf.enable(&mut region, 0)?;
            Ok(lv)
        },
    )
}

/// One in-circuit ID-inequality check, gated by both the leaf's nonempty flag
/// and the event-branch flag.  The witness `inv` must be `(a-b)^-1`; if a==b
/// no inverse exists and the constraint `fl*bf*((a-b)*inv - 1)=0` fails.
#[allow(clippy::too_many_arguments)]
fn scan_id_neq<L: Layouter<F>>(
    cfg: &TransitionConfigR1,
    layouter: &mut L,
    nonempty: bool,
    branch: &AssignedCell<F, F>,
    a: &AssignedCell<F, F>,
    b: &AssignedCell<F, F>,
    inv: F,
    note: &'static str,
) -> Result<(), Error> {
    let fv = F::from(nonempty as u64);
    let bv = branch.value().copied();
    let av = a.value().copied();
    let bvv = b.value().copied();
    layouter.assign_region(
        || note,
        |mut region| -> Result<_, Error> {
            region.assign_advice(|| "nonempty", cfg.scan_fl, 0, || Value::known(fv))?;
            let bf = region.assign_advice(|| "branch", cfg.scan_bf, 0, || bv)?;
            region.constrain_equal(branch.cell(), bf.cell())?;
            let ia = region.assign_advice(|| "id_a", cfg.scan_ia, 0, || av)?;
            region.constrain_equal(a.cell(), ia.cell())?;
            let ib = region.assign_advice(|| "id_b", cfg.scan_ib, 0, || bvv)?;
            region.constrain_equal(b.cell(), ib.cell())?;
            region.assign_advice(|| "inv", cfg.scan_inv, 0, || Value::known(inv))?;
            cfg.q_scan_neq.enable(&mut region, 0)?;
            Ok(())
        },
    )
}

/// Recompute a depth-4 Merkle root from 16 leaf cells.  Internal nodes use the
/// frozen `D_NODE` Poseidon(hash(left,right)) with left/right ordering by slot
/// index; this matches `SparseTreeB::opening/root` in b_types.rs.
fn recompute_root_from_leaves<L: Layouter<F>>(
    cfg: &TransitionConfigR1,
    layouter: &mut L,
    d_node: &AssignedCell<F, F>,
    leaves: Vec<AssignedCell<F, F>>,
    note: &'static str,
) -> Result<AssignedCell<F, F>, Error> {
    let mut level = leaves;
    for d in 0..super::b_constants::DEPTH {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_words(
                cfg,
                layouter.namespace(|| format!("{note}_l{d}")),
                "node",
                [d_node.clone(), pair[0].clone(), pair[1].clone()],
            )?);
        }
        level = next;
    }
    level.into_iter().next().ok_or(Error::Synthesis)
}

/// State transition cell: `out = in + flag*(new-in)`.  `in/new/flag` are permuted
/// in (unknown values), `out` is assigned from the host-computed value; the gate
/// enforces the relation.  The returned `out` cell feeds the next event's input.
#[allow(clippy::too_many_arguments)]
fn state_transition<L: Layouter<F>>(
    cfg: &TransitionConfigR1,
    layouter: &mut L,
    state_in: &AssignedCell<F, F>,
    state_new: &AssignedCell<F, F>,
    flag: &AssignedCell<F, F>,
    in_val: F,
    new_val: F,
    flag_val: F,
    known: bool,
    note: &'static str,
) -> Result<AssignedCell<F, F>, Error> {
    let out_val = in_val + flag_val * (new_val - in_val);
    let iv = state_in.value().copied();
    let nv = state_new.value().copied();
    let fvv = flag.value().copied();
    layouter.assign_region(
        || note,
        |mut region| -> Result<_, Error> {
            let i = region.assign_advice(|| "in", cfg.st_in, 0, || iv)?;
            let n = region.assign_advice(|| "new", cfg.st_new, 0, || nv)?;
            let f = region.assign_advice(|| "flag", cfg.st_flag, 0, || fvv)?;
            let o = assign_value::<F>(&mut region, cfg.st_out, 0, "out", out_val, known)?;
            region.constrain_equal(state_in.cell(), i.cell())?;
            region.constrain_equal(state_new.cell(), n.cell())?;
            region.constrain_equal(flag.cell(), f.cell())?;
            cfg.q_state.enable(&mut region, 0)?;
            Ok(o)
        },
    )
}

#[derive(Clone, Debug)]
pub struct TransitionCircuitR1 {
    pub witness: Option<TransitionWitnessR1>,
}

impl TransitionCircuitR1 {
    pub fn new(witness: TransitionWitnessR1) -> Self {
        Self {
            witness: Some(witness),
        }
    }
    pub fn for_keygen() -> Self {
        Self { witness: None }
    }
}

impl Circuit<F> for TransitionCircuitR1 {
    type Config = TransitionConfigR1;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::for_keygen()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let state: [Column<Advice>; 3] = (0..3)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let partial_sbox = meta.advice_column();
        let rc_a: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let rc_b: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        let b_bit = meta.advice_column();
        let pref = meta.advice_column();
        let ltacc = meta.advice_column();
        let acc = meta.advice_column();
        let p_bit = meta.fixed_column();
        let weight = meta.fixed_column();
        let scratch = meta.advice_column();
        let active_col = meta.advice_column();
        let flag_grant = meta.advice_column();
        let flag_revoke = meta.advice_column();
        let slot_col = meta.advice_column();
        let n_col = meta.advice_column();
        let instance = meta.instance_column();
        let path_dir = meta.advice_column();
        let path_sib = meta.advice_column();
        let path_cur = meta.advice_column();
        let path_left = meta.advice_column();
        let path_right = meta.advice_column();
        let bit_a = meta.advice_column();
        let bit_b = meta.advice_column();
        let acc_a = meta.advice_column();
        let acc_b = meta.advice_column();
        let pref_cmp = meta.advice_column();
        let less_cmp = meta.advice_column();
        let bit_weight_col = meta.fixed_column();
        let gate_flag = meta.advice_column();
        let gate_l = meta.advice_column();
        let gate_r = meta.advice_column();
        let st_in = meta.advice_column();
        let st_new = meta.advice_column();
        let st_flag = meta.advice_column();
        let st_out = meta.advice_column();
        let scan_fl = meta.advice_column();
        let scan_lv = meta.advice_column();
        let scan_hs = meta.advice_column();
        let scan_bf = meta.advice_column();
        let scan_ia = meta.advice_column();
        let scan_ib = meta.advice_column();
        let scan_inv = meta.advice_column();

        for col in [
            b_bit,
            pref,
            ltacc,
            acc,
            scratch,
            active_col,
            flag_grant,
            flag_revoke,
            slot_col,
            n_col,
            path_dir,
            path_sib,
            path_cur,
            path_left,
            path_right,
            bit_a,
            bit_b,
            acc_a,
            acc_b,
            pref_cmp,
            less_cmp,
            gate_flag,
            gate_l,
            gate_r,
            st_in,
            st_new,
            st_flag,
            st_out,
            scan_fl,
            scan_lv,
            scan_hs,
            scan_bf,
            scan_ia,
            scan_ib,
            scan_inv,
        ] {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance);

        let q_bool_bit = meta.selector();
        let q_cmp = meta.selector();
        let q_final = meta.selector();
        let q_bind_policy = meta.selector();
        let q_bind_version = meta.selector();
        let q_bool_active = meta.selector();
        let q_slotpad = meta.selector();
        let q_mono = meta.selector();
        let q_count = meta.selector();
        let q_bool_flag = meta.selector();
        let q_type_split = meta.selector();
        let q_path_bool = meta.selector();
        let q_path_select = meta.selector();
        let q_pair_bool = meta.selector();
        let q_acc_a = meta.selector();
        let q_acc_b = meta.selector();
        let q_grant_valid = meta.selector();
        let q_scope = meta.selector();
        let q_prefix = meta.selector();
        let q_epoch = meta.selector();
        let q_epoch_final = meta.selector();
        let q_epoch_plus_one = meta.selector();
        let q_gate_eq = meta.selector();
        let q_state = meta.selector();
        let q_scan_bool = meta.selector();
        let q_scan_leaf = meta.selector();
        let q_scan_neq = meta.selector();

        // canonical field gadget (identical to A/B/C)
        meta.create_gate("root-bit-boolean", |meta| {
            let q = meta.query_selector(q_bool_bit);
            let b = meta.query_advice(b_bit, Rotation::cur());
            Constraints::with_selector(q, vec![b.clone() * b.clone() - b])
        });
        meta.create_gate("canonical-transition", |meta| {
            let q = meta.query_selector(q_cmp);
            let bit = meta.query_advice(b_bit, Rotation::cur());
            let p = meta.query_fixed(p_bit);
            let w = meta.query_fixed(weight);
            let pref_cur = meta.query_advice(pref, Rotation::cur());
            let less_cur = meta.query_advice(ltacc, Rotation::cur());
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let pref_next = meta.query_advice(pref, Rotation::next());
            let less_next = meta.query_advice(ltacc, Rotation::next());
            let acc_next = meta.query_advice(acc, Rotation::next());
            let diff = bit.clone() - p.clone();
            Constraints::with_selector(
                q,
                vec![
                    pref_next
                        - pref_cur.clone() * (Expression::Constant(F::ONE) - diff.clone() * diff),
                    less_next
                        - less_cur
                        - pref_cur * (Expression::Constant(F::ONE) - bit.clone()) * p,
                    acc_next - acc_cur - bit * w,
                ],
            )
        });
        meta.create_gate("canonical-final", |meta| {
            let q = meta.query_selector(q_final);
            let less = meta.query_advice(ltacc, Rotation::cur());
            Constraints::with_selector(q, vec![less - Expression::Constant(F::ONE)])
        });
        meta.create_gate("bind-policy", |meta| {
            let q = meta.query_selector(q_bind_policy);
            let a = meta.query_advice(scratch, Rotation::cur());
            Constraints::with_selector(q, vec![a - Expression::Constant(policy_id())])
        });
        meta.create_gate("bind-version", |meta| {
            let q = meta.query_selector(q_bind_version);
            let a = meta.query_advice(scratch, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![a - Expression::Constant(F::from(transition_version() as u64))],
            )
        });

        // control + batch gates
        meta.create_gate("active-boolean", |meta| {
            let q = meta.query_selector(q_bool_active);
            let a = meta.query_advice(active_col, Rotation::cur());
            Constraints::with_selector(q, vec![a.clone() * a.clone() - a])
        });
        meta.create_gate("type-flag-boolean", |meta| {
            let q = meta.query_selector(q_bool_flag);
            let g = meta.query_advice(flag_grant, Rotation::cur());
            let r = meta.query_advice(flag_revoke, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![g.clone() * g.clone() - g, r.clone() * r.clone() - r],
            )
        });
        meta.create_gate("type-split", |meta| {
            let q = meta.query_selector(q_type_split);
            let g = meta.query_advice(flag_grant, Rotation::cur());
            let r = meta.query_advice(flag_revoke, Rotation::cur());
            let a = meta.query_advice(active_col, Rotation::cur());
            Constraints::with_selector(q, vec![g + r - a])
        });
        meta.create_gate("slot-padding", |meta| {
            let q = meta.query_selector(q_slotpad);
            let active = meta.query_advice(active_col, Rotation::cur());
            let slot = meta.query_advice(slot_col, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![
                    (Expression::Constant(F::ONE) - active)
                        * (slot - Expression::Constant(batch_pad())),
                ],
            )
        });
        meta.create_gate("active-monotone", |meta| {
            let q = meta.query_selector(q_mono);
            let a = meta.query_advice(active_col, Rotation::cur());
            let a_next = meta.query_advice(active_col, Rotation::next());
            Constraints::with_selector(q, vec![a_next * (Expression::Constant(F::ONE) - a)])
        });
        meta.create_gate("active-count", |meta| {
            let q = meta.query_selector(q_count);
            let n = meta.query_advice(n_col, Rotation::cur());
            let mut sum = Expression::Constant(F::ZERO);
            for i in 0..MAX_EVENTS {
                sum = sum + meta.query_advice(active_col, Rotation(i as i32));
            }
            Constraints::with_selector(q, vec![n - sum])
        });

        // Merkle path
        meta.create_gate("path-dir-bool", |meta| {
            let q = meta.query_selector(q_path_bool);
            let d = meta.query_advice(path_dir, Rotation::cur());
            Constraints::with_selector(q, vec![d.clone() * d.clone() - d])
        });
        meta.create_gate("path-select", |meta| {
            let q = meta.query_selector(q_path_select);
            let d = meta.query_advice(path_dir, Rotation::cur());
            let cur = meta.query_advice(path_cur, Rotation::cur());
            let sib = meta.query_advice(path_sib, Rotation::cur());
            let left = meta.query_advice(path_left, Rotation::cur());
            let right = meta.query_advice(path_right, Rotation::cur());
            let one = Expression::Constant(F::ONE);
            Constraints::with_selector(
                q,
                vec![
                    left - ((one.clone() - d.clone()) * cur.clone() + d.clone() * sib.clone()),
                    right - (d.clone() * cur + (one - d) * sib),
                ],
            )
        });

        // 64-bit pair gates
        meta.create_gate("pair-bit-bool", |meta| {
            let q = meta.query_selector(q_pair_bool);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![a.clone() * a.clone() - a, b.clone() * b.clone() - b],
            )
        });
        meta.create_gate("pair-acc-a", |meta| {
            let q = meta.query_selector(q_acc_a);
            let an = meta.query_advice(acc_a, Rotation::next());
            let ac = meta.query_advice(acc_a, Rotation::cur());
            let bit = meta.query_advice(bit_a, Rotation::cur());
            let w = meta.query_fixed(bit_weight_col);
            Constraints::with_selector(q, vec![an - ac - bit * w])
        });
        meta.create_gate("pair-acc-b", |meta| {
            let q = meta.query_selector(q_acc_b);
            let an = meta.query_advice(acc_b, Rotation::next());
            let ac = meta.query_advice(acc_b, Rotation::cur());
            let bit = meta.query_advice(bit_b, Rotation::cur());
            let w = meta.query_fixed(bit_weight_col);
            Constraints::with_selector(q, vec![an - ac - bit * w])
        });
        meta.create_gate("grant-valid-one", |meta| {
            let q = meta.query_selector(q_grant_valid);
            let a = meta.query_advice(scratch, Rotation::cur());
            Constraints::with_selector(q, vec![a - Expression::Constant(F::ONE)])
        });
        meta.create_gate("scope-subset", |meta| {
            let q = meta.query_selector(q_scope);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(q, vec![a * (Expression::Constant(F::ONE) - b)])
        });
        meta.create_gate("prefix-eq", |meta| {
            let q = meta.query_selector(q_prefix);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(q, vec![a - b])
        });
        meta.create_gate("epoch-pref", |meta| {
            let q = meta.query_selector(q_epoch);
            let pn = meta.query_advice(pref_cmp, Rotation::next());
            let pc = meta.query_advice(pref_cmp, Rotation::cur());
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            let diff = a - b;
            Constraints::with_selector(
                q,
                vec![pn - pc * (Expression::Constant(F::ONE) - diff.clone() * diff)],
            )
        });
        meta.create_gate("epoch-less", |meta| {
            let q = meta.query_selector(q_epoch);
            let ln = meta.query_advice(less_cmp, Rotation::next());
            let lc = meta.query_advice(less_cmp, Rotation::cur());
            let pc = meta.query_advice(pref_cmp, Rotation::cur());
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![ln - lc - pc * (Expression::Constant(F::ONE) - a) * b],
            )
        });
        meta.create_gate("epoch-final", |meta| {
            let q = meta.query_selector(q_epoch_final);
            let less = meta.query_advice(less_cmp, Rotation::cur());
            Constraints::with_selector(q, vec![less])
        });
        meta.create_gate("epoch-plus-one", |meta| {
            let q = meta.query_selector(q_epoch_plus_one);
            let prev = meta.query_advice(scratch, Rotation::cur());
            let next = meta.query_advice(scratch, Rotation::next());
            Constraints::with_selector(q, vec![next - prev - Expression::Constant(F::ONE)])
        });

        // gated equality: flag * (left - right) = 0
        meta.create_gate("gated-eq", |meta| {
            let q = meta.query_selector(q_gate_eq);
            let f = meta.query_advice(gate_flag, Rotation::cur());
            let l = meta.query_advice(gate_l, Rotation::cur());
            let r = meta.query_advice(gate_r, Rotation::cur());
            Constraints::with_selector(q, vec![f * (l - r)])
        });
        // state transition: out - (in + flag*(new-in)) = 0
        meta.create_gate("state-transition", |meta| {
            let q = meta.query_selector(q_state);
            let i = meta.query_advice(st_in, Rotation::cur());
            let n = meta.query_advice(st_new, Rotation::cur());
            let f = meta.query_advice(st_flag, Rotation::cur());
            let o = meta.query_advice(st_out, Rotation::cur());
            Constraints::with_selector(q, vec![o - (i.clone() + f * (n - i))])
        });

        // E-R1 scan gates
        meta.create_gate("scan-nonempty-boolean", |meta| {
            let q = meta.query_selector(q_scan_bool);
            let f = meta.query_advice(scan_fl, Rotation::cur());
            Constraints::with_selector(q, vec![f.clone() * f.clone() - f])
        });
        meta.create_gate("scan-leaf-select", |meta| {
            let q = meta.query_selector(q_scan_leaf);
            let f = meta.query_advice(scan_fl, Rotation::cur());
            let lv = meta.query_advice(scan_lv, Rotation::cur());
            let hs = meta.query_advice(scan_hs, Rotation::cur());
            Constraints::with_selector(q, vec![lv - f * hs])
        });
        meta.create_gate("scan-id-neq", |meta| {
            let q = meta.query_selector(q_scan_neq);
            let fl = meta.query_advice(scan_fl, Rotation::cur());
            let bf = meta.query_advice(scan_bf, Rotation::cur());
            let a = meta.query_advice(scan_ia, Rotation::cur());
            let b = meta.query_advice(scan_ib, Rotation::cur());
            let inv = meta.query_advice(scan_inv, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![fl * bf * ((a - b) * inv - Expression::Constant(F::ONE))],
            )
        });

        TransitionConfigR1 {
            poseidon,
            b_bit,
            pref,
            ltacc,
            acc,
            p_bit,
            weight,
            scratch,
            active_col,
            flag_grant,
            flag_revoke,
            slot_col,
            n_col,
            instance,
            path_dir,
            path_sib,
            path_cur,
            path_left,
            path_right,
            bit_a,
            bit_b,
            acc_a,
            acc_b,
            pref_cmp,
            less_cmp,
            bit_weight_col,
            gate_flag,
            gate_l,
            gate_r,
            st_in,
            st_new,
            st_flag,
            st_out,
            q_bool_bit,
            q_cmp,
            q_final,
            q_bind_policy,
            q_bind_version,
            q_bool_active,
            q_slotpad,
            q_mono,
            q_count,
            q_bool_flag,
            q_type_split,
            q_path_bool,
            q_path_select,
            q_pair_bool,
            q_acc_a,
            q_acc_b,
            q_grant_valid,
            q_scope,
            q_prefix,
            q_epoch,
            q_epoch_final,
            q_epoch_plus_one,
            q_gate_eq,
            q_state,
            scan_fl,
            scan_lv,
            scan_hs,
            scan_bf,
            scan_ia,
            scan_ib,
            scan_inv,
            q_scan_bool,
            q_scan_leaf,
            q_scan_neq,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let known = self.witness.is_some();
        let w = self
            .witness
            .clone()
            .unwrap_or_else(super::e_r1_types_host::blank_r1);
        let val = |x: F| {
            if known {
                Value::known(x)
            } else {
                Value::unknown()
            }
        };

        // ---- 1. constants ----
        let (
            d_state_cell,
            d_batch_cell,
            d_node_cell,
            d_event_cell,
            _d_grant_cell,
            _d_revoke_cell,
            _type_grant_cell,
            _type_revoke_cell,
            zero_cell,
            policy_cell,
            version_cell,
            epoch_prev,
            epoch_next,
        ) = layouter.assign_region(
            || "constants",
            |mut region| -> Result<_, Error> {
                let sc = config.scratch;
                let ds = assign_value::<F>(&mut region, sc, 0, "d_state", d_state(), known)?;
                let db = assign_value::<F>(&mut region, sc, 1, "d_batch", d_batch(), known)?;
                let dn = assign_value::<F>(&mut region, sc, 2, "d_node", d_node_b(), known)?;
                let de = assign_value::<F>(&mut region, sc, 3, "d_event", d_event_b(), known)?;
                let dg = assign_value::<F>(&mut region, sc, 4, "d_grant", d_grant_b(), known)?;
                let dr = assign_value::<F>(&mut region, sc, 5, "d_revoke", d_revoke_c(), known)?;
                let tg = assign_value::<F>(
                    &mut region,
                    sc,
                    6,
                    "type_grant",
                    F::from(TYPE_GRANT),
                    known,
                )?;
                let tr = assign_value::<F>(
                    &mut region,
                    sc,
                    7,
                    "type_revoke",
                    F::from(TYPE_REVOKE),
                    known,
                )?;
                let zc = assign_value::<F>(&mut region, sc, 8, "zero", F::ZERO, known)?;
                let pc = assign_value::<F>(&mut region, sc, 9, "policy", policy_id(), known)?;
                config.q_bind_policy.enable(&mut region, 9)?;
                let vc = assign_value::<F>(
                    &mut region,
                    sc,
                    10,
                    "version",
                    F::from(transition_version() as u64),
                    known,
                )?;
                config.q_bind_version.enable(&mut region, 10)?;
                let ep = assign_value::<F>(
                    &mut region,
                    sc,
                    11,
                    "prev_epoch",
                    F::from(w.prev_epoch),
                    known,
                )?;
                let en = assign_value::<F>(
                    &mut region,
                    sc,
                    12,
                    "next_epoch",
                    F::from(w.next_epoch),
                    known,
                )?;
                config.q_epoch_plus_one.enable(&mut region, 11)?;
                Ok((ds, db, dn, de, dg, dr, tg, tr, zc, pc, vc, ep, en))
            },
        )?;

        // ---- 2. S0 canonical roots ----
        let mut mk_root = |name: &'static str, bytes: [u8; 32]| {
            let cfg = config.clone();
            layouter.assign_region(
                || name,
                move |mut region| assign_root_encoding(&cfg, &mut region, bytes, known),
            )
        };
        let gprev = mk_root("gr_prev", w.gr_prev_be)?;
        let rprev = mk_root("rr_prev", w.rr_prev_be)?;

        // ---- 3. control + batch region (single table, 3 rows: e0, e1, pad) ----
        let (_active_cells, grant_cells, revoke_cells, slot_cells, n_cell) = layouter
            .assign_region(
                || "control and batch",
                |mut region| -> Result<_, Error> {
                    let mut act = Vec::with_capacity(MAX_EVENTS);
                    let mut gc = Vec::with_capacity(MAX_EVENTS);
                    let mut rc = Vec::with_capacity(MAX_EVENTS);
                    let mut slots = Vec::with_capacity(MAX_EVENTS);
                    for i in 0..MAX_EVENTS {
                        let (a_v, g_v, r_v) = if i < MAX_ACTIVE_EVENTS {
                            let e = &w.events[i];
                            (e.active, e.is_grant, e.is_revoke)
                        } else {
                            (false, false, false)
                        };
                        let a = assign_value::<F>(
                            &mut region,
                            config.active_col,
                            i,
                            "active",
                            F::from(a_v as u64),
                            known,
                        )?;
                        let g = assign_value::<F>(
                            &mut region,
                            config.flag_grant,
                            i,
                            "is_grant",
                            F::from(g_v as u64),
                            known,
                        )?;
                        let r = assign_value::<F>(
                            &mut region,
                            config.flag_revoke,
                            i,
                            "is_revoke",
                            F::from(r_v as u64),
                            known,
                        )?;
                        let s = assign_value::<F>(
                            &mut region,
                            config.slot_col,
                            i,
                            "slot",
                            if i < 3 {
                                w.event_commitments[i]
                            } else {
                                batch_pad()
                            },
                            known,
                        )?;
                        config.q_bool_active.enable(&mut region, i)?;
                        config.q_bool_flag.enable(&mut region, i)?;
                        config.q_type_split.enable(&mut region, i)?;
                        config.q_slotpad.enable(&mut region, i)?;
                        if i + 1 < MAX_EVENTS {
                            config.q_mono.enable(&mut region, i)?;
                        }
                        act.push(a);
                        gc.push(g);
                        rc.push(r);
                        slots.push(s);
                    }
                    let n = assign_value::<F>(
                        &mut region,
                        config.n_col,
                        0,
                        "n",
                        F::from(w.event_count as u64),
                        known,
                    )?;
                    config.q_count.enable(&mut region, 0)?;
                    Ok((act, gc, rc, slots, n))
                },
            )?;

        // ---- 4. state epoch pair (next >= prev, plus field +1 above) ----
        let (next_acc, prev_acc) = layouter.assign_region(
            || "state epoch pair",
            |mut region| {
                assign_pair_u64(
                    &config,
                    &mut region,
                    w.next_epoch,
                    w.prev_epoch,
                    known,
                    PairMode::State,
                )
            },
        )?;
        copy_equal(&mut layouter, &next_acc, &epoch_next)?;
        copy_equal(&mut layouter, &prev_acc, &epoch_prev)?;

        // ---- 5. two sequential events ----
        let decode = |be: &[u8; 32]| super::constants::decode_field_i(be).unwrap_or(F::ZERO);
        let mut gr_in: Vec<AssignedCell<F, F>> = vec![gprev.clone()];
        let mut rr_in: Vec<AssignedCell<F, F>> = vec![rprev.clone()];
        let mut gr_in_val = vec![decode(&w.gr_prev_be)];
        let mut rr_in_val = vec![decode(&w.rr_prev_be)];

        for i in 0..MAX_ACTIVE_EVENTS {
            let e: &EventWitnessR1 = &w.events[i];
            let gf = F::from(e.is_grant as u64);
            let rf = F::from(e.is_revoke as u64);

            // ---- Grant branch ----
            let parent_words = layouter.assign_region(
                || format!("event{i} parent grant words"),
                |mut region| assign_grant_words(&config, &mut region, &e.parent, known),
            )?;
            let child_words = layouter.assign_region(
                || format!("event{i} child grant words"),
                |mut region| assign_grant_words(&config, &mut region, &e.child, known),
            )?;
            let parent_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("e{i}_parent_leaf")),
                "parent_leaf",
                parent_words.clone(),
            )?;
            let child_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("e{i}_child_leaf")),
                "child_leaf",
                child_words.clone(),
            )?;
            // unconditional grant bindings (dummy branches are self-consistent)
            copy_equal(&mut layouter, &child_words[6], &parent_words[1])?; // parent_key == parent.id
            copy_equal(&mut layouter, &child_words[2], &parent_words[3])?; // issuer == parent.subject
            copy_equal(&mut layouter, &child_words[7], &epoch_next)?; // child.epoch == next_epoch

            let (scope_c, scope_p) = layouter.assign_region(
                || format!("e{i} scope subset"),
                |mut region| {
                    assign_pair_u64(
                        &config,
                        &mut region,
                        e.child.scope,
                        e.parent.scope,
                        known,
                        PairMode::Scope,
                    )
                },
            )?;
            copy_equal(&mut layouter, &scope_c, &child_words[5])?;
            copy_equal(&mut layouter, &scope_p, &parent_words[5])?;

            let (pref_c, pref_p) = layouter.assign_region(
                || format!("e{i} resource prefix"),
                |mut region| {
                    assign_pair_u64(
                        &config,
                        &mut region,
                        u64::from_be_bytes(e.child.resource_prefix),
                        u64::from_be_bytes(e.parent.resource_prefix),
                        known,
                        PairMode::Prefix,
                    )
                },
            )?;
            copy_equal(&mut layouter, &pref_c, &child_words[4])?;
            copy_equal(&mut layouter, &pref_p, &parent_words[4])?;

            let (ep_c, ep_p) = layouter.assign_region(
                || format!("e{i} epoch monotonic"),
                |mut region| {
                    assign_pair_u64(
                        &config,
                        &mut region,
                        e.child.epoch,
                        e.parent.epoch,
                        known,
                        PairMode::Epoch,
                    )
                },
            )?;
            copy_equal(&mut layouter, &ep_c, &child_words[7])?;
            copy_equal(&mut layouter, &ep_p, &parent_words[7])?;

            let parent_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("e{i} parent opening")),
                d_node_cell.clone(),
                parent_leaf,
                &e.parent_open,
                "parent",
            )?;
            let child_old_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("e{i} child old opening")),
                d_node_cell.clone(),
                zero_cell.clone(),
                &e.child_old_open,
                "child_old",
            )?;
            let child_new_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("e{i} child new opening")),
                d_node_cell.clone(),
                child_leaf.clone(),
                &e.child_new_open,
                "child_new",
            )?;
            for l in 0..DEPTH {
                copy_equal(
                    &mut layouter,
                    &child_new_opening.path[l].0,
                    &child_old_opening.path[l].0,
                )?;
                copy_equal(
                    &mut layouter,
                    &child_new_opening.path[l].1,
                    &child_old_opening.path[l].1,
                )?;
            }

            // ---- Revoke branch ----
            let target_words = layouter.assign_region(
                || format!("e{i} target grant words"),
                |mut region| assign_grant_words(&config, &mut region, &e.target, known),
            )?;
            let (rv_id, rv_revoker, rv_epoch) = layouter.assign_region(
                || format!("e{i} revoke event words"),
                |mut region| -> Result<_, Error> {
                    let id = assign_value::<F>(
                        &mut region,
                        config.scratch,
                        0,
                        "revoke_grant_id",
                        e.revoke.grant_id,
                        known,
                    )?;
                    let rev = assign_value::<F>(
                        &mut region,
                        config.scratch,
                        1,
                        "revoke_revoker",
                        e.revoke.revoker,
                        known,
                    )?;
                    let ep = assign_value::<F>(
                        &mut region,
                        config.scratch,
                        2,
                        "revoke_epoch",
                        F::from(e.revoke.epoch),
                        known,
                    )?;
                    Ok((id, rev, ep))
                },
            )?;
            copy_equal(&mut layouter, &target_words[1], &rv_id)?; // target.id == revoke.grant_id
            copy_equal(&mut layouter, &target_words[2], &rv_revoker)?; // target.issuer == revoker
            copy_equal(&mut layouter, &rv_epoch, &epoch_next)?; // revoke.epoch == next_epoch

            let target_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("e{i}_target_leaf")),
                "target_leaf",
                target_words.clone(),
            )?;
            let revoke_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("e{i}_revoke_leaf")),
                "revoke_leaf",
                [
                    _d_revoke_cell.clone(),
                    rv_id.clone(),
                    rv_revoker.clone(),
                    rv_epoch.clone(),
                ],
            )?;
            let target_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("e{i} target opening")),
                d_node_cell.clone(),
                target_leaf,
                &e.target_open,
                "target",
            )?;
            let rr_old_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("e{i} rr old opening")),
                d_node_cell.clone(),
                zero_cell.clone(),
                &e.rr_old_open,
                "rr_old",
            )?;
            let rr_new_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("e{i} rr new opening")),
                d_node_cell.clone(),
                revoke_leaf,
                &e.rr_new_open,
                "rr_new",
            )?;
            for l in 0..DEPTH {
                copy_equal(
                    &mut layouter,
                    &rr_new_opening.path[l].0,
                    &rr_old_opening.path[l].0,
                )?;
                copy_equal(
                    &mut layouter,
                    &rr_new_opening.path[l].1,
                    &rr_old_opening.path[l].1,
                )?;
            }

            // ---- gated semantic root bindings ----
            gated_eq(
                &config,
                &mut layouter,
                &grant_cells[i],
                &parent_opening.root,
                &gr_in[i],
                "grant parent in GR",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &grant_cells[i],
                &child_old_opening.root,
                &gr_in[i],
                "grant child slot empty",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &revoke_cells[i],
                &target_opening.root,
                &gr_in[i],
                "revoke target in GR",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &revoke_cells[i],
                &rr_old_opening.root,
                &rr_in[i],
                "revoke slot empty in RR",
            )?;

            // ---- E-R1 full-tree scan: ID-level uniqueness / revocation validity ----
            let scan = &w.scans[i];
            let d_node_scan = d_node_cell.clone();

            // GR scan: recompute root from 16 GR leaf preimages, bind to gr_in[i].
            // Each non-empty leaf also proves its id != child.id (Grant uniqueness).
            let mut gr_scan_leaves: Vec<AssignedCell<F, F>> = Vec::with_capacity(16);
            for slot in 0..16 {
                let leaf = &scan.gr[slot];
                let words = layouter.assign_region(
                    || format!("e{i} scan gr words {slot}"),
                    |mut region| assign_grant_words(&config, &mut region, &leaf.grant, known),
                )?;
                let h = hash_words(
                    &config,
                    layouter.namespace(|| format!("e{i}_scan_gr_hash_{slot}")),
                    "scan_gr_leaf",
                    words.clone(),
                )?;
                let hval = leaf.grant.leaf(true);
                let lv = assign_scan_leaf(
                    &config,
                    &mut layouter,
                    !leaf.empty,
                    hval,
                    &h,
                    "scan gr leaf select",
                )?;
                // Region creation must be unconditional: keygen (blank witness)
                // and prove (real witness) must produce the same layout.
                // The gate itself is disabled for empty slots via scan_fl=0.
                let inv = neq_inv(leaf.grant.id, e.child.id).unwrap_or(F::ZERO);
                scan_id_neq(
                    &config,
                    &mut layouter,
                    !leaf.empty,
                    &grant_cells[i],
                    &words[1],
                    &child_words[1],
                    inv,
                    "grant id global unique in GR",
                )?;
                gr_scan_leaves.push(lv);
            }
            let gr_scan_root = recompute_root_from_leaves(
                &config,
                &mut layouter,
                &d_node_scan,
                gr_scan_leaves,
                "gr scan root",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &grant_cells[i],
                &gr_scan_root,
                &gr_in[i],
                "grant scan root binds current GR",
            )?;

            // RR scan: 16 RR leaf preimages; bind root to rr_in[i].
            // Grant branch: parent.id must NOT appear (parent not revoked).
            // Revoke branch: revoke.grant_id must NOT appear (no duplicate revoke).
            let mut rr_scan_leaves: Vec<AssignedCell<F, F>> = Vec::with_capacity(16);
            for slot in 0..16 {
                let leaf = &scan.rr[slot];
                let (id_cell, rv_cell, ep_cell) = layouter.assign_region(
                    || format!("e{i} scan rr words {slot}"),
                    |mut region| -> Result<_, Error> {
                        let id = assign_value::<F>(
                            &mut region,
                            config.scratch,
                            0,
                            "scan_rr_id",
                            leaf.revoke.grant_id,
                            known,
                        )?;
                        let rv = assign_value::<F>(
                            &mut region,
                            config.scratch,
                            1,
                            "scan_rr_revoker",
                            leaf.revoke.revoker,
                            known,
                        )?;
                        let ep = assign_value::<F>(
                            &mut region,
                            config.scratch,
                            2,
                            "scan_rr_epoch",
                            F::from(leaf.revoke.epoch),
                            known,
                        )?;
                        Ok((id, rv, ep))
                    },
                )?;
                let h = hash_words(
                    &config,
                    layouter.namespace(|| format!("e{i}_scan_rr_hash_{slot}")),
                    "scan_rr_leaf",
                    [_d_revoke_cell.clone(), id_cell.clone(), rv_cell, ep_cell],
                )?;
                let hval = leaf.revoke.leaf();
                let lv = assign_scan_leaf(
                    &config,
                    &mut layouter,
                    !leaf.empty,
                    hval,
                    &h,
                    "scan rr leaf select",
                )?;
                let inv_parent = neq_inv(leaf.revoke.grant_id, e.parent.id).unwrap_or(F::ZERO);
                scan_id_neq(
                    &config,
                    &mut layouter,
                    !leaf.empty,
                    &grant_cells[i],
                    &id_cell,
                    &parent_words[1],
                    inv_parent,
                    "parent not revoked in RR",
                )?;
                let inv_revoke =
                    neq_inv(leaf.revoke.grant_id, e.revoke.grant_id).unwrap_or(F::ZERO);
                scan_id_neq(
                    &config,
                    &mut layouter,
                    !leaf.empty,
                    &revoke_cells[i],
                    &id_cell,
                    &rv_id,
                    inv_revoke,
                    "revoke id global unique in RR",
                )?;
                rr_scan_leaves.push(lv);
            }
            let rr_scan_root = recompute_root_from_leaves(
                &config,
                &mut layouter,
                &d_node_scan,
                rr_scan_leaves,
                "rr scan root",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &revoke_cells[i],
                &rr_scan_root,
                &rr_in[i],
                "revoke scan root binds current RR",
            )?;
            // Parent must be checked on the RR input even for a Grant event.
            // The RR root binding above is gated by revoke_cells[i] only, so for
            // a Grant event we add a second binding gated by grant_cells[i].
            gated_eq(
                &config,
                &mut layouter,
                &grant_cells[i],
                &rr_scan_root,
                &rr_in[i],
                "parent scan root binds current RR",
            )?;

            // ---- state transition: GR changes only on Grant, RR only on Revoke ----
            let gnew_val = super::b_types::recompute_root_b(e.child.leaf(true), &e.child_new_open);
            let rnew_val = super::c_types::revoke_leaf_c(&e.revoke);
            let rnew_root_val = super::b_types::recompute_root_b(rnew_val, &e.rr_new_open);
            let gr_out = state_transition(
                &config,
                &mut layouter,
                &gr_in[i],
                &child_new_opening.root,
                &grant_cells[i],
                gr_in_val[i],
                gnew_val,
                gf,
                known,
                "GR state transition",
            )?;
            let rr_out = state_transition(
                &config,
                &mut layouter,
                &rr_in[i],
                &rr_new_opening.root,
                &revoke_cells[i],
                rr_in_val[i],
                rnew_root_val,
                rf,
                known,
                "RR state transition",
            )?;
            let gr_out_val = gr_in_val[i] + gf * (gnew_val - gr_in_val[i]);
            let rr_out_val = rr_in_val[i] + rf * (rnew_root_val - rr_in_val[i]);
            gr_in.push(gr_out);
            rr_in.push(rr_out);
            gr_in_val.push(gr_out_val);
            rr_in_val.push(rr_out_val);

            // ---- event commitments bound to batch slots (gated) ----
            let c_grant = hash_words(
                &config,
                layouter.namespace(|| format!("e{i}_c_grant")),
                "c_grant",
                [
                    d_event_cell.clone(),
                    _type_grant_cell.clone(),
                    child_words[1].clone(),
                    child_words[2].clone(),
                    child_words[3].clone(),
                    child_words[4].clone(),
                    child_words[5].clone(),
                    child_words[6].clone(),
                    child_words[7].clone(),
                ],
            )?;
            let c_revoke = hash_words(
                &config,
                layouter.namespace(|| format!("e{i}_c_revoke")),
                "c_revoke",
                [
                    d_event_cell.clone(),
                    _type_revoke_cell.clone(),
                    rv_id,
                    rv_revoker,
                    rv_epoch,
                ],
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &grant_cells[i],
                &c_grant,
                &slot_cells[i],
                "grant commitment -> slot",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &revoke_cells[i],
                &c_revoke,
                &slot_cells[i],
                "revoke commitment -> slot",
            )?;
        }

        // ---- 6. state commitments from S0 and S2 roots ----
        let c_prev = hash_words(
            &config,
            layouter.namespace(|| "C_prev"),
            "C_prev",
            [
                d_state_cell.clone(),
                gr_in[0].clone(),
                rr_in[0].clone(),
                epoch_prev.clone(),
                policy_cell.clone(),
            ],
        )?;
        let c_next = hash_words(
            &config,
            layouter.namespace(|| "C_next"),
            "C_next",
            [
                d_state_cell,
                gr_in[MAX_ACTIVE_EVENTS].clone(),
                rr_in[MAX_ACTIVE_EVENTS].clone(),
                epoch_next.clone(),
                policy_cell.clone(),
            ],
        )?;

        // ---- 7. batch commitment ----
        let mut batch_words = Vec::with_capacity(MAX_EVENTS + 2);
        batch_words.push(d_batch_cell);
        batch_words.push(n_cell.clone());
        batch_words.extend(slot_cells);
        let batch_arr: [AssignedCell<F, F>; MAX_EVENTS + 2] = batch_words.try_into().unwrap();
        let d_e = hash_words(&config, layouter.namespace(|| "D_E"), "D_E", batch_arr)?;

        // ---- 8. frozen 8 instances ----
        layouter.constrain_instance(c_prev.cell(), config.instance, 0)?;
        layouter.constrain_instance(epoch_prev.cell(), config.instance, 1)?;
        layouter.constrain_instance(c_next.cell(), config.instance, 2)?;
        layouter.constrain_instance(epoch_next.cell(), config.instance, 3)?;
        layouter.constrain_instance(policy_cell.cell(), config.instance, 4)?;
        layouter.constrain_instance(version_cell.cell(), config.instance, 5)?;
        layouter.constrain_instance(d_e.cell(), config.instance, 6)?;
        layouter.constrain_instance(n_cell.cell(), config.instance, 7)?;
        let _ = (zero_cell, val);
        Ok(())
    }
}
