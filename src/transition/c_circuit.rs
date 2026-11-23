//! EXP-D3-03-C — in-circuit DirectOnly single grant revocation.
//!
//! Independent additive circuit: A (`circuit.rs`) and B (`b_circuit.rs`) stay
//! frozen.  It keeps the same 8 public instances and reuses A/B canonical-root,
//! Poseidon, batch and Merkle-opening gadgets.
//!
//! In-circuit relations:
//!   * target grant is opened from GR_prev with valid=1;
//!   * revoke.grant_id == grant.id and revoke.revoker == grant.issuer;
//!   * revoke.epoch == next_epoch == prev_epoch + 1;
//!   * RR_prev slot leaf is ZERO, RR_next slot leaf is L_REVOKE_C, same path;
//!   * GR_next == GR_prev (explicit copy, DirectOnly);
//!   * C_prev/C_next and D_E recomputed exactly as A, event_count == 1.
//!
//! Honest boundaries: category-II field mapping, canonical slot assignment,
//! Bridge/checkpoint and freshness remain external trust.  This is NOT a DENY
//! proof, Cascade proof, multi-event proof or history-completeness proof.

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
use super::c_types::TransitionWitnessC;
use super::constants::{
    batch_pad, d_batch, d_state, policy_id, transition_version, MAX_EVENTS, PALLAS_P_BE,
};

const BITS: usize = 256;
const U64: usize = 64;

#[derive(Clone, Debug)]
pub struct TransitionConfigC {
    poseidon: Pow5Config<F, 3, 2>,
    b_bit: Column<Advice>,
    pref: Column<Advice>,
    ltacc: Column<Advice>,
    acc: Column<Advice>,
    p_bit: Column<Fixed>,
    weight: Column<Fixed>,
    scratch: Column<Advice>,
    active_col: Column<Advice>,
    slot_col: Column<Advice>,
    n_col: Column<Advice>,
    instance: Column<Instance>,
    path_dir: Column<Advice>,
    path_sib: Column<Advice>,
    path_cur: Column<Advice>,
    path_left: Column<Advice>,
    path_right: Column<Advice>,
    bit_a: Column<Advice>,
    bit_b: Column<Advice>,
    acc_a: Column<Advice>,
    acc_b: Column<Advice>,
    pref_cmp: Column<Advice>,
    less_cmp: Column<Advice>,
    bit_weight_col: Column<Fixed>,
    q_bool_bit: Selector,
    q_cmp: Selector,
    q_final: Selector,
    q_bind_policy: Selector,
    q_bind_version: Selector,
    q_bool_active: Selector,
    q_slotpad: Selector,
    q_mono: Selector,
    q_count: Selector,
    q_event_count_one: Selector,
    q_path_bool: Selector,
    q_path_select: Selector,
    q_pair_bool: Selector,
    q_acc_a: Selector,
    q_acc_b: Selector,
    q_grant_valid: Selector,
    q_epoch: Selector,
    q_epoch_final: Selector,
    q_epoch_plus_one: Selector,
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

/// Assign an advice cell.  The extra type parameter avoids a rustc HRTB ICE
/// seen in B when assigning `Value` derived from `AssignedCell`.
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

/// Copy constraint between cells in different regions (Halo2 0.4 has no
/// `Layouter::constrain_equal`; `Region::constrain_equal` is the API).
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
    cfg: &TransitionConfigC,
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
    cfg: &TransitionConfigC,
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

/// Decompose `next` (a) and `prev` (b) into 64 bool bits, enforce a >= b, and
/// return final accumulator cells.  `epoch-plus-one` is a separate field gate;
/// together they rule out u64 wraparound.
fn assign_epoch_pair(
    cfg: &TransitionConfigC,
    region: &mut Region<'_, F>,
    next: u64,
    prev: u64,
    known: bool,
) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
    let mut acc_a = [F::ZERO; U64 + 1];
    let mut acc_b = [F::ZERO; U64 + 1];
    let mut pref = [F::ZERO; U64 + 1];
    let mut less = [F::ZERO; U64 + 1];
    pref[0] = F::ONE;
    for i in 0..U64 {
        let an = ((next >> (U64 - 1 - i)) & 1) as u64;
        let bp = ((prev >> (U64 - 1 - i)) & 1) as u64;
        let w = bit_weight(i, U64);
        acc_a[i + 1] = acc_a[i] + F::from(an) * w;
        acc_b[i + 1] = acc_b[i] + F::from(bp) * w;
        let diff = F::from(an) - F::from(bp);
        pref[i + 1] = pref[i] * (F::ONE - diff * diff);
        less[i + 1] = less[i] + pref[i] * (F::ONE - F::from(an)) * F::from(bp);
    }
    for i in 0..U64 {
        let an = ((next >> (U64 - 1 - i)) & 1) as u64;
        let bp = ((prev >> (U64 - 1 - i)) & 1) as u64;
        assign_value::<F>(region, cfg.bit_a, i, "bit_next", F::from(an), known)?;
        assign_value::<F>(region, cfg.bit_b, i, "bit_prev", F::from(bp), known)?;
        assign_value::<F>(region, cfg.acc_a, i, "acc_next", acc_a[i], known)?;
        assign_value::<F>(region, cfg.acc_b, i, "acc_prev", acc_b[i], known)?;
        assign_value::<F>(region, cfg.pref_cmp, i, "pref", pref[i], known)?;
        assign_value::<F>(region, cfg.less_cmp, i, "less", less[i], known)?;
        region.assign_fixed(
            || "bw",
            cfg.bit_weight_col,
            i,
            || Value::known(bit_weight(i, U64)),
        )?;
        cfg.q_pair_bool.enable(region, i)?;
        cfg.q_acc_a.enable(region, i)?;
        cfg.q_acc_b.enable(region, i)?;
        cfg.q_epoch.enable(region, i)?;
    }
    let next_acc = assign_value::<F>(region, cfg.acc_a, U64, "acc_next_final", acc_a[U64], known)?;
    let prev_acc = assign_value::<F>(region, cfg.acc_b, U64, "acc_prev_final", acc_b[U64], known)?;
    assign_value::<F>(region, cfg.bit_a, U64, "bit_next_sentinel", F::ZERO, known)?;
    assign_value::<F>(region, cfg.bit_b, U64, "bit_prev_sentinel", F::ZERO, known)?;
    assign_value::<F>(region, cfg.pref_cmp, U64, "pref_final", pref[U64], known)?;
    assign_value::<F>(region, cfg.less_cmp, U64, "less_final", less[U64], known)?;
    cfg.q_epoch_final.enable(region, U64)?;
    Ok((next_acc, prev_acc))
}

fn assign_grant_words(
    cfg: &TransitionConfigC,
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
        F::ONE, // valid=1 is enforced by q_grant_valid
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
    cfg: &TransitionConfigC,
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

#[derive(Clone, Debug)]
pub struct TransitionCircuitC {
    pub witness: Option<TransitionWitnessC>,
}

impl TransitionCircuitC {
    pub fn new(witness: TransitionWitnessC) -> Self {
        Self {
            witness: Some(witness),
        }
    }

    pub fn for_keygen() -> Self {
        Self { witness: None }
    }
}

impl Circuit<F> for TransitionCircuitC {
    type Config = TransitionConfigC;
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

        for col in [
            b_bit, pref, ltacc, acc, scratch, active_col, slot_col, n_col, path_dir, path_sib,
            path_cur, path_left, path_right, bit_a, bit_b, acc_a, acc_b, pref_cmp, less_cmp,
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
        let q_event_count_one = meta.selector();
        let q_path_bool = meta.selector();
        let q_path_select = meta.selector();
        let q_pair_bool = meta.selector();
        let q_acc_a = meta.selector();
        let q_acc_b = meta.selector();
        let q_grant_valid = meta.selector();
        let q_epoch = meta.selector();
        let q_epoch_final = meta.selector();
        let q_epoch_plus_one = meta.selector();

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
        meta.create_gate("active-boolean", |meta| {
            let q = meta.query_selector(q_bool_active);
            let a = meta.query_advice(active_col, Rotation::cur());
            Constraints::with_selector(q, vec![a.clone() * a.clone() - a])
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
        meta.create_gate("event-count-one", |meta| {
            let q = meta.query_selector(q_event_count_one);
            let n = meta.query_advice(n_col, Rotation::cur());
            Constraints::with_selector(q, vec![n - Expression::Constant(F::ONE)])
        });
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
        meta.create_gate("pair-bit-bool", |meta| {
            let q = meta.query_selector(q_pair_bool);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![a.clone() * a.clone() - a, b.clone() * b.clone() - b],
            )
        });
        meta.create_gate("pair-acc-next", |meta| {
            let q = meta.query_selector(q_acc_a);
            let an = meta.query_advice(acc_a, Rotation::next());
            let ac = meta.query_advice(acc_a, Rotation::cur());
            let bit = meta.query_advice(bit_a, Rotation::cur());
            let w = meta.query_fixed(bit_weight_col);
            Constraints::with_selector(q, vec![an - ac - bit * w])
        });
        meta.create_gate("pair-acc-prev", |meta| {
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
        // `scratch` rows prev_epoch/next_epoch are adjacent in the constants
        // region.  This field equation plus the 64-bit >= gadget gives exact +1.
        meta.create_gate("epoch-plus-one", |meta| {
            let q = meta.query_selector(q_epoch_plus_one);
            let prev = meta.query_advice(scratch, Rotation::cur());
            let next = meta.query_advice(scratch, Rotation::next());
            Constraints::with_selector(q, vec![next - prev - Expression::Constant(F::ONE)])
        });

        TransitionConfigC {
            poseidon,
            b_bit,
            pref,
            ltacc,
            acc,
            p_bit,
            weight,
            scratch,
            active_col,
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
            q_bool_bit,
            q_cmp,
            q_final,
            q_bind_policy,
            q_bind_version,
            q_bool_active,
            q_slotpad,
            q_mono,
            q_count,
            q_event_count_one,
            q_path_bool,
            q_path_select,
            q_pair_bool,
            q_acc_a,
            q_acc_b,
            q_grant_valid,
            q_epoch,
            q_epoch_final,
            q_epoch_plus_one,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let known = self.witness.is_some();
        let w = self.witness.clone().unwrap_or_else(silent_blank_c);
        let val = |x: F| {
            if known {
                Value::known(x)
            } else {
                Value::unknown()
            }
        };

        // ---- constants ----
        let (
            d_state_cell,
            d_batch_cell,
            d_grant_cell,
            d_node_cell,
            d_event_cell,
            d_revoke_cell,
            type_revoke_cell,
            zero_cell,
            policy_cell,
            version_cell,
            epoch_prev,
            epoch_next,
        ) = layouter.assign_region(
            || "constants",
            |mut region| -> Result<_, Error> {
                let sc = config.scratch;
                let dsc = assign_value::<F>(&mut region, sc, 0, "d_state", d_state(), known)?;
                let dbc = assign_value::<F>(&mut region, sc, 1, "d_batch", d_batch(), known)?;
                let dgc = assign_value::<F>(&mut region, sc, 2, "d_grant", d_grant_b(), known)?;
                let dnc = assign_value::<F>(&mut region, sc, 3, "d_node", d_node_b(), known)?;
                let dec = assign_value::<F>(&mut region, sc, 4, "d_event", d_event_b(), known)?;
                let drc = assign_value::<F>(&mut region, sc, 5, "d_revoke", d_revoke_c(), known)?;
                let tc = assign_value::<F>(
                    &mut region,
                    sc,
                    6,
                    "type_revoke",
                    F::from(TYPE_REVOKE),
                    known,
                )?;
                let zc = assign_value::<F>(&mut region, sc, 7, "zero", F::ZERO, known)?;
                let pc = assign_value::<F>(&mut region, sc, 8, "policy", policy_id(), known)?;
                config.q_bind_policy.enable(&mut region, 8)?;
                let vc = assign_value::<F>(
                    &mut region,
                    sc,
                    9,
                    "version",
                    F::from(transition_version() as u64),
                    known,
                )?;
                config.q_bind_version.enable(&mut region, 9)?;
                let ep = assign_value::<F>(
                    &mut region,
                    sc,
                    10,
                    "prev_epoch",
                    F::from(w.prev_epoch),
                    known,
                )?;
                let en = assign_value::<F>(
                    &mut region,
                    sc,
                    11,
                    "next_epoch",
                    F::from(w.next_epoch),
                    known,
                )?;
                config.q_epoch_plus_one.enable(&mut region, 10)?;
                Ok((dsc, dbc, dgc, dnc, dec, drc, tc, zc, pc, vc, ep, en))
            },
        )?;

        // ---- canonical roots and A state commitments ----
        let mut mk_root = |name: &'static str, bytes: [u8; 32]| {
            let cfg = config.clone();
            layouter.assign_region(
                || name,
                move |mut region| assign_root_encoding(&cfg, &mut region, bytes, known),
            )
        };
        let gprev = mk_root("gr_prev", w.gr_prev_be)?;
        let rprev = mk_root("rr_prev", w.rr_prev_be)?;
        let gnext = mk_root("gr_next", w.gr_next_be)?;
        let rnext = mk_root("rr_next", w.rr_next_be)?;

        let c_prev = hash_words(
            &config,
            layouter.namespace(|| "C_prev"),
            "C_prev",
            [
                d_state_cell.clone(),
                gprev.clone(),
                rprev.clone(),
                epoch_prev.clone(),
                policy_cell.clone(),
            ],
        )?;
        let c_next = hash_words(
            &config,
            layouter.namespace(|| "C_next"),
            "C_next",
            [
                d_state_cell.clone(),
                gnext.clone(),
                rnext.clone(),
                epoch_next.clone(),
                policy_cell.clone(),
            ],
        )?;

        // ---- target grant words and leaf ----
        let grant_words = layouter.assign_region(
            || "target grant words",
            |mut region| assign_grant_words(&config, &mut region, &w.grant, known),
        )?;
        let grant_leaf = hash_words(
            &config,
            layouter.namespace(|| "grant_leaf"),
            "grant_leaf",
            grant_words.clone(),
        )?;
        let _ = d_grant_cell;

        // ---- revoke event words (private witness, bound to grant/epoch) ----
        let (revoke_id, revoke_revoker, revoke_epoch) = layouter.assign_region(
            || "revoke event words",
            |mut region| -> Result<_, Error> {
                let id = assign_value::<F>(
                    &mut region,
                    config.scratch,
                    0,
                    "revoke_grant_id",
                    w.revoke.grant_id,
                    known,
                )?;
                let rev = assign_value::<F>(
                    &mut region,
                    config.scratch,
                    1,
                    "revoke_revoker",
                    w.revoke.revoker,
                    known,
                )?;
                let ep = assign_value::<F>(
                    &mut region,
                    config.scratch,
                    2,
                    "revoke_epoch",
                    F::from(w.revoke.epoch),
                    known,
                )?;
                Ok((id, rev, ep))
            },
        )?;
        copy_equal(&mut layouter, &grant_words[1], &revoke_id)?;
        copy_equal(&mut layouter, &grant_words[2], &revoke_revoker)?;
        copy_equal(&mut layouter, &revoke_epoch, &epoch_next)?;

        // ---- 64-bit epoch >= and field +1 ----
        let (next_acc, prev_acc) = layouter.assign_region(
            || "state epoch",
            |mut region| assign_epoch_pair(&config, &mut region, w.next_epoch, w.prev_epoch, known),
        )?;
        copy_equal(&mut layouter, &next_acc, &epoch_next)?;
        copy_equal(&mut layouter, &prev_acc, &epoch_prev)?;

        // ---- revoke leaf, RR old/new openings, GR unchanged ----
        let revoke_leaf = hash_words(
            &config,
            layouter.namespace(|| "revoke_leaf"),
            "revoke_leaf",
            [
                d_revoke_cell,
                revoke_id.clone(),
                revoke_revoker.clone(),
                revoke_epoch.clone(),
            ],
        )?;

        let grant_opening = assign_opening_path(
            &config,
            layouter.namespace(|| "grant opening"),
            d_node_cell.clone(),
            grant_leaf,
            &w.grant_open,
            "grant",
        )?;
        copy_equal(&mut layouter, &grant_opening.root, &gprev)?;

        let rr_old_opening = assign_opening_path(
            &config,
            layouter.namespace(|| "rr old opening"),
            d_node_cell.clone(),
            zero_cell,
            &w.rr_old_open,
            "rr_old",
        )?;
        copy_equal(&mut layouter, &rr_old_opening.root, &rprev)?;

        let rr_new_opening = assign_opening_path(
            &config,
            layouter.namespace(|| "rr new opening"),
            d_node_cell,
            revoke_leaf,
            &w.rr_new_open,
            "rr_new",
        )?;
        for level in 0..DEPTH {
            copy_equal(
                &mut layouter,
                &rr_new_opening.path[level].0,
                &rr_old_opening.path[level].0,
            )?;
            copy_equal(
                &mut layouter,
                &rr_new_opening.path[level].1,
                &rr_old_opening.path[level].1,
            )?;
        }
        copy_equal(&mut layouter, &rr_new_opening.root, &rnext)?;

        // DirectOnly: GR root must be the very same cell value, not merely
        // two equal-looking public roots supplied by the prover.
        copy_equal(&mut layouter, &gnext, &gprev)?;

        // ---- revoke event commitment -> batch slot 0 ----
        let c_revoke = hash_words(
            &config,
            layouter.namespace(|| "c_revoke"),
            "c_revoke",
            [
                d_event_cell,
                type_revoke_cell,
                revoke_id,
                revoke_revoker,
                revoke_epoch,
            ],
        )?;

        let mut active = [0u64; MAX_EVENTS];
        for i in 0..MAX_EVENTS {
            active[i] = if (i as u32) < w.event_count { 1 } else { 0 };
        }
        let (n_cell, slots) = layouter.assign_region(
            || "batch slots",
            |mut region| -> Result<_, Error> {
                let n = region.assign_advice(
                    || "n",
                    config.n_col,
                    0,
                    || val(F::from(w.event_count as u64)),
                )?;
                let mut slot_cells = Vec::with_capacity(MAX_EVENTS);
                for i in 0..MAX_EVENTS {
                    let s = region.assign_advice(
                        || "slot",
                        config.slot_col,
                        i,
                        || val(w.event_commitments[i]),
                    )?;
                    let a = region.assign_advice(
                        || "active",
                        config.active_col,
                        i,
                        || val(F::from(active[i])),
                    )?;
                    config.q_slotpad.enable(&mut region, i)?;
                    config.q_bool_active.enable(&mut region, i)?;
                    if i + 1 < MAX_EVENTS {
                        config.q_mono.enable(&mut region, i)?;
                    }
                    let _ = a;
                    slot_cells.push(s);
                }
                config.q_count.enable(&mut region, 0)?;
                config.q_event_count_one.enable(&mut region, 0)?;
                Ok((n, slot_cells))
            },
        )?;
        copy_equal(&mut layouter, &c_revoke, &slots[0])?;

        let mut batch_words = Vec::with_capacity(MAX_EVENTS + 2);
        batch_words.push(d_batch_cell);
        batch_words.push(n_cell.clone());
        batch_words.extend(slots);
        let batch_arr: [AssignedCell<F, F>; MAX_EVENTS + 2] = batch_words.try_into().unwrap();
        let d_e = hash_words(&config, layouter.namespace(|| "D_E"), "D_E", batch_arr)?;

        // ---- frozen 8 instances ----
        layouter.constrain_instance(c_prev.cell(), config.instance, 0)?;
        layouter.constrain_instance(epoch_prev.cell(), config.instance, 1)?;
        layouter.constrain_instance(c_next.cell(), config.instance, 2)?;
        layouter.constrain_instance(epoch_next.cell(), config.instance, 3)?;
        layouter.constrain_instance(policy_cell.cell(), config.instance, 4)?;
        layouter.constrain_instance(version_cell.cell(), config.instance, 5)?;
        layouter.constrain_instance(d_e.cell(), config.instance, 6)?;
        layouter.constrain_instance(n_cell.cell(), config.instance, 7)?;
        Ok(())
    }
}

fn silent_blank_c() -> TransitionWitnessC {
    let blank_open = OpeningB {
        sibling: [F::ZERO; DEPTH],
        dir: [0u8; DEPTH],
        left: [F::ZERO; DEPTH],
        right: [F::ZERO; DEPTH],
        cur: [F::ZERO; DEPTH],
    };
    TransitionWitnessC {
        gr_prev_be: [0u8; 32],
        rr_prev_be: [0u8; 32],
        gr_next_be: [0u8; 32],
        rr_next_be: [0u8; 32],
        prev_epoch: 0,
        next_epoch: 1,
        event_commitments: [batch_pad(); MAX_EVENTS],
        event_count: 1,
        grant: GrantFieldsB {
            id: F::ZERO,
            issuer: F::ZERO,
            subject: F::ZERO,
            resource_prefix: [0u8; 8],
            scope: 0,
            parent_key: F::ZERO,
            epoch: 0,
        },
        revoke: super::c_types::RevokeFieldsC {
            grant_id: F::ZERO,
            revoker: F::ZERO,
            epoch: 1,
        },
        grant_slot: 0,
        revoke_slot: 1,
        grant_open: blank_open.clone(),
        rr_old_open: blank_open.clone(),
        rr_new_open: blank_open,
    }
}
