//! EXP-D3-06-C — two-event sequential IR-bound transition circuit.
//!
//! Independent additive circuit.  A/B/C/D/E/R1/R2/R3/S0/D3-06-B stay frozen.
//! Keeps the frozen 8 public instances; `C_prev/C_next` use `D3-STATE-v2` over
//! 6 words (GR, RR, IR, epoch, policy).
//!
//! Core relation (all in-circuit; host pre-checks are NOT trusted):
//!   * both event slots are active: `is_grant_i + is_revoke_i = 1` and
//!     `event_count = 2`; no inactive event or `pre_ok` no-op bypass;
//!   * the output root cells of Event 0 are used directly as the input root
//!     cells of Event 1 for GR, RR and IR — Event 1 cannot supply a fresh
//!     intermediate root witness;
//!   * for every opened IR ID, canonical 256-bit decomposition binds
//!     `slot = low_4(id)` and each Merkle direction bit;
//!   * IR leaves are recomputed in-circuit; state words come only from
//!     constrained constants through the B state-transition mux;
//!   * old/new openings share sibling and direction cells, so only the target
//!     leaf changes within an event;
//!   * Event 0/1 commitments are bound to batch slots 0/1; slot 2 is padding.
//!
//! Honest boundaries: S0 external anchoring, SHA-256 key mapping, revoker
//! authority, 256-bit ID mapping, freshness, DENY, RG and recursion are NOT
//! proved here.

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

use super::b_constants::{d_event_b, d_grant_b, d_node_b, DEPTH};
use super::b_types::{GrantFieldsB, OpeningB};
use super::c_constants::d_revoke_c;
use super::constants::{batch_pad, d_batch, policy_id, transition_version, PALLAS_P_BE};
use super::d3_06_c_constants::{
    d_index, d_index_node, d_state_v2, MAX_EVENTS, TYPE_GRANT, TYPE_REVOKE,
};
use super::d3_06_c_types::{blank_c, TransitionWitnessC};

const BITS: usize = 256;
const U64: usize = 64;

#[derive(Clone, Debug)]
pub struct TransitionConfigC {
    poseidon: Pow5Config<F, 3, 2>,
    // canonical field decomposition (shared by root decoding and IR id/slot)
    b_bit: Column<Advice>,
    pref: Column<Advice>,
    ltacc: Column<Advice>,
    acc: Column<Advice>,
    p_bit: Column<Fixed>,
    weight: Column<Fixed>,
    scratch: Column<Advice>,
    // control
    flag_grant: Column<Advice>,
    flag_revoke: Column<Advice>,
    slot_col: Column<Advice>,
    n_col: Column<Advice>,
    instance: Column<Instance>,
    // Merkle path (GR/RR/IR)
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
    // IR slot low-bit gate: slot = sum_{b=0..3} 2^b * bit_b
    ir_slot_bit: Column<Advice>,
    ir_slot_w: Column<Fixed>,
    // selectors
    q_bool_bit: Selector,
    q_canon: Selector,
    q_final: Selector,
    q_bool_active: Selector,
    q_bool_flag: Selector,
    q_type_split: Selector,
    q_slotpad: Selector,
    q_count: Selector,
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
    q_ir_slot_bool: Selector,
    q_ir_slot: Selector,
    q_const_two: Selector,
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

fn assign_value(
    region: &mut Region<'_, F>,
    column: Column<Advice>,
    row: usize,
    label: &'static str,
    value: F,
    known: bool,
) -> Result<AssignedCell<F, F>, Error> {
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

/// Canonical field root decoding (identical to E-R1 `assign_root_encoding`).
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
        assign_value(region, cfg.b_bit, t, "root_bit", b, known)?;
        cfg.q_bool_bit.enable(region, t)?;
        region.assign_fixed(|| "p_bit", cfg.p_bit, t, || Value::known(F::from(pbits[t])))?;
        region.assign_fixed(|| "weight", cfg.weight, t, || Value::known(weights[t]))?;
        cfg.q_canon.enable(region, t)?;
    }
    let mut root_cell: Option<AssignedCell<F, F>> = None;
    for (col, values, label) in [
        (cfg.pref, &pref, "pref"),
        (cfg.ltacc, &less, "ltacc"),
        (cfg.acc, &acc, "acc"),
    ] {
        for t in 0..=BITS {
            let cell = assign_value(region, col, t, label, values[t], known)?;
            if col == cfg.acc && t == BITS {
                root_cell = Some(cell);
            }
        }
    }
    cfg.q_final.enable(region, BITS)?;
    assign_value(region, cfg.b_bit, BITS, "bit_sentinel", F::ZERO, known)?;
    root_cell.ok_or(Error::Synthesis)
}

/// Result of a canonical ID decomposition: the field cell (reconstructed id)
/// and the four low-bit cells (bit0=LSB..bit3), each copy-constrained to the
/// canonical decomposition; plus the bound `slot` cell.
pub struct CanonId {
    pub field_cell: AssignedCell<F, F>,
    pub low_bits: [AssignedCell<F, F>; 4],
    pub slot_cell: AssignedCell<F, F>,
}

/// Decompose a full field ID canonically and bind `slot = low_4(id)` in-circuit.
/// The low nibble of `id` sits at canonical bit positions BITS-4..BITS
/// (big-endian bits: index BITS-4 is 2^3, index BITS-1 is 2^0).
#[allow(clippy::too_many_arguments)]
fn assign_canon_id<L: Layouter<F>>(
    cfg: &TransitionConfigC,
    mut layouter: L,
    value: F,
    known: bool,
    note: &'static str,
) -> Result<CanonId, Error> {
    let bytes = super::constants::encode_field_i(&value);
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
    let mut field_cell = None;
    // Save each assigned b_bit cell so the low nibble can be referenced by
    // copy-constraint instead of re-assigning the same cell (which Halo2
    // rejects with a "cell already assigned" panic).
    let mut bit_cells: Vec<Option<AssignedCell<F, F>>> = (0..BITS).map(|_| None).collect();
    layouter.assign_region(
        || note,
        |mut region| -> Result<_, Error> {
            for t in 0..BITS {
                let b = F::from(bits[t]);
                let cell = assign_value(&mut region, cfg.b_bit, t, "id_bit", b, known)?;
                bit_cells[t] = Some(cell);
                cfg.q_bool_bit.enable(&mut region, t)?;
                region.assign_fixed(
                    || "p_bit",
                    cfg.p_bit,
                    t,
                    || Value::known(F::from(pbits[t])),
                )?;
                region.assign_fixed(|| "weight", cfg.weight, t, || Value::known(weights[t]))?;
                cfg.q_canon.enable(&mut region, t)?;
            }
            for (col, values, label) in [
                (cfg.pref, &pref, "pref"),
                (cfg.ltacc, &less, "ltacc"),
                (cfg.acc, &acc, "acc"),
            ] {
                for t in 0..=BITS {
                    let cell = assign_value(&mut region, col, t, label, values[t], known)?;
                    if col == cfg.acc && t == BITS {
                        field_cell = Some(cell);
                    }
                }
            }
            cfg.q_final.enable(&mut region, BITS)?;
            assign_value(&mut region, cfg.b_bit, BITS, "sentinel", F::ZERO, known)?;
            Ok(())
        },
    )?;
    // The low nibble lives at canonical indices BITS-4..BITS.  Index t carries
    // weight 2^(BITS-1-t), so nibble bit position bpos = BITS-1-t (bpos 0 = LSB).
    let low_bits: [AssignedCell<F, F>; 4] = std::array::from_fn(|bpos| {
        bit_cells[BITS - 1 - bpos]
            .clone()
            .expect("canonical bit cell assigned")
    });
    // Bind slot = sum_{b=0..3} 2^b * low_bits[b] in its own region.
    // Gate `b-ir-slot-bind` queries `acc` at cur AND next for rows 0..3, so
    // every accumulator row 0..=4 must be assigned here (otherwise MockProver
    // sees unassigned advice and the chain cannot be satisfied).
    let slot_cell = layouter.assign_region(
        || "ir slot bind",
        |mut region| -> Result<_, Error> {
            let mut acc = F::ZERO;
            for b in 0..4 {
                // row b holds the running accumulator BEFORE adding bit b
                assign_value(&mut region, cfg.acc, b, "slot_acc", acc, known)?;
                let bit_v = F::from(bits[BITS - 1 - b]);
                let bit_cell =
                    assign_value(&mut region, cfg.ir_slot_bit, b, "slot_bit", bit_v, known)?;
                region.constrain_equal(low_bits[b].cell(), bit_cell.cell())?;
                cfg.q_ir_slot_bool.enable(&mut region, b)?;
                let w = F::from(1u64 << b);
                region.assign_fixed(|| "slot_w", cfg.ir_slot_w, b, || Value::known(w))?;
                cfg.q_ir_slot.enable(&mut region, b)?;
                acc = acc + bit_v * w;
            }
            // row 4 = final accumulated slot (sum of 2^b * bit_b).
            let sc = assign_value(&mut region, cfg.acc, 4, "slot", acc, known)?;
            Ok(sc)
        },
    )?;
    Ok(CanonId {
        field_cell: field_cell.ok_or(Error::Synthesis)?,
        low_bits,
        slot_cell,
    })
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
        F::ONE,
    ];
    let mut cells = Vec::with_capacity(9);
    for (i, word) in words.iter().enumerate() {
        cells.push(assign_value(
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

#[derive(Clone, Copy)]
enum PairMode {
    Scope,
    Prefix,
    Epoch,
}

fn assign_pair_u64(
    cfg: &TransitionConfigC,
    region: &mut Region<'_, F>,
    a: u64,
    b: u64,
    known: bool,
    mode: PairMode,
) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
    let mut acc_a = [F::ZERO; U64 + 1];
    let mut acc_b = [F::ZERO; U64 + 1];
    let mut bit_a = [0u64; U64];
    let mut bit_b = [0u64; U64];
    for i in 0..U64 {
        bit_a[i] = (a >> (U64 - 1 - i)) & 1;
        bit_b[i] = (b >> (U64 - 1 - i)) & 1;
        let w = F::from(2u64).pow([(U64 - 1 - i) as u64]);
        acc_a[i + 1] = acc_a[i] + F::from(bit_a[i]) * w;
        acc_b[i + 1] = acc_b[i] + F::from(bit_b[i]) * w;
    }
    for i in 0..U64 {
        assign_value(region, cfg.bit_a, i, "bit_a", F::from(bit_a[i]), known)?;
        assign_value(region, cfg.bit_b, i, "bit_b", F::from(bit_b[i]), known)?;
        cfg.q_pair_bool.enable(region, i)?;
        region.assign_fixed(
            || "bw",
            cfg.bit_weight_col,
            i,
            || Value::known(F::from(2u64).pow([(U64 - 1 - i) as u64])),
        )?;
        cfg.q_acc_a.enable(region, i)?;
        cfg.q_acc_b.enable(region, i)?;
        match mode {
            PairMode::Scope => cfg.q_scope.enable(region, i)?,
            PairMode::Prefix => cfg.q_prefix.enable(region, i)?,
            PairMode::Epoch => {}
        }
    }
    for (col, vals, label) in [(cfg.acc_a, &acc_a, "acc_a"), (cfg.acc_b, &acc_b, "acc_b")] {
        for i in 0..=U64 {
            assign_value(region, col, i, label, vals[i], known)?;
        }
    }
    let a_cell = assign_value(region, cfg.acc_a, U64, "a_final", acc_a[U64], known)?;
    let b_cell = assign_value(region, cfg.acc_b, U64, "b_final", acc_b[U64], known)?;
    Ok((a_cell, b_cell))
}

struct OpeningResult {
    root: AssignedCell<F, F>,
    path: Vec<(AssignedCell<F, F>, AssignedCell<F, F>)>,
}

/// Assign a depth-4 Merkle path (GR/RR use D3-NODE-v1 cell; IR uses D3-INDEX-NODE-v1).
/// Returns sibling/dir cells for same-path copy constraints.
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
            || format!("{note}_sel_{level}"),
            |mut region| -> Result<_, Error> {
                let cur_cell = assign_value(&mut region, cfg.path_cur, 0, "cur", cur_v, true)?;
                let dir_cell = assign_value(&mut region, cfg.path_dir, 0, "dir", dir_v, true)?;
                let sib_cell = assign_value(&mut region, cfg.path_sib, 0, "sib", sib_v, true)?;
                let left = assign_value(&mut region, cfg.path_left, 0, "left", left_v, true)?;
                let right = assign_value(&mut region, cfg.path_right, 0, "right", right_v, true)?;
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

/// IR opening using `IrOpening` (identical shape, IR node domain cell).
fn assign_ir_opening<L: Layouter<F>>(
    cfg: &TransitionConfigC,
    mut layouter: L,
    d_node_cell: AssignedCell<F, F>,
    leaf: AssignedCell<F, F>,
    open: &super::d3_06_b_ir::IrOpening,
    note: &'static str,
) -> Result<OpeningResult, Error> {
    let mut cur = leaf;
    let mut path = Vec::with_capacity(DEPTH);
    for level in 0..DEPTH {
        let dir_v = F::from(open.dir[level] as u64);
        let (cur_cell, left, right, dir_cell, sib_cell) = layouter.assign_region(
            || format!("{note}_sel_{level}"),
            |mut region| -> Result<_, Error> {
                let cur_cell =
                    assign_value(&mut region, cfg.path_cur, 0, "cur", open.cur[level], true)?;
                let dir_cell = assign_value(&mut region, cfg.path_dir, 0, "dir", dir_v, true)?;
                let sib_cell = assign_value(
                    &mut region,
                    cfg.path_sib,
                    0,
                    "sib",
                    open.sibling[level],
                    true,
                )?;
                let left = assign_value(
                    &mut region,
                    cfg.path_left,
                    0,
                    "left",
                    open.left[level],
                    true,
                )?;
                let right = assign_value(
                    &mut region,
                    cfg.path_right,
                    0,
                    "right",
                    open.right[level],
                    true,
                )?;
                cfg.q_path_bool.enable(&mut region, 0)?;
                cfg.q_path_select.enable(&mut region, 0)?;
                Ok((cur_cell, left, right, dir_cell, sib_cell))
            },
        )?;
        copy_equal(&mut layouter, &cur_cell, &cur)?;
        cur = hash_words(
            cfg,
            layouter.namespace(|| format!("{note}_node_{level}")),
            "ir_node",
            [d_node_cell.clone(), left, right],
        )?;
        path.push((dir_cell, sib_cell));
    }
    Ok(OpeningResult { root: cur, path })
}

fn gated_eq<L: Layouter<F>>(
    cfg: &TransitionConfigC,
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

fn state_transition<L: Layouter<F>>(
    cfg: &TransitionConfigC,
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
            let o = assign_value(&mut region, cfg.st_out, 0, "out", out_val, known)?;
            region.constrain_equal(state_in.cell(), i.cell())?;
            region.constrain_equal(state_new.cell(), n.cell())?;
            region.constrain_equal(flag.cell(), f.cell())?;
            cfg.q_state.enable(&mut region, 0)?;
            Ok(o)
        },
    )
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
        let ir_slot_bit = meta.advice_column();
        let ir_slot_w = meta.fixed_column();

        for col in [
            b_bit,
            pref,
            ltacc,
            acc,
            scratch,
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
            ir_slot_bit,
        ] {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance);

        let q_bool_bit = meta.selector();
        let q_canon = meta.selector();
        let q_final = meta.selector();
        let q_bool_active = meta.selector();
        let q_bool_flag = meta.selector();
        let q_type_split = meta.selector();
        let q_slotpad = meta.selector();
        let q_count = meta.selector();
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
        let q_ir_slot_bool = meta.selector();
        let q_ir_slot = meta.selector();
        let q_const_two = meta.selector();

        // canonical decomposition (same as E-R1)
        meta.create_gate("c-root-bit-boolean", |meta| {
            let q = meta.query_selector(q_bool_bit);
            let b = meta.query_advice(b_bit, Rotation::cur());
            Constraints::with_selector(q, vec![b.clone() * b.clone() - b])
        });
        meta.create_gate("c-canonical-transition", |meta| {
            let q = meta.query_selector(q_canon);
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
        meta.create_gate("c-canonical-final", |meta| {
            let q = meta.query_selector(q_final);
            let less = meta.query_advice(ltacc, Rotation::cur());
            Constraints::with_selector(q, vec![less - Expression::Constant(F::ONE)])
        });

        // control
        meta.create_gate("c-bool-flag", |meta| {
            let q = meta.query_selector(q_bool_flag);
            let g = meta.query_advice(flag_grant, Rotation::cur());
            let r = meta.query_advice(flag_revoke, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![g.clone() * g.clone() - g, r.clone() * r.clone() - r],
            )
        });
        meta.create_gate("c-type-split", |meta| {
            let q = meta.query_selector(q_type_split);
            let g = meta.query_advice(flag_grant, Rotation::cur());
            let r = meta.query_advice(flag_revoke, Rotation::cur());
            Constraints::with_selector(q, vec![g + r - Expression::Constant(F::ONE)])
        });
        meta.create_gate("c-slot-pad", |meta| {
            let q = meta.query_selector(q_slotpad);
            let slot = meta.query_advice(slot_col, Rotation::cur());
            Constraints::with_selector(q, vec![slot - Expression::Constant(batch_pad())])
        });
        meta.create_gate("c-count", |meta| {
            let q = meta.query_selector(q_count);
            let n = meta.query_advice(n_col, Rotation::cur());
            Constraints::with_selector(q, vec![n - Expression::Constant(F::from(2u64))])
        });

        // path
        meta.create_gate("c-path-dir-bool", |meta| {
            let q = meta.query_selector(q_path_bool);
            let d = meta.query_advice(path_dir, Rotation::cur());
            Constraints::with_selector(q, vec![d.clone() * d.clone() - d])
        });
        meta.create_gate("c-path-select", |meta| {
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
                    right - (d.clone() * cur + (one - d.clone()) * sib),
                ],
            )
        });

        // 64-bit pair
        meta.create_gate("c-pair-bit-bool", |meta| {
            let q = meta.query_selector(q_pair_bool);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(
                q,
                vec![a.clone() * a.clone() - a, b.clone() * b.clone() - b],
            )
        });
        meta.create_gate("c-pair-acc-a", |meta| {
            let q = meta.query_selector(q_acc_a);
            let an = meta.query_advice(acc_a, Rotation::next());
            let ac = meta.query_advice(acc_a, Rotation::cur());
            let bit = meta.query_advice(bit_a, Rotation::cur());
            let w = meta.query_fixed(bit_weight_col);
            Constraints::with_selector(q, vec![an - ac - bit * w])
        });
        meta.create_gate("c-pair-acc-b", |meta| {
            let q = meta.query_selector(q_acc_b);
            let an = meta.query_advice(acc_b, Rotation::next());
            let ac = meta.query_advice(acc_b, Rotation::cur());
            let bit = meta.query_advice(bit_b, Rotation::cur());
            let w = meta.query_fixed(bit_weight_col);
            Constraints::with_selector(q, vec![an - ac - bit * w])
        });
        meta.create_gate("c-grant-valid-one", |meta| {
            let q = meta.query_selector(q_grant_valid);
            let a = meta.query_advice(scratch, Rotation::cur());
            Constraints::with_selector(q, vec![a - Expression::Constant(F::ONE)])
        });
        // Constrain the REVOKED state code cell == 2 (host cannot choose it).
        meta.create_gate("c-const-two", |meta| {
            let q = meta.query_selector(q_const_two);
            let a = meta.query_advice(scratch, Rotation::cur());
            Constraints::with_selector(q, vec![a - Expression::Constant(F::from(2u64))])
        });
        meta.create_gate("c-scope-subset", |meta| {
            let q = meta.query_selector(q_scope);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(q, vec![a * (Expression::Constant(F::ONE) - b)])
        });
        meta.create_gate("c-prefix-eq", |meta| {
            let q = meta.query_selector(q_prefix);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            Constraints::with_selector(q, vec![a - b])
        });
        meta.create_gate("c-epoch-final", |meta| {
            let q = meta.query_selector(q_epoch_final);
            let less = meta.query_advice(less_cmp, Rotation::cur());
            Constraints::with_selector(q, vec![less])
        });
        meta.create_gate("c-epoch-plus-one", |meta| {
            let q = meta.query_selector(q_epoch_plus_one);
            let prev = meta.query_advice(scratch, Rotation::cur());
            let next = meta.query_advice(scratch, Rotation::next());
            Constraints::with_selector(q, vec![next - prev - Expression::Constant(F::ONE)])
        });

        // gated equality + state transition
        meta.create_gate("c-gated-eq", |meta| {
            let q = meta.query_selector(q_gate_eq);
            let f = meta.query_advice(gate_flag, Rotation::cur());
            let l = meta.query_advice(gate_l, Rotation::cur());
            let r = meta.query_advice(gate_r, Rotation::cur());
            Constraints::with_selector(q, vec![f * (l - r)])
        });
        meta.create_gate("c-state-transition", |meta| {
            let q = meta.query_selector(q_state);
            let i = meta.query_advice(st_in, Rotation::cur());
            let n = meta.query_advice(st_new, Rotation::cur());
            let f = meta.query_advice(st_flag, Rotation::cur());
            let o = meta.query_advice(st_out, Rotation::cur());
            Constraints::with_selector(q, vec![o - (i.clone() + f * (n - i))])
        });

        // IR slot low-bit boolean + binding: slot bit b is boolean, and
        // acc(next) = acc(cur) + 2^b * bit_b; row 4 acc = sum = low_4(id).
        meta.create_gate("c-ir-slot-bit-bool", |meta| {
            let q = meta.query_selector(q_ir_slot_bool);
            let b = meta.query_advice(ir_slot_bit, Rotation::cur());
            Constraints::with_selector(q, vec![b.clone() * b.clone() - b])
        });
        meta.create_gate("c-ir-slot-bind", |meta| {
            let q = meta.query_selector(q_ir_slot);
            let an = meta.query_advice(acc, Rotation::next());
            let ac = meta.query_advice(acc, Rotation::cur());
            let bit = meta.query_advice(ir_slot_bit, Rotation::cur());
            let w = meta.query_fixed(ir_slot_w);
            Constraints::with_selector(q, vec![an - ac - bit * w])
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
            ir_slot_bit,
            ir_slot_w,
            q_bool_bit,
            q_canon,
            q_final,
            q_bool_active,
            q_bool_flag,
            q_type_split,
            q_slotpad,
            q_count,
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
            q_ir_slot_bool,
            q_ir_slot,
            q_const_two,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let known = self.witness.is_some();
        let w = self.witness.clone().unwrap_or_else(blank_c);

        // ---- constants (identical encoding surface to D3-06-B) ----
        let (
            d_state_cell,
            d_batch_cell,
            d_node_cell,
            d_event_cell,
            d_grant_cell,
            d_revoke_cell,
            d_index_cell,
            d_index_node_cell,
            type_grant_cell,
            type_revoke_cell,
            zero_cell,
            one_cell,
            revoked_code,
            policy_cell,
            version_cell,
            epoch_prev,
            epoch_next,
        ) = layouter.assign_region(
            || "constants",
            |mut region| -> Result<_, Error> {
                let sc = config.scratch;
                let ds = assign_value(&mut region, sc, 0, "d_state_v2", d_state_v2(), known)?;
                let db = assign_value(&mut region, sc, 1, "d_batch", d_batch(), known)?;
                let dn = assign_value(&mut region, sc, 2, "d_node", d_node_b(), known)?;
                let de = assign_value(&mut region, sc, 3, "d_event", d_event_b(), known)?;
                let dg = assign_value(&mut region, sc, 4, "d_grant", d_grant_b(), known)?;
                let dr = assign_value(&mut region, sc, 5, "d_revoke", d_revoke_c(), known)?;
                let di = assign_value(&mut region, sc, 6, "d_index", d_index(), known)?;
                let din = assign_value(&mut region, sc, 7, "d_index_node", d_index_node(), known)?;
                let tg = assign_value(
                    &mut region,
                    sc,
                    8,
                    "type_grant",
                    F::from(TYPE_GRANT as u64),
                    known,
                )?;
                let tr = assign_value(
                    &mut region,
                    sc,
                    9,
                    "type_revoke",
                    F::from(TYPE_REVOKE as u64),
                    known,
                )?;
                let zc = assign_value(&mut region, sc, 10, "zero", F::ZERO, known)?;
                let oc = assign_value(&mut region, sc, 15, "one", F::ONE, known)?;
                config.q_grant_valid.enable(&mut region, 15)?;
                let rc = assign_value(&mut region, sc, 16, "revoked_code", F::from(2u64), known)?;
                config.q_const_two.enable(&mut region, 16)?;
                let pc = assign_value(&mut region, sc, 11, "policy", policy_id(), known)?;
                let vc = assign_value(
                    &mut region,
                    sc,
                    12,
                    "version",
                    F::from(transition_version() as u64),
                    known,
                )?;
                let ep = assign_value(
                    &mut region,
                    sc,
                    13,
                    "prev_epoch",
                    F::from(w.prev_epoch),
                    known,
                )?;
                let en = assign_value(
                    &mut region,
                    sc,
                    14,
                    "next_epoch",
                    F::from(w.next_epoch),
                    known,
                )?;
                config.q_epoch_plus_one.enable(&mut region, 13)?;
                Ok((
                    ds, db, dn, de, dg, dr, di, din, tg, tr, zc, oc, rc, pc, vc, ep, en,
                ))
            },
        )?;

        // ---- S0 roots ----
        let gprev = layouter.assign_region(
            || "gr_prev",
            |mut region| assign_root_encoding(&config, &mut region, w.gr_prev_be, known),
        )?;
        let rprev = layouter.assign_region(
            || "rr_prev",
            |mut region| assign_root_encoding(&config, &mut region, w.rr_prev_be, known),
        )?;
        let irprev = layouter.assign_region(
            || "ir_prev",
            |mut region| assign_value(&mut region, config.scratch, 0, "ir_prev", w.ir_prev, known),
        )?;

        // ---- two active events + three batch slots ----
        let (grant_cells, revoke_cells, slot_cells, n_cell) = layouter.assign_region(
            || "control and batch",
            |mut region| -> Result<_, Error> {
                let mut grants = Vec::with_capacity(MAX_EVENTS);
                let mut revokes = Vec::with_capacity(MAX_EVENTS);
                let mut slots = Vec::with_capacity(3);
                for i in 0..MAX_EVENTS {
                    let e = &w.events[i];
                    let g = assign_value(
                        &mut region,
                        config.flag_grant,
                        i,
                        "is_grant",
                        F::from(e.is_grant as u64),
                        known,
                    )?;
                    let r = assign_value(
                        &mut region,
                        config.flag_revoke,
                        i,
                        "is_revoke",
                        F::from(e.is_revoke as u64),
                        known,
                    )?;
                    config.q_bool_flag.enable(&mut region, i)?;
                    config.q_type_split.enable(&mut region, i)?;
                    let s = assign_value(
                        &mut region,
                        config.slot_col,
                        i,
                        "event_commitment",
                        w.event_commitments[i],
                        known,
                    )?;
                    grants.push(g);
                    revokes.push(r);
                    slots.push(s);
                }
                let pad = assign_value(
                    &mut region,
                    config.slot_col,
                    MAX_EVENTS,
                    "slot_pad",
                    w.event_commitments[2],
                    known,
                )?;
                config.q_slotpad.enable(&mut region, MAX_EVENTS)?;
                slots.push(pad);
                let n = assign_value(
                    &mut region,
                    config.n_col,
                    0,
                    "n",
                    F::from(w.event_count as u64),
                    known,
                )?;
                config.q_count.enable(&mut region, 0)?;
                Ok((grants, revokes, slots, n))
            },
        )?;

        // ---- root chains: Event 0 output cells become Event 1 input cells ----
        let mut gr_in = vec![gprev];
        let mut rr_in = vec![rprev];
        let mut ir_in = vec![irprev];
        let mut gr_in_val = vec![decode_root(&w.gr_prev_be)];
        let mut rr_in_val = vec![decode_root(&w.rr_prev_be)];
        let mut ir_in_val = vec![w.ir_prev];

        for i in 0..MAX_EVENTS {
            let e = &w.events[i];
            let gf = grant_cells[i].clone();
            let rf = revoke_cells[i].clone();
            let gf_val = F::from(e.is_grant as u64);
            let rf_val = F::from(e.is_revoke as u64);

            // ---- canonical IR ids ----
            let read_canon = assign_canon_id(
                &config,
                layouter.namespace(|| format!("event{i} ir read id")),
                e.ir_read_id,
                known,
                "ir_read_id",
            )?;
            let write_canon = assign_canon_id(
                &config,
                layouter.namespace(|| format!("event{i} ir write id")),
                e.ir_write_id,
                known,
                "ir_write_id",
            )?;

            // ---- Grant branch (both branches assigned unconditionally) ----
            let parent_words = layouter.assign_region(
                || format!("event{i} parent grant words"),
                |mut r| assign_grant_words(&config, &mut r, &e.parent, known),
            )?;
            let child_words = layouter.assign_region(
                || format!("event{i} child grant words"),
                |mut r| assign_grant_words(&config, &mut r, &e.child, known),
            )?;
            let parent_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} parent leaf")),
                "parent_leaf",
                parent_words.clone(),
            )?;
            let child_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} child leaf")),
                "child_leaf",
                child_words.clone(),
            )?;
            copy_equal(&mut layouter, &child_words[6], &parent_words[1])?;
            copy_equal(&mut layouter, &child_words[2], &parent_words[3])?;
            copy_equal(&mut layouter, &child_words[7], &epoch_next)?;
            let (sc, sp) = layouter.assign_region(
                || format!("event{i} scope"),
                |mut r| {
                    assign_pair_u64(
                        &config,
                        &mut r,
                        e.child.scope,
                        e.parent.scope,
                        known,
                        PairMode::Scope,
                    )
                },
            )?;
            copy_equal(&mut layouter, &sc, &child_words[5])?;
            copy_equal(&mut layouter, &sp, &parent_words[5])?;
            let (pc, pp) = layouter.assign_region(
                || format!("event{i} prefix"),
                |mut r| {
                    assign_pair_u64(
                        &config,
                        &mut r,
                        u64::from_be_bytes(e.child.resource_prefix),
                        u64::from_be_bytes(e.parent.resource_prefix),
                        known,
                        PairMode::Prefix,
                    )
                },
            )?;
            copy_equal(&mut layouter, &pc, &child_words[4])?;
            copy_equal(&mut layouter, &pp, &parent_words[4])?;

            let parent_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("event{i} parent opening")),
                d_node_cell.clone(),
                parent_leaf,
                &e.parent_open,
                "parent",
            )?;
            let child_old_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("event{i} child old")),
                d_node_cell.clone(),
                zero_cell.clone(),
                &e.child_old_open,
                "child_old",
            )?;
            let child_new_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("event{i} child new")),
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
                || format!("event{i} target grant words"),
                |mut r| assign_grant_words(&config, &mut r, &e.target, known),
            )?;
            let (rv_id, rv_revoker, rv_epoch) = layouter.assign_region(
                || format!("event{i} revoke words"),
                |mut region| -> Result<_, Error> {
                    let id = assign_value(
                        &mut region,
                        config.scratch,
                        0,
                        "rv_id",
                        e.revoke.grant_id,
                        known,
                    )?;
                    let rv = assign_value(
                        &mut region,
                        config.scratch,
                        1,
                        "rv_revoker",
                        e.revoke.revoker,
                        known,
                    )?;
                    let ep = assign_value(
                        &mut region,
                        config.scratch,
                        2,
                        "rv_epoch",
                        F::from(e.revoke.epoch),
                        known,
                    )?;
                    Ok((id, rv, ep))
                },
            )?;
            // Equality is enforced by the same constrained one_cell flag used
            // for all C gates.  This avoids adding zero-row copy-only regions
            // while keeping the relation unconditional.
            gated_eq(
                &config,
                &mut layouter,
                &one_cell,
                &target_words[1],
                &rv_id,
                "target id = revoke id",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &one_cell,
                &target_words[2],
                &rv_revoker,
                "target issuer = revoker",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &one_cell,
                &rv_epoch,
                &epoch_next,
                "revoke epoch = next",
            )?;
            let target_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} target leaf")),
                "target_leaf",
                target_words.clone(),
            )?;
            let revoke_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} revoke leaf")),
                "revoke_leaf",
                [
                    d_revoke_cell.clone(),
                    rv_id.clone(),
                    rv_revoker.clone(),
                    rv_epoch.clone(),
                ],
            )?;
            let target_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("event{i} target opening")),
                d_node_cell.clone(),
                target_leaf,
                &e.target_open,
                "target",
            )?;
            let rr_old_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("event{i} rr old")),
                d_node_cell.clone(),
                zero_cell.clone(),
                &e.rr_old_open,
                "rr_old",
            )?;
            let rr_new_opening = assign_opening_path(
                &config,
                layouter.namespace(|| format!("event{i} rr new")),
                d_node_cell.clone(),
                revoke_leaf.clone(),
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

            // ---- IR leaves and openings: all state words from constants ----
            let active_leaf_read = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} ir read leaf")),
                "ir_read_leaf",
                [
                    d_index_cell.clone(),
                    read_canon.field_cell.clone(),
                    one_cell.clone(),
                ],
            )?;
            let write_old_id_cell = state_transition(
                &config,
                &mut layouter,
                &zero_cell,
                &write_canon.field_cell,
                &rf,
                F::ZERO,
                e.ir_write_id,
                rf_val,
                known,
                "ir write old id mux",
            )?;
            let write_old_state_cell = state_transition(
                &config,
                &mut layouter,
                &zero_cell,
                &one_cell,
                &rf,
                F::ZERO,
                F::ONE,
                rf_val,
                known,
                "ir write old state mux",
            )?;
            let write_old_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} ir write old leaf")),
                "ir_write_old",
                [
                    d_index_cell.clone(),
                    write_old_id_cell,
                    write_old_state_cell,
                ],
            )?;
            let write_new_state_cell = state_transition(
                &config,
                &mut layouter,
                &one_cell,
                &revoked_code,
                &rf,
                F::ONE,
                F::from(2u64),
                rf_val,
                known,
                "ir write new state mux",
            )?;
            let write_new_leaf = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} ir write new leaf")),
                "ir_write_new",
                [
                    d_index_cell.clone(),
                    write_canon.field_cell.clone(),
                    write_new_state_cell,
                ],
            )?;

            let read_opening = assign_ir_opening(
                &config,
                layouter.namespace(|| format!("event{i} ir read opening")),
                d_index_node_cell.clone(),
                active_leaf_read,
                &e.ir_read_open,
                "ir_read_open",
            )?;
            for l in 0..DEPTH {
                copy_equal(
                    &mut layouter,
                    &read_opening.path[l].0,
                    &read_canon.low_bits[l],
                )?;
            }
            let write_old_opening = assign_ir_opening(
                &config,
                layouter.namespace(|| format!("event{i} ir write old opening")),
                d_index_node_cell.clone(),
                write_old_leaf.clone(),
                &e.ir_write_old_open,
                "ir_write_old_open",
            )?;
            for l in 0..DEPTH {
                copy_equal(
                    &mut layouter,
                    &write_old_opening.path[l].0,
                    &write_canon.low_bits[l],
                )?;
            }
            let write_new_opening = assign_ir_opening(
                &config,
                layouter.namespace(|| format!("event{i} ir write new opening")),
                d_index_node_cell.clone(),
                write_new_leaf,
                &e.ir_write_new_open,
                "ir_write_new_open",
            )?;
            for l in 0..DEPTH {
                copy_equal(
                    &mut layouter,
                    &write_new_opening.path[l].0,
                    &write_canon.low_bits[l],
                )?;
            }
            for l in 0..DEPTH {
                copy_equal(
                    &mut layouter,
                    &write_new_opening.path[l].0,
                    &write_old_opening.path[l].0,
                )?;
                copy_equal(
                    &mut layouter,
                    &write_new_opening.path[l].1,
                    &write_old_opening.path[l].1,
                )?;
            }

            // ---- bind canonical ids to event fields ----
            gated_eq(
                &config,
                &mut layouter,
                &gf,
                &read_canon.field_cell,
                &parent_words[1],
                "read id = parent.id",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &read_canon.field_cell,
                &target_words[1],
                "read id = target.id",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &gf,
                &write_canon.field_cell,
                &child_words[1],
                "write id = child.id",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &write_canon.field_cell,
                &rv_id,
                "write id = revoke.id",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &rv_id,
                &write_canon.field_cell,
                "RR id = IR write id",
            )?;

            // ---- semantic root bindings against THIS event's input roots ----
            gated_eq(
                &config,
                &mut layouter,
                &gf,
                &parent_opening.root,
                &gr_in[i],
                "grant parent in GR",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &gf,
                &child_old_opening.root,
                &gr_in[i],
                "grant child slot empty in GR",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &gf,
                &read_opening.root,
                &ir_in[i],
                "grant IR parent in IR",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &gf,
                &write_old_opening.root,
                &ir_in[i],
                "grant IR child empty slot",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &target_opening.root,
                &gr_in[i],
                "revoke target in GR",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &rr_old_opening.root,
                &rr_in[i],
                "revoke RR slot empty",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &read_opening.root,
                &ir_in[i],
                "revoke IR target active",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &write_old_opening.root,
                &ir_in[i],
                "revoke IR old slot",
            )?;

            // ---- root transitions ----
            let gnew_val = super::b_types::recompute_root_b(e.child.leaf(true), &e.child_new_open);
            let rnew_val = super::b_types::recompute_root_b(
                super::c_types::revoke_leaf_c(&e.revoke),
                &e.rr_new_open,
            );
            let ir_new_val = super::d3_06_b_ir::ir_recompute_root(
                super::d3_06_b_ir::ir_leaf(e.ir_write_id, e.ir_write_new_state),
                &e.ir_write_new_open,
            );
            let gr_out = state_transition(
                &config,
                &mut layouter,
                &gr_in[i],
                &child_new_opening.root,
                &gf,
                gr_in_val[i],
                gnew_val,
                gf_val,
                known,
                "GR transition",
            )?;
            let rr_out = state_transition(
                &config,
                &mut layouter,
                &rr_in[i],
                &rr_new_opening.root,
                &rf,
                rr_in_val[i],
                rnew_val,
                rf_val,
                known,
                "RR transition",
            )?;
            let ir_out = state_transition(
                &config,
                &mut layouter,
                &ir_in[i],
                &write_new_opening.root,
                &one_cell,
                ir_in_val[i],
                ir_new_val,
                F::ONE,
                known,
                "IR transition",
            )?;

            // ---- event commitments bound to ordered batch slots ----
            let c_grant = hash_words(
                &config,
                layouter.namespace(|| format!("event{i} c_grant")),
                "c_grant",
                [
                    d_event_cell.clone(),
                    type_grant_cell.clone(),
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
                layouter.namespace(|| format!("event{i} c_revoke")),
                "c_revoke",
                [
                    d_event_cell.clone(),
                    type_revoke_cell.clone(),
                    rv_id,
                    rv_revoker,
                    rv_epoch,
                ],
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &gf,
                &c_grant,
                &slot_cells[i],
                "grant commitment",
            )?;
            gated_eq(
                &config,
                &mut layouter,
                &rf,
                &c_revoke,
                &slot_cells[i],
                "revoke commitment",
            )?;

            gr_in_val.push(gr_in_val[i] + gf_val * (gnew_val - gr_in_val[i]));
            rr_in_val.push(rr_in_val[i] + rf_val * (rnew_val - rr_in_val[i]));
            ir_in_val.push(ir_in_val[i] + (ir_new_val - ir_in_val[i]));
            gr_in.push(gr_out);
            rr_in.push(rr_out);
            ir_in.push(ir_out);
        }

        // ---- C_prev / C_next from S0 and S2 roots ----
        let c_prev = hash_words(
            &config,
            layouter.namespace(|| "C_prev"),
            "C_prev",
            [
                d_state_cell.clone(),
                gr_in[0].clone(),
                rr_in[0].clone(),
                ir_in[0].clone(),
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
                gr_in[MAX_EVENTS].clone(),
                rr_in[MAX_EVENTS].clone(),
                ir_in[MAX_EVENTS].clone(),
                epoch_next.clone(),
                policy_cell.clone(),
            ],
        )?;

        // ---- D_E = H(D3-BATCH-v1, 2, C0, C1, pad) ----
        let d_e = hash_words(
            &config,
            layouter.namespace(|| "D_E"),
            "D_E",
            [
                d_batch_cell,
                n_cell.clone(),
                slot_cells[0].clone(),
                slot_cells[1].clone(),
                slot_cells[2].clone(),
            ],
        )?;

        // ---- frozen 8 instances ----
        layouter.constrain_instance(c_prev.cell(), config.instance, 0)?;
        layouter.constrain_instance(epoch_prev.cell(), config.instance, 1)?;
        layouter.constrain_instance(c_next.cell(), config.instance, 2)?;
        layouter.constrain_instance(epoch_next.cell(), config.instance, 3)?;
        layouter.constrain_instance(policy_cell.cell(), config.instance, 4)?;
        layouter.constrain_instance(version_cell.cell(), config.instance, 5)?;
        layouter.constrain_instance(d_e.cell(), config.instance, 6)?;
        layouter.constrain_instance(n_cell.cell(), config.instance, 7)?;
        let _ = (d_grant_cell, d_index_cell);
        Ok(())
    }
}

fn decode_root(be: &[u8; 32]) -> F {
    super::constants::decode_field_i(be).unwrap_or(F::ZERO)
}
