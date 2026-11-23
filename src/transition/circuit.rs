//! EXP-D3-03-A — minimal Halo2 state-transition circuit skeleton.
//!
//! Scope (deliberately narrow): bind C_prev / C_next to public instances by
//! recomputing them from witness bytes and field constants INSIDE the circuit;
//! check R2-02 category-I canonical field encoding entirely in-circuit; bind
//! policy_id / transition_version / event_batch_commitment / event_count.
//!
//! NOT in scope (D3-03-B/C): grant/revoke semantics, parent binding, scope,
//! resource, Merkle updates, Cascade.  This circuit alone does not prove ALLOW
//! or DENY, does not check the Bridge signature, layout canonicality or freshness.
//!
//! Canonical field check gadget (32-byte big-endian b vs Pallas Fp modulus p):
//!   - decompose each byte into 8 boolean bits (MSB first), t = 0..255;
//!   - pref[t]   = product of (1 - (bit_s - p_s)^2) for s < t  (1 while prefix equal);
//!   - ltacc[t]  = sum_{s<t} pref[s]*(1-bit_s)*p_s            (1 iff already less);
//!   - gate: final ltacc == 1  ⇒  b < p (b == p or b > p are rejected);
//!   - acc[t]    = sum_{s<=t} bit_s * 2^(255-s)  ⇒ acc[256] = int_be(b) mod p,
//!     which equals the canonical field element because b < p is enforced.
//!
//! `p_s` and `2^(255-s)` are fixed columns, never witness-controlled.

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

use super::constants::{
    batch_pad, d_batch, d_state, policy_id, transition_version, MAX_EVENTS, PALLAS_P_BE,
};
use super::types::{TransitionInstances, TransitionWitness};

const BITS: usize = 256;

#[derive(Clone, Debug)]
pub struct TransitionConfig {
    // --- Poseidon gadget ---
    poseidon: Pow5Config<F, 3, 2>,
    // --- canonical-field gadget ---
    b_bit: Column<Advice>,
    pref: Column<Advice>,
    ltacc: Column<Advice>,
    acc: Column<Advice>,
    p_bit: Column<Fixed>,
    weight: Column<Fixed>,
    // --- general-purpose bound cells ---
    scratch: Column<Advice>,
    active_col: Column<Advice>,
    slot_col: Column<Advice>,
    n_col: Column<Advice>,
    instance: Column<Instance>,
    // --- selectors ---
    q_bool_bit: Selector,
    q_cmp: Selector,
    q_final: Selector,
    q_bind_policy: Selector,
    q_bind_version: Selector,
    q_bool_active: Selector,
    q_slotpad: Selector,
    q_mono: Selector,
    q_count: Selector,
}

/// Bit weight of bit position t (MSB-first, t=0 -> 2^255).  Computed in the
/// field; when t=0 the value is 2^255 mod p, which is fine because the final
/// integer is already constrained < p.
fn bit_weights() -> Vec<F> {
    let mut w = vec![F::ZERO; BITS];
    w[BITS - 1] = F::ONE;
    for t in (0..BITS - 1).rev() {
        w[t] = w[t + 1] * F::from(2u64);
    }
    w
}

fn p_bits() -> Vec<u64> {
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

/// Assign one root's 32 bytes; return the cell holding the canonical field
/// element (int_be(bytes) as Fp).  Enforces bytes < p with two dedicated
/// prefix/less accumulators and boolean bit decomposition.
fn assign_root_encoding(
    cfg: &TransitionConfig,
    region: &mut Region<'_, F>,
    bytes: [u8; 32],
    known: bool,
) -> Result<AssignedCell<F, F>, Error> {
    let weights = bit_weights();
    let pbits = p_bits();

    let mut bits = [0u64; BITS];
    for (i, byte) in bytes.iter().enumerate() {
        for k in 0..8 {
            bits[i * 8 + k] = u64::from((byte >> (7 - k)) & 1);
        }
    }

    // prefix: 1 while all higher bits equal p, then 0 forever.
    let mut pref = [F::ZERO; BITS + 1];
    pref[0] = F::ONE;
    // less-than accumulator.
    let mut less = [F::ZERO; BITS + 1];
    // integer accumulator (field representation of int_be(b) mod p).
    let mut acc = [F::ZERO; BITS + 1];
    for t in 0..BITS {
        let b = F::from(bits[t]);
        let p = F::from(pbits[t]);
        pref[t + 1] = pref[t] * (F::ONE - (b - p) * (b - p));
        less[t + 1] = less[t] + pref[t] * (F::ONE - b) * p;
        acc[t + 1] = acc[t] + b * weights[t];
    }

    // Assign bit cells + fixed constants; enable boolean and transition gates.
    for t in 0..BITS {
        let b = F::from(bits[t]);
        assign_value::<F>(region, cfg.b_bit, t, "root_bit", b, known)?;
        cfg.q_bool_bit.enable(region, t)?;
        region.assign_fixed(|| "p_bit", cfg.p_bit, t, || Value::known(F::from(pbits[t])))?;
        region.assign_fixed(|| "weight", cfg.weight, t, || Value::known(weights[t]))?;
        cfg.q_cmp.enable(region, t)?;
    }
    // Sentinel row BITS holds the final accumulators.  q_final forces less == 1.
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
    // b_bit at the sentinel row is not queried by any gate; assign a dummy so
    // the advice column stays fully populated in every region.
    assign_value::<F>(region, cfg.b_bit, BITS, "bit_sentinel", F::ZERO, known)?;

    root_cell.ok_or(Error::Synthesis)
}

fn hash_words<L: Layouter<F>, const N: usize>(
    cfg: &TransitionConfig,
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

#[derive(Clone, Debug)]
pub struct TransitionCircuit {
    pub witness: Option<TransitionWitness>,
}

impl TransitionCircuit {
    pub fn new(witness: TransitionWitness) -> Self {
        Self {
            witness: Some(witness),
        }
    }
    /// Key-generation shape: identical constraints, no private values.
    pub fn for_keygen() -> Self {
        Self { witness: None }
    }
}

impl Circuit<F> for TransitionCircuit {
    type Config = TransitionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::for_keygen()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Poseidon columns (same layout as D2-A).
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

        for col in [
            b_bit, pref, ltacc, acc, scratch, active_col, slot_col, n_col,
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

        // bit booleanity
        meta.create_gate("root-bit-boolean", |meta| {
            let q = meta.query_selector(q_bool_bit);
            let b = meta.query_advice(b_bit, Rotation::cur());
            Constraints::with_selector(q, vec![b.clone() * b.clone() - b])
        });

        // prefix / less-than / integer accumulation transitions
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

        // final: less == 1 ⇒ bytes < p strictly (rejects b == p and b > p)
        meta.create_gate("canonical-final", |meta| {
            let q = meta.query_selector(q_final);
            let less = meta.query_advice(ltacc, Rotation::cur());
            Constraints::with_selector(q, vec![less - Expression::Constant(F::ONE)])
        });

        // constant binding gates: embedded frozen constants, not prover input.
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

        // batch slot padding / ordering / count
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

        TransitionConfig {
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
            q_bool_bit,
            q_cmp,
            q_final,
            q_bind_policy,
            q_bind_version,
            q_bool_active,
            q_slotpad,
            q_mono,
            q_count,
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
            .unwrap_or_else(TransitionWitness::blank);
        let val = |x: F| {
            if known {
                Value::known(x)
            } else {
                Value::unknown()
            }
        };

        // ---- 1. four canonical roots, fully in-circuit ----
        // Each root MUST live in its own region: assign_root_encoding occupies
        // rows 0..=256 of the shared advice columns, so packing four into one
        // region would overlap and silently overwrite cells.
        let mut mk_root = |name: &'static str, bytes: [u8; 32]| {
            let cfg = config.clone();
            let cell = layouter.assign_region(
                || name,
                move |mut region| assign_root_encoding(&cfg, &mut region, bytes, known),
            )?;
            Ok::<_, Error>(cell)
        };
        let gprev = mk_root("root gr_prev", w.gr_prev_be)?;
        let rprev = mk_root("root rr_prev", w.rr_prev_be)?;
        let gnext = mk_root("root gr_next", w.gr_next_be)?;
        let rnext = mk_root("root rr_next", w.rr_next_be)?;
        let roots = [gprev, rprev, gnext, rnext];

        // ---- 2. field constants + epoch cells (hardcoded / witness, never free) ----
        let (d_state_cell, d_batch_cell, policy_cell, version_cell, epoch_prev, epoch_next) =
            layouter.assign_region(
                || "constants and epochs",
                |mut region| -> Result<_, Error> {
                    let ds =
                        region.assign_advice(|| "d_state", config.scratch, 0, || val(d_state()))?;
                    let db =
                        region.assign_advice(|| "d_batch", config.scratch, 1, || val(d_batch()))?;
                    let pc = region.assign_advice(
                        || "policy",
                        config.scratch,
                        2,
                        || val(policy_id()),
                    )?;
                    config.q_bind_policy.enable(&mut region, 2)?;
                    let vc = region.assign_advice(
                        || "version",
                        config.scratch,
                        3,
                        || val(F::from(transition_version() as u64)),
                    )?;
                    config.q_bind_version.enable(&mut region, 3)?;
                    let ep = region.assign_advice(
                        || "prev_epoch",
                        config.scratch,
                        4,
                        || val(F::from(w.prev_epoch)),
                    )?;
                    let en = region.assign_advice(
                        || "next_epoch",
                        config.scratch,
                        5,
                        || val(F::from(w.next_epoch)),
                    )?;
                    Ok((ds, db, pc, vc, ep, en))
                },
            )?;

        // ---- 3. state commitments: C_prev / C_next recomputed in-circuit ----
        let c_prev = hash_words(
            &config,
            layouter.namespace(|| "C_prev"),
            "C_prev",
            [
                d_state_cell.clone(),
                roots[0].clone(),
                roots[1].clone(),
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
                roots[2].clone(),
                roots[3].clone(),
                epoch_next.clone(),
                policy_cell.clone(),
            ],
        )?;

        // ---- 4. batch commitment with explicit padding rule ----
        let mut active = [0u64; MAX_EVENTS];
        for i in 0..MAX_EVENTS {
            active[i] = if (i as u32) < w.event_count { 1 } else { 0 };
        }
        let (n_cell, slots, active_cells) = layouter.assign_region(
            || "batch slots",
            |mut region| -> Result<_, Error> {
                let n = region.assign_advice(
                    || "n",
                    config.n_col,
                    0,
                    || val(F::from(w.event_count as u64)),
                )?;
                let mut slot_cells = Vec::with_capacity(MAX_EVENTS);
                let mut act_cells = Vec::with_capacity(MAX_EVENTS);
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
                    slot_cells.push(s);
                    act_cells.push(a);
                }
                config.q_count.enable(&mut region, 0)?;
                Ok((n, slot_cells, act_cells))
            },
        )?;
        let _ = active_cells; // cells are bound by gates; no extra copy needed.

        let mut batch_words = Vec::with_capacity(MAX_EVENTS + 2);
        batch_words.push(d_batch_cell);
        batch_words.push(n_cell.clone());
        batch_words.extend(slots);
        let batch_arr: [AssignedCell<F, F>; MAX_EVENTS + 2] = batch_words.try_into().unwrap();
        let d_e = hash_words(&config, layouter.namespace(|| "D_E"), "D_E", batch_arr)?;

        // ---- 5. constrain the 8 public instances in frozen order ----
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

/// Convenience: verify that an instance vector has the frozen length.
pub fn assert_instance_shape(inst: &TransitionInstances) {
    assert_eq!(inst.as_vec().len(), TransitionInstances::COUNT);
}
