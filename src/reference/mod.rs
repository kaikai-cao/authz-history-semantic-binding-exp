//! Independent off-circuit reference models.
//!
//! These modules deliberately do not call Halo2, MockProver, or any circuit
//! witness builder. They exist to validate design semantics independently.

pub mod mixed_event_state;

pub use mixed_event_state::*;
