// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Split Difference Bound Matrix — sparse weighted-graph representation of
//! difference constraints for abstract interpretation.

pub mod graph;
pub mod graph_ops;
pub mod graph_views;
pub mod heap;
pub mod split_dbm;

use crate::arith::number::Number;

/// DBM edge weight — unbounded mathematical integer.
pub type Weight = Number;

/// Vertex identifier in the graph.
pub type VertId = u16;

/// Set of vertex identifiers.
pub type VertSet = std::collections::HashSet<VertId>;
