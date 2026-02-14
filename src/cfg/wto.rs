// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Weak Topological Ordering (WTO) as defined in
//! Bourdoncle, "Efficient chaotic iteration strategies with widenings", 1993.
//!
//! Using the example from section 3.1 in the paper, the graph:
//!
//! ```text
//!         4 --> 5 <-> 6
//!         ^ \________ |
//!         |          vv
//!         3 <-------- 7
//!         ^           |
//!         |           v
//!   1 --> 2 --------> 8
//! ```
//!
//! results in the WTO: `1 2 (3 4 (5 6) 7) 8`

use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::{Rc, Weak};

use super::graph::Cfg;
use super::label::Label;

/// A component in the WTO: either a single vertex or a cycle.
pub enum CycleOrLabel {
    Label(Label),
    Cycle(Rc<WtoCycle>),
}

/// A list of WTO components, stored in **reverse** order.
/// Iteration should use `.iter().rev()`.
type WtoPartition = Vec<CycleOrLabel>;

/// A cycle (nested component) in the WTO.
///
/// The head of the cycle is the last element in `components` (since they
/// are stored in reverse order).
pub struct WtoCycle {
    /// Sub-components in reverse order.
    components: WtoPartition,
    /// The cycle containing this cycle, or None if top-level.
    containing_cycle: OnceCell<Weak<WtoCycle>>,
}

impl WtoCycle {
    /// Get the head vertex of the cycle.
    ///
    /// Per Definition 1 in the paper, any cycle must start with a vertex.
    /// Since the vector is in reverse order, the head is the last element.
    pub fn head(&self) -> &Label {
        assert!(!self.components.is_empty(), "Empty cycle");
        match self.components.last().unwrap() {
            CycleOrLabel::Label(label) => label,
            CycleOrLabel::Cycle(_) => panic!("Expected Label at the back of components"),
        }
    }

    /// Iterate over components in forward order (i.e., reverse of storage).
    pub fn iter(&self) -> impl Iterator<Item = &CycleOrLabel> {
        self.components.iter().rev()
    }

    /// Visit the heads of all nested loops in this cycle.
    pub fn for_each_loop_head(&self, f: &mut dyn FnMut(&Label)) {
        for component in self.iter() {
            if let CycleOrLabel::Cycle(cycle) = component {
                f(cycle.head());
                cycle.for_each_loop_head(f);
            }
        }
    }
}

/// Check if a label is a member of a WTO component.
pub fn is_component_member(label: &Label, component: &CycleOrLabel) -> bool {
    match component {
        CycleOrLabel::Label(l) => l == label,
        CycleOrLabel::Cycle(cycle) => {
            if cycle.head() == label {
                return true;
            }
            for sub in cycle.iter() {
                if is_component_member(label, sub) {
                    return true;
                }
            }
            false
        }
    }
}

/// The nesting of a vertex: the set of heads of nested components containing it.
///
/// Stored in reverse order (innermost to outermost).
#[derive(Clone)]
pub struct WtoNesting {
    heads: Vec<Label>,
}

impl WtoNesting {
    /// Create a new nesting from a list of heads (inner → outer order).
    pub fn new(heads: Vec<Label>) -> Self {
        WtoNesting { heads }
    }

    /// Test whether this nesting is a strict superset of another nesting.
    ///
    /// That is, this nesting contains all heads from `other` plus at least one more.
    pub fn is_superset_of(&self, other: &WtoNesting) -> bool {
        let this_size = self.heads.len();
        let other_size = other.heads.len();
        if this_size <= other_size {
            return false;
        }
        // Compare from outermost (end of vectors) inward.
        for index in 0..other_size {
            if self.heads[this_size - 1 - index] != other.heads[other_size - 1 - index] {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for WtoNesting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Output from outermost to innermost.
        for head in self.heads.iter().rev() {
            write!(f, "{} ", head)?;
        }
        Ok(())
    }
}

/// Weak Topological Ordering of a control-flow graph.
pub struct Wto {
    /// Top-level components in reverse order.
    components: WtoPartition,
    /// Table mapping label to the cycle containing the label.
    containing_cycle: HashMap<Label, Weak<WtoCycle>>,
    /// Precomputed nesting for every label in the CFG.
    nesting: HashMap<Label, WtoNesting>,
}

impl Wto {
    /// Build a WTO from a control-flow graph.
    pub fn new(cfg: &Cfg) -> Self {
        WtoBuilder::build(cfg)
    }

    /// Iterate over top-level components in forward order.
    pub fn iter(&self) -> impl Iterator<Item = &CycleOrLabel> {
        self.components.iter().rev()
    }

    /// Get the vertex at the head of the component containing a given label.
    ///
    /// If the label is itself a head of a component, we want the head of whatever
    /// contains that entire component. Returns None if the label is not nested.
    fn head(&self, label: &Label) -> Option<Label> {
        let weak = self.containing_cycle.get(label)?;
        let cycle = weak.upgrade()?;
        let first = cycle.head();
        if first != label {
            // Return the head of the cycle the label is inside.
            return Some(first.clone());
        }
        // This label is already the head of a cycle, so get the cycle's parent.
        let parent = cycle.containing_cycle.get()?.upgrade()?;
        Some(parent.head().clone())
    }

    /// Collect the chain of heads from inner to outer for a given label.
    fn collect_heads(&self, label: &Label) -> Vec<Label> {
        let mut heads = Vec::new();
        let mut h = self.head(label);
        while let Some(head) = h {
            heads.push(head.clone());
            h = self.head(&head);
        }
        heads
    }

    /// Get the precomputed nesting for a given label.
    pub fn nesting(&self, label: &Label) -> &WtoNesting {
        self.nesting
            .get(label)
            .expect("label not found in WTO nesting table")
    }

    /// Visit the heads of all loops in the WTO.
    pub fn for_each_loop_head(&self, f: &mut dyn FnMut(&Label)) {
        for component in self.iter() {
            if let CycleOrLabel::Cycle(cycle) = component {
                f(cycle.head());
                cycle.for_each_loop_head(f);
            }
        }
    }
}

impl fmt::Display for Wto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn write_partition(f: &mut fmt::Formatter<'_>, partition: &WtoPartition) -> fmt::Result {
            for component in partition.iter().rev() {
                match component {
                    CycleOrLabel::Label(label) => write!(f, "{}", label)?,
                    CycleOrLabel::Cycle(cycle) => {
                        write!(f, "( ")?;
                        write_partition(f, &cycle.components)?;
                        write!(f, ")")?;
                    }
                }
                write!(f, " ")?;
            }
            Ok(())
        }
        write_partition(f, &self.components)?;
        writeln!(f)
    }
}

// ---------------------------------------------------------------------------
// WTO Builder (iterative Bourdoncle algorithm)
// ---------------------------------------------------------------------------

const DFN_INF: i32 = i32::MAX;

/// Per-vertex data during WTO construction.
struct WtoVertexData {
    dfn: i32,
    head_dfn: i32,
}

impl WtoVertexData {
    fn new() -> Self {
        WtoVertexData {
            dfn: 0,
            head_dfn: 0,
        }
    }
}

/// A component during construction. Cycles are referenced by index.
enum BuilderComponent {
    Label(Label),
    /// Index into the builder's `cycles` vector.
    CycleIdx(usize),
}

/// A cycle being built. Fields mirror WtoCycle but with builder-local indices.
struct BuilderCycle {
    components: Vec<BuilderComponent>,
    /// Index of parent cycle, or None if top-level.
    parent_cycle_idx: Option<usize>,
}

enum VisitTaskType {
    PushSuccessors,
    StartVisit,
    ContinueVisit,
}

struct VisitTask {
    task_type: VisitTaskType,
    vertex: Label,
    /// Which partition to append to: None = top-level, Some(idx) = cycle at idx.
    target_cycle: Option<usize>,
    /// The containing cycle index (for recording nesting).
    containing_cycle: Option<usize>,
}

struct WtoBuilder {
    vertex_data: HashMap<Label, WtoVertexData>,
    num: i32,
    stack: Vec<Label>,
    /// Top-level components (in reverse order).
    top_components: Vec<BuilderComponent>,
    /// All cycles created during construction.
    cycles: Vec<BuilderCycle>,
    /// Mapping from vertex to the cycle that directly contains it.
    containing_cycle_map: HashMap<Label, usize>,
}

impl WtoBuilder {
    fn build(cfg: &Cfg) -> Wto {
        let mut vertex_data = HashMap::new();
        for label in cfg.labels() {
            vertex_data.insert(label.clone(), WtoVertexData::new());
        }

        let mut builder = WtoBuilder {
            vertex_data,
            num: 0,
            stack: Vec::new(),
            top_components: Vec::new(),
            cycles: Vec::new(),
            containing_cycle_map: HashMap::new(),
        };

        let mut visit_stack: Vec<VisitTask> = Vec::new();
        visit_stack.push(VisitTask {
            task_type: VisitTaskType::PushSuccessors,
            vertex: cfg.entry_label(),
            target_cycle: None,
            containing_cycle: None,
        });

        while let Some(task) = visit_stack.pop() {
            match task.task_type {
                VisitTaskType::PushSuccessors => {
                    builder.push_successors(
                        cfg,
                        &mut visit_stack,
                        &task.vertex,
                        task.target_cycle,
                        task.containing_cycle,
                    );
                }
                VisitTaskType::StartVisit => {
                    builder.start_visit(
                        cfg,
                        &mut visit_stack,
                        &task.vertex,
                        task.target_cycle,
                        task.containing_cycle,
                    );
                }
                VisitTaskType::ContinueVisit => {
                    builder.continue_visit(&task.vertex, task.target_cycle, task.containing_cycle);
                }
            }
        }

        // Convert builder representation to final Rc-based structure.
        builder.finalize()
    }

    fn get_partition_mut(&mut self, target_cycle: Option<usize>) -> &mut Vec<BuilderComponent> {
        match target_cycle {
            None => &mut self.top_components,
            Some(idx) => &mut self.cycles[idx].components,
        }
    }

    fn push_successors(
        &mut self,
        cfg: &Cfg,
        visit_stack: &mut Vec<VisitTask>,
        vertex: &Label,
        target_cycle: Option<usize>,
        containing_cycle: Option<usize>,
    ) {
        if self.vertex_data[vertex].dfn != 0 {
            return;
        }
        self.num += 1;
        self.vertex_data.get_mut(vertex).unwrap().dfn = self.num;
        self.stack.push(vertex.clone());

        visit_stack.push(VisitTask {
            task_type: VisitTaskType::StartVisit,
            vertex: vertex.clone(),
            target_cycle,
            containing_cycle,
        });

        for succ in cfg.children_of(vertex).iter().rev() {
            if self.vertex_data[succ].dfn == 0 {
                visit_stack.push(VisitTask {
                    task_type: VisitTaskType::PushSuccessors,
                    vertex: succ.clone(),
                    target_cycle,
                    containing_cycle,
                });
            }
        }
    }

    fn start_visit(
        &mut self,
        cfg: &Cfg,
        visit_stack: &mut Vec<VisitTask>,
        vertex: &Label,
        target_cycle: Option<usize>,
        containing_cycle: Option<usize>,
    ) {
        let vertex_dfn = self.vertex_data[vertex].dfn;
        let mut head_dfn = vertex_dfn;
        let mut is_loop = false;

        for succ in cfg.children_of(vertex) {
            let data = &self.vertex_data[succ];
            let mut min_dfn = data.dfn;
            if data.head_dfn != 0 && data.dfn != DFN_INF {
                min_dfn = data.head_dfn;
            }
            if min_dfn <= head_dfn {
                head_dfn = min_dfn;
                is_loop = true;
            }
        }

        if head_dfn == vertex_dfn {
            self.vertex_data.get_mut(vertex).unwrap().dfn = DFN_INF;
            let mut element = self.stack.pop().unwrap();

            if is_loop {
                while element != *vertex {
                    self.vertex_data.get_mut(&element).unwrap().dfn = 0;
                    self.vertex_data.get_mut(&element).unwrap().head_dfn = 0;
                    element = self.stack.pop().unwrap();
                }
                self.vertex_data.get_mut(vertex).unwrap().head_dfn = head_dfn;

                // Create a new cycle.
                let cycle_idx = self.cycles.len();
                self.cycles.push(BuilderCycle {
                    components: Vec::new(),
                    parent_cycle_idx: containing_cycle,
                });

                // Schedule ContinueVisit.
                visit_stack.push(VisitTask {
                    task_type: VisitTaskType::ContinueVisit,
                    vertex: vertex.clone(),
                    target_cycle,
                    containing_cycle: Some(cycle_idx),
                });

                // Walk successors for the Component() function.
                for succ in cfg.children_of(vertex).iter().rev() {
                    if self.vertex_data[succ].dfn == 0 {
                        visit_stack.push(VisitTask {
                            task_type: VisitTaskType::PushSuccessors,
                            vertex: succ.clone(),
                            target_cycle: Some(cycle_idx),
                            containing_cycle: Some(cycle_idx),
                        });
                    }
                }
                return;
            }

            // Not a loop head: insert as a plain vertex.
            self.get_partition_mut(target_cycle)
                .push(BuilderComponent::Label(vertex.clone()));
            if let Some(cc) = containing_cycle {
                self.containing_cycle_map.insert(vertex.clone(), cc);
            }
        }

        self.vertex_data.get_mut(vertex).unwrap().head_dfn = head_dfn;
    }

    fn continue_visit(
        &mut self,
        vertex: &Label,
        target_cycle: Option<usize>,
        containing_cycle: Option<usize>,
    ) {
        let cycle_idx = containing_cycle.expect("ContinueVisit must have containing_cycle");

        // Add the head vertex to the cycle.
        self.cycles[cycle_idx]
            .components
            .push(BuilderComponent::Label(vertex.clone()));

        // Insert the cycle reference into the parent partition.
        self.get_partition_mut(target_cycle)
            .push(BuilderComponent::CycleIdx(cycle_idx));

        // Record containing cycle for this vertex.
        self.containing_cycle_map.insert(vertex.clone(), cycle_idx);
    }

    /// Convert the builder's index-based representation to the final Rc-based WTO.
    fn finalize(self) -> Wto {
        let num_cycles = self.cycles.len();

        // Build cycles bottom-up. Child cycles (higher index) are built before parents
        // (lower index), since a child cycle is always created after its parent in the
        // DFS. We process in reverse so children are available when parents need them.
        //
        // We first build all WtoCycle structs (without parent pointers), wrap them in Rc,
        // then set up the parent (containing_cycle) Weak pointers in a second pass.
        let mut rc_cycles: Vec<Option<Rc<WtoCycle>>> = vec![None; num_cycles];

        // Pass 1: Build components for each cycle (reverse order).
        for i in (0..num_cycles).rev() {
            let builder_cycle = &self.cycles[i];
            let mut components = Vec::new();
            for comp in &builder_cycle.components {
                match comp {
                    BuilderComponent::Label(label) => {
                        components.push(CycleOrLabel::Label(label.clone()));
                    }
                    BuilderComponent::CycleIdx(idx) => {
                        components.push(CycleOrLabel::Cycle(
                            rc_cycles[*idx].as_ref().unwrap().clone(),
                        ));
                    }
                }
            }
            rc_cycles[i] = Some(Rc::new(WtoCycle {
                components,
                containing_cycle: OnceCell::new(), // filled in pass 2
            }));
        }

        // Pass 2: Set up containing_cycle (parent) Weak pointers.
        // This uses OnceCell so the parent link is initialized exactly once.
        for i in 0..num_cycles {
            if let Some(parent_idx) = self.cycles[i].parent_cycle_idx {
                let weak_parent = Rc::downgrade(rc_cycles[parent_idx].as_ref().unwrap());
                let rc = rc_cycles[i].as_ref().unwrap();
                rc.containing_cycle
                    .set(weak_parent)
                    .expect("containing_cycle initialized exactly once");
            }
        }

        // Convert top-level components.
        let mut top_components = Vec::new();
        for comp in &self.top_components {
            match comp {
                BuilderComponent::Label(label) => {
                    top_components.push(CycleOrLabel::Label(label.clone()));
                }
                BuilderComponent::CycleIdx(idx) => {
                    top_components.push(CycleOrLabel::Cycle(
                        rc_cycles[*idx].as_ref().unwrap().clone(),
                    ));
                }
            }
        }

        // Build containing_cycle map with Weak references.
        let mut containing_cycle = HashMap::new();
        for (label, idx) in &self.containing_cycle_map {
            containing_cycle.insert(
                label.clone(),
                Rc::downgrade(rc_cycles[*idx].as_ref().unwrap()),
            );
        }

        let mut wto = Wto {
            components: top_components,
            containing_cycle,
            nesting: HashMap::new(),
        };

        // Precompute nestings for every label in the CFG.
        for label in self.vertex_data.keys() {
            let heads = wto.collect_heads(label);
            wto.nesting.insert(label.clone(), WtoNesting::new(heads));
        }

        wto
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::graph::cfg_from_adjacency_list;

    fn l(n: i32) -> Label {
        Label::new(n)
    }

    /// Port of test_wto.cpp: "wto figure 1"
    #[test]
    fn wto_figure_1() {
        let wto = Wto::new(&cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2)]),
            (l(2), vec![l(3)]),
            (l(3), vec![l(4)]),
            (l(4), vec![l(5), l(7)]),
            (l(5), vec![l(6)]),
            (l(6), vec![l(5), l(7)]),
            (l(7), vec![l(3), l(8)]),
            (l(8), vec![Label::exit()]),
        ]));
        assert_eq!(format!("{}", wto), "entry 1 2 ( 3 4 ( 5 6 ) 7 ) 8 exit \n");
    }

    /// Port of test_wto.cpp: "wto figure 2a"
    #[test]
    fn wto_figure_2a() {
        let wto = Wto::new(&cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2), l(4)]),
            (l(2), vec![l(3)]),
            (l(3), vec![Label::exit()]),
            (l(4), vec![l(3), l(5)]),
            (l(5), vec![l(4)]),
        ]));
        assert_eq!(format!("{}", wto), "entry 1 ( 4 5 ) 2 3 exit \n");
    }

    /// Port of test_wto.cpp: "wto figure 2b"
    #[test]
    fn wto_figure_2b() {
        let wto = Wto::new(&cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2), l(4)]),
            (l(2), vec![l(3)]),
            (l(3), vec![l(1), Label::exit()]),
            (l(4), vec![l(3)]),
        ]));
        assert_eq!(format!("{}", wto), "entry ( 1 4 2 3 ) exit \n");
    }

    #[test]
    fn wto_nesting_figure_1() {
        let wto = Wto::new(&cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2)]),
            (l(2), vec![l(3)]),
            (l(3), vec![l(4)]),
            (l(4), vec![l(5), l(7)]),
            (l(5), vec![l(6)]),
            (l(6), vec![l(5), l(7)]),
            (l(7), vec![l(3), l(8)]),
            (l(8), vec![Label::exit()]),
        ]));

        // Node 1 is not in any cycle.
        assert_eq!(format!("{}", wto.nesting(&l(1))), "");

        // Node 4 is in cycle headed by 3.
        assert_eq!(format!("{}", wto.nesting(&l(4))), "3 ");

        // Node 6 is in cycle headed by 5, which is in cycle headed by 3.
        assert_eq!(format!("{}", wto.nesting(&l(6))), "3 5 ");

        // Node 3 (head of outer cycle) — its nesting is the cycles above it = empty.
        assert_eq!(format!("{}", wto.nesting(&l(3))), "");
    }

    #[test]
    fn wto_nesting_superset() {
        let inner = WtoNesting::new(vec![l(5), l(3)]);
        let outer = WtoNesting::new(vec![l(3)]);
        assert!(inner.is_superset_of(&outer));
        assert!(!outer.is_superset_of(&inner));
        assert!(!inner.is_superset_of(&inner));
    }

    #[test]
    fn wto_for_each_loop_head() {
        let wto = Wto::new(&cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2)]),
            (l(2), vec![l(3)]),
            (l(3), vec![l(4)]),
            (l(4), vec![l(5), l(7)]),
            (l(5), vec![l(6)]),
            (l(6), vec![l(5), l(7)]),
            (l(7), vec![l(3), l(8)]),
            (l(8), vec![Label::exit()]),
        ]));
        let mut heads = Vec::new();
        wto.for_each_loop_head(&mut |label| heads.push(label.clone()));
        // Should find heads 3 and 5.
        heads.sort();
        assert_eq!(heads, vec![l(3), l(5)]);
    }

    #[test]
    fn wto_is_component_member() {
        let wto = Wto::new(&cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2)]),
            (l(2), vec![l(1), Label::exit()]),
        ]));
        // The WTO should be: entry (1 2) exit
        // Check that 1 and 2 are members of the cycle.
        for component in wto.iter() {
            if let CycleOrLabel::Cycle(cycle) = component {
                assert!(is_component_member(
                    &l(1),
                    &CycleOrLabel::Cycle(cycle.clone())
                ));
                assert!(is_component_member(
                    &l(2),
                    &CycleOrLabel::Cycle(cycle.clone())
                ));
                assert!(!is_component_member(
                    &l(3),
                    &CycleOrLabel::Cycle(cycle.clone())
                ));
            }
        }
    }
}
