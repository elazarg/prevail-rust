// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Control-flow graph abstraction.

use std::collections::{BTreeMap, BTreeSet};

use super::label::Label;

/// Adjacency information for a single node in the CFG.
struct Adjacent {
    parents: BTreeSet<Label>,
    children: BTreeSet<Label>,
}

impl Adjacent {
    fn new() -> Self {
        Adjacent {
            parents: BTreeSet::new(),
            children: BTreeSet::new(),
        }
    }
}

/// Control-Flow Graph.
///
/// Nodes are `Label`s. Every CFG has an entry and an exit node.
pub struct Cfg {
    neighbours: BTreeMap<Label, Adjacent>,
}

impl Cfg {
    /// Create a new CFG with entry and exit nodes (no edges between them).
    pub fn new() -> Self {
        let mut neighbours = BTreeMap::new();
        neighbours.insert(Label::entry(), Adjacent::new());
        neighbours.insert(Label::exit(), Adjacent::new());
        Cfg { neighbours }
    }

    /// The entry label.
    pub fn entry_label(&self) -> Label {
        Label::entry()
    }

    /// The exit label.
    pub fn exit_label(&self) -> Label {
        Label::exit()
    }

    fn get_node(&self, label: &Label) -> &Adjacent {
        self.neighbours
            .get(label)
            .unwrap_or_else(|| panic!("Label {} not found in the CFG", label))
    }

    fn get_node_mut(&mut self, label: &Label) -> &mut Adjacent {
        self.neighbours
            .get_mut(label)
            .unwrap_or_else(|| panic!("Label {} not found in the CFG", label))
    }

    /// Returns the children (successors) of the given label.
    pub fn children_of(&self, label: &Label) -> &BTreeSet<Label> {
        &self.get_node(label).children
    }

    /// Returns the parents (predecessors) of the given label.
    pub fn parents_of(&self, label: &Label) -> &BTreeSet<Label> {
        &self.get_node(label).parents
    }

    /// Returns an iterator over all labels in the CFG (including entry and exit).
    pub fn labels(&self) -> impl Iterator<Item = &Label> {
        self.neighbours.keys()
    }

    /// Returns the number of nodes in the CFG.
    pub fn size(&self) -> usize {
        self.neighbours.len()
    }

    /// Returns true if the CFG contains the given label.
    pub fn contains(&self, label: &Label) -> bool {
        self.neighbours.contains_key(label)
    }

    /// Returns the single child of the given label.
    ///
    /// Panics if the label does not have exactly one child.
    pub fn get_child(&self, label: &Label) -> Label {
        let node = self.get_node(label);
        assert_eq!(
            node.children.len(),
            1,
            "Label {} does not have a single child",
            label
        );
        node.children.iter().next().unwrap().clone()
    }

    /// Returns the single parent of the given label.
    ///
    /// Panics if the label does not have exactly one parent.
    pub fn get_parent(&self, label: &Label) -> Label {
        let node = self.get_node(label);
        assert_eq!(
            node.parents.len(),
            1,
            "Label {} does not have a single parent",
            label
        );
        node.parents.iter().next().unwrap().clone()
    }

    /// Returns the in-degree (number of parents) of the given label.
    pub fn in_degree(&self, label: &Label) -> usize {
        self.get_node(label).parents.len()
    }

    /// Returns the out-degree (number of children) of the given label.
    pub fn out_degree(&self, label: &Label) -> usize {
        self.get_node(label).children.len()
    }

    /// Returns the number of siblings of the given label.
    ///
    /// Panics if the label does not have exactly one parent.
    pub fn num_siblings(&self, label: &Label) -> usize {
        let parent = self.get_parent(label);
        self.out_degree(&parent)
    }

    /// Insert a label into the CFG (no edges).
    pub fn insert(&mut self, label: Label) {
        assert!(
            !self.neighbours.contains_key(&label),
            "Label {} already exists",
            label
        );
        self.neighbours.insert(label, Adjacent::new());
    }

    /// Add a directed edge from `a` to `b`.
    pub fn add_child(&mut self, a: &Label, b: &Label) {
        assert_ne!(b, &Label::entry(), "Cannot add edge to entry");
        assert_ne!(a, &Label::exit(), "Cannot add edge from exit");
        self.get_node_mut(a).children.insert(b.clone());
        self.get_node_mut(b).parents.insert(a.clone());
    }

    /// Remove a directed edge from `a` to `b`.
    pub fn remove_child(&mut self, a: &Label, b: &Label) {
        self.get_node_mut(a).children.remove(b);
        self.get_node_mut(b).parents.remove(a);
    }

    /// Insert a new label after `prev`, splicing it into all of prev's outgoing edges.
    pub fn insert_after(&mut self, prev: &Label, new_label: Label) {
        assert_ne!(prev, &new_label, "Cannot insert after the same label");
        // Collect prev's children.
        let prev_children: BTreeSet<Label> = std::mem::take(&mut self.get_node_mut(prev).children);
        // Remove prev from each child's parents.
        for child in &prev_children {
            self.get_node_mut(child).parents.remove(prev);
        }
        // Insert new node.
        self.insert(new_label.clone());
        // Re-wire: prev -> new_label -> each former child.
        for child in &prev_children {
            self.add_child(prev, &new_label);
            self.add_child(&new_label, child);
        }
    }
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg::new()
    }
}

/// Construct a CFG from an adjacency list of `(from_pc, [to_pc, ...])` pairs.
///
/// Entry and exit labels must appear explicitly in the adjacency list if they
/// have edges; they are pre-inserted by the CFG constructor.
pub fn cfg_from_adjacency_list(adj: &[(Label, Vec<Label>)]) -> Cfg {
    let mut cfg = Cfg::new();
    // Insert all non-entry/exit labels.
    for (label, children) in adj {
        if *label != Label::entry() && *label != Label::exit() && !cfg.contains(label) {
            cfg.insert(label.clone());
        }
        // Also ensure children exist as nodes.
        for child in children {
            if *child != Label::entry() && *child != Label::exit() && !cfg.contains(child) {
                cfg.insert(child.clone());
            }
        }
    }
    // Add edges.
    for (label, children) in adj {
        for child in children {
            cfg.add_child(label, child);
        }
    }
    cfg
}

/// A basic block: a maximal sequence of labels with single-entry/single-exit flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicBlock {
    labels: Vec<Label>,
}

impl BasicBlock {
    /// Create a basic block starting with the given label.
    pub fn new(first_label: Label) -> Self {
        BasicBlock {
            labels: vec![first_label],
        }
    }

    /// The first label in the block.
    pub fn first_label(&self) -> &Label {
        self.labels.first().unwrap()
    }

    /// The last label in the block.
    pub fn last_label(&self) -> &Label {
        self.labels.last().unwrap()
    }

    /// Iterator over labels in the block.
    pub fn iter(&self) -> std::slice::Iter<'_, Label> {
        self.labels.iter()
    }

    /// Number of labels in the block.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Whether the block is empty.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

impl Ord for BasicBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.first_label().cmp(other.first_label())
    }
}

impl PartialOrd for BasicBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> IntoIterator for &'a BasicBlock {
    type Item = &'a Label;
    type IntoIter = std::slice::Iter<'a, Label>;
    fn into_iter(self) -> Self::IntoIter {
        self.labels.iter()
    }
}

/// Collect basic blocks from a CFG.
///
/// If `simplify` is false, each non-entry/non-exit label becomes its own block.
/// If `simplify` is true, consecutive labels with single-child/single-parent
/// chains are merged into one block.
pub fn collect_basic_blocks(cfg: &Cfg, simplify: bool) -> BTreeSet<BasicBlock> {
    if !simplify {
        let mut res = BTreeSet::new();
        for label in cfg.labels() {
            if *label != cfg.entry_label() && *label != cfg.exit_label() {
                res.insert(BasicBlock::new(label.clone()));
            }
        }
        return res;
    }

    let mut res = BTreeSet::new();
    let mut seen = BTreeSet::new();

    for label in cfg.labels() {
        let label = label.clone();
        if seen.contains(&label) {
            continue;
        }
        seen.insert(label.clone());

        // Skip labels that can be merged into a predecessor's block.
        if cfg.in_degree(&label) == 1 && cfg.num_siblings(&label) == 1 {
            continue;
        }

        let mut bb = BasicBlock::new(label.clone());
        let mut current = label;
        while cfg.out_degree(&current) == 1 {
            let next_label = cfg.get_child(bb.last_label());

            if seen.contains(&next_label)
                || next_label == cfg.exit_label()
                || cfg.in_degree(&next_label) != 1
            {
                break;
            }

            if *bb.first_label() == cfg.entry_label() {
                // Entry instruction is Undefined. We want to start with the real first instruction.
                bb.labels.clear();
            }
            bb.labels.push(next_label.clone());

            seen.insert(next_label.clone());
            current = next_label;
        }
        res.insert(bb);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(n: i32) -> Label {
        Label::new(n)
    }

    #[test]
    fn test_cfg_new() {
        let cfg = Cfg::new();
        assert_eq!(cfg.size(), 2); // entry + exit
        assert!(cfg.contains(&Label::entry()));
        assert!(cfg.contains(&Label::exit()));
    }

    #[test]
    fn test_cfg_insert_and_edges() {
        let mut cfg = Cfg::new();
        cfg.insert(l(1));
        cfg.insert(l(2));
        cfg.add_child(&Label::entry(), &l(1));
        cfg.add_child(&l(1), &l(2));
        cfg.add_child(&l(2), &Label::exit());

        assert_eq!(cfg.size(), 4);
        assert_eq!(cfg.out_degree(&Label::entry()), 1);
        assert_eq!(cfg.in_degree(&l(1)), 1);
        assert_eq!(*cfg.children_of(&l(1)), BTreeSet::from([l(2)]));
        assert_eq!(*cfg.parents_of(&l(2)), BTreeSet::from([l(1)]));
    }

    #[test]
    fn test_cfg_get_child_get_parent() {
        let mut cfg = Cfg::new();
        cfg.insert(l(1));
        cfg.add_child(&Label::entry(), &l(1));
        cfg.add_child(&l(1), &Label::exit());

        assert_eq!(cfg.get_child(&Label::entry()), l(1));
        assert_eq!(cfg.get_parent(&l(1)), Label::entry());
    }

    #[test]
    fn test_cfg_from_adjacency_list() {
        let cfg = cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2)]),
            (l(2), vec![Label::exit()]),
        ]);
        assert_eq!(cfg.size(), 4);
        assert_eq!(cfg.get_child(&Label::entry()), l(1));
        assert_eq!(cfg.get_child(&l(1)), l(2));
        assert_eq!(cfg.get_child(&l(2)), Label::exit());
    }

    #[test]
    fn test_basic_blocks_unsimplified() {
        let cfg = cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2)]),
            (l(2), vec![Label::exit()]),
        ]);
        let blocks = collect_basic_blocks(&cfg, false);
        assert_eq!(blocks.len(), 2); // l(1), l(2) — entry/exit excluded
    }

    #[test]
    fn test_basic_blocks_simplified() {
        let cfg = cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2)]),
            (l(2), vec![l(3)]),
            (l(3), vec![Label::exit()]),
        ]);
        let blocks = collect_basic_blocks(&cfg, true);
        // entry -> 1 -> 2 -> 3 -> exit: should merge into one block [1, 2, 3]
        assert_eq!(blocks.len(), 1);
        let bb = blocks.iter().next().unwrap();
        assert_eq!(*bb.first_label(), l(1));
        assert_eq!(*bb.last_label(), l(3));
        assert_eq!(bb.len(), 3);
    }

    #[test]
    fn test_basic_blocks_branch() {
        let cfg = cfg_from_adjacency_list(&[
            (Label::entry(), vec![l(1)]),
            (l(1), vec![l(2), l(3)]),
            (l(2), vec![Label::exit()]),
            (l(3), vec![Label::exit()]),
        ]);
        let blocks = collect_basic_blocks(&cfg, true);
        // After simplification: block [1], block [2], block [3], block [exit]
        assert_eq!(blocks.len(), 4);
    }

    #[test]
    fn test_insert_after() {
        let mut cfg = Cfg::new();
        cfg.insert(l(1));
        cfg.insert(l(2));
        cfg.add_child(&Label::entry(), &l(1));
        cfg.add_child(&l(1), &l(2));
        cfg.add_child(&l(2), &Label::exit());

        cfg.insert_after(&l(1), l(10));

        // 1 -> 10 -> 2
        assert_eq!(cfg.get_child(&l(1)), l(10));
        assert_eq!(cfg.get_child(&l(10)), l(2));
        assert_eq!(cfg.get_parent(&l(10)), l(1));
        assert_eq!(cfg.get_parent(&l(2)), l(10));
    }
}
