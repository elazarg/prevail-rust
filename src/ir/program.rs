// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Program representation and CFG construction from instruction sequences.
//!
//! Ports `src/ir/program.hpp` and `src/ir/cfg_builder.cpp`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::rc::Rc;

use crate::cfg::graph::Cfg;
use crate::cfg::label::Label;
use crate::cfg::wto::{CycleOrLabel, Wto};
use crate::ir::assertions::get_assertions;
use crate::ir::syntax::{
    ArgSingleKind, Assertion, Assume, Bin, BinOp, Call, CallKind, Condition, ConditionOp, Imm,
    IncrementLoopCounter, Instruction, InstructionSeq, LoadMapAddress, LoadMapFd, LoadPseudo, Mem,
    PseudoAddressKind, Un, UnOp, Undefined, Value,
};
use crate::ir::unmarshal::conformance_groups;
use crate::platform::EbpfPlatform;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::type_descriptors::ProgramInfo;

/// Delimiter used between stack frame components in labels.
const STACK_FRAME_DELIMITER: char = '/';

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error indicating invalid control flow in an instruction sequence.
#[derive(Debug)]
pub struct InvalidControlFlow {
    pub message: String,
}

impl fmt::Display for InvalidControlFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for InvalidControlFlow {}

fn is_tail_call_helper(call: &Call, platform: &dyn EbpfPlatform) -> bool {
    if call.kind != CallKind::Helper {
        return false;
    }
    if !platform.is_helper_usable(call.func) {
        return false;
    }
    platform.get_helper_prototype(call.func).return_type
        == crate::spec::ebpf_base::EbpfReturnType::IntegerOrNoReturnIfSucceed
}

fn is_tail_call_site(ins: &Instruction, platform: &dyn EbpfPlatform) -> bool {
    match ins {
        Instruction::Call(call) => is_tail_call_helper(call, platform),
        // At CFG-construction time callx targets are unknown.
        // Conservatively treat callx as a potential tail-call site.
        Instruction::Callx(_) => true,
        _ => false,
    }
}

fn collect_wto_labels(component: &CycleOrLabel, labels: &mut BTreeSet<Label>) {
    match component {
        CycleOrLabel::Label(label) => {
            labels.insert(label.clone());
        }
        CycleOrLabel::Cycle(cycle) => {
            for nested in cycle.iter() {
                collect_wto_labels(nested, labels);
            }
        }
    }
}

/// Enforce a global upper bound on tail-call chain length by counting
/// tail-call sites over the reachable maximal-SCC DAG.
fn validate_tail_call_chain_depth(
    prog: &Program,
    wto: &Wto,
    platform: &dyn EbpfPlatform,
) -> Result<(), InvalidControlFlow> {
    const TAIL_CALL_CHAIN_LIMIT: i32 = 33;
    const UNINITIALIZED_DEPTH: i32 = i32::MIN;

    // WTO only covers labels reachable from entry.
    let mut reachable = BTreeSet::new();
    for component in wto.iter() {
        collect_wto_labels(component, &mut reachable);
    }

    // Partition reachable labels by maximal SCC representative:
    // outermost WTO cycle head, or the label itself if not in a cycle.
    let mut maximal_scc_of: BTreeMap<Label, Label> = BTreeMap::new();
    let mut maximal_scc_ids = BTreeSet::new();
    for label in &reachable {
        let scc_id = wto
            .nesting(label)
            .outermost_head()
            .unwrap_or_else(|| label.clone());
        maximal_scc_of.insert(label.clone(), scc_id.clone());
        maximal_scc_ids.insert(scc_id);
    }

    let mut tail_sites_per_scc: BTreeMap<Label, i32> = BTreeMap::new();
    let mut representative_tail_label: BTreeMap<Label, Option<Label>> = BTreeMap::new();
    let mut dag_successors: BTreeMap<Label, BTreeSet<Label>> = BTreeMap::new();
    let mut indegree: BTreeMap<Label, i32> = BTreeMap::new();

    for scc_id in &maximal_scc_ids {
        tail_sites_per_scc.insert(scc_id.clone(), 0);
        representative_tail_label.insert(scc_id.clone(), None);
        dag_successors.insert(scc_id.clone(), BTreeSet::new());
        indegree.insert(scc_id.clone(), 0);
    }

    for label in &reachable {
        let src_scc = maximal_scc_of
            .get(label)
            .expect("reachable label missing SCC");

        if is_tail_call_site(prog.instruction_at(label), platform) {
            *tail_sites_per_scc
                .get_mut(src_scc)
                .expect("missing SCC tail count") += 1;
            let representative = representative_tail_label
                .get_mut(src_scc)
                .expect("missing SCC representative");
            if representative.is_none() {
                *representative = Some(label.clone());
            }
        }

        for child in prog.cfg().children_of(label) {
            if !reachable.contains(child) {
                continue;
            }
            let dst_scc = maximal_scc_of
                .get(child)
                .expect("reachable child missing SCC");
            if src_scc != dst_scc {
                let inserted = dag_successors
                    .get_mut(src_scc)
                    .expect("missing SCC successors")
                    .insert(dst_scc.clone());
                if inserted {
                    *indegree.get_mut(dst_scc).expect("missing SCC indegree") += 1;
                }
            }
        }
    }

    let indegree_for_sources = indegree.clone();
    let mut topo_order = Vec::with_capacity(maximal_scc_ids.len());
    for scc_id in &maximal_scc_ids {
        if *indegree.get(scc_id).expect("missing SCC indegree") == 0 {
            topo_order.push(scc_id.clone());
        }
    }

    let mut index = 0;
    while index < topo_order.len() {
        let scc_id = topo_order[index].clone();
        index += 1;
        let successors: Vec<Label> = dag_successors
            .get(&scc_id)
            .expect("missing SCC successors")
            .iter()
            .cloned()
            .collect();
        for succ in &successors {
            let entry = indegree.get_mut(succ).expect("missing SCC indegree");
            *entry -= 1;
            if *entry == 0 {
                topo_order.push(succ.clone());
            }
        }
    }

    if topo_order.len() != maximal_scc_ids.len() {
        return Err(InvalidControlFlow {
            message: "WTO-derived SCC graph must be acyclic".to_string(),
        });
    }

    let mut max_tail_depth: BTreeMap<Label, i32> = BTreeMap::new();
    let mut depth_label: BTreeMap<Label, Option<Label>> = BTreeMap::new();
    for scc_id in &maximal_scc_ids {
        max_tail_depth.insert(scc_id.clone(), UNINITIALIZED_DEPTH);
        depth_label.insert(scc_id.clone(), None);
        if *indegree_for_sources
            .get(scc_id)
            .expect("missing SCC indegree source")
            == 0
        {
            max_tail_depth.insert(
                scc_id.clone(),
                *tail_sites_per_scc
                    .get(scc_id)
                    .expect("missing SCC tail count source"),
            );
            depth_label.insert(
                scc_id.clone(),
                representative_tail_label
                    .get(scc_id)
                    .expect("missing SCC representative source")
                    .clone(),
            );
        }
    }

    for scc_id in &topo_order {
        let current_depth = *max_tail_depth.get(scc_id).expect("missing SCC max depth");
        if current_depth == UNINITIALIZED_DEPTH {
            continue;
        }
        if current_depth > TAIL_CALL_CHAIN_LIMIT {
            let at = depth_label
                .get(scc_id)
                .and_then(|x| x.clone())
                .unwrap_or_else(|| scc_id.clone());
            return Err(InvalidControlFlow {
                message: format!(
                    "tail call chain depth exceeds {} (at {})",
                    TAIL_CALL_CHAIN_LIMIT, at
                ),
            });
        }

        let successors: Vec<Label> = dag_successors
            .get(scc_id)
            .expect("missing SCC successors")
            .iter()
            .cloned()
            .collect();
        for succ in &successors {
            let candidate_depth = current_depth
                + tail_sites_per_scc
                    .get(succ)
                    .expect("missing SCC tail count successor");
            let succ_depth = *max_tail_depth
                .get(succ)
                .expect("missing SCC successor max depth");
            if candidate_depth > succ_depth {
                max_tail_depth.insert(succ.clone(), candidate_depth);
                let representative = representative_tail_label
                    .get(succ)
                    .expect("missing SCC successor representative")
                    .clone();
                if representative.is_some() {
                    depth_label.insert(succ.clone(), representative);
                } else {
                    depth_label.insert(
                        succ.clone(),
                        depth_label
                            .get(scc_id)
                            .expect("missing SCC depth label")
                            .clone(),
                    );
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

/// A verified-ready eBPF program: instructions indexed by label, with a CFG
/// and pre-computed assertions.
pub struct Program {
    /// Map from label to the instruction at that label.
    instructions: BTreeMap<Label, Instruction>,
    /// Cached assertions for each label.
    assertions: BTreeMap<Label, Vec<Assertion>>,
    /// Control-flow graph over labels.
    cfg: Cfg,
    /// Valid top-level instruction labels usable as callback entries via
    /// PTR_TO_FUNC. Populated by `from_sequence` from the CFG.
    callback_target_labels: BTreeSet<i32>,
    /// Subset of `callback_target_labels` whose body can reach a top-level Exit.
    callback_targets_with_exit: BTreeSet<i32>,
}

impl crate::fwd_analyzer::Program for Program {
    fn cfg(&self) -> &Cfg {
        &self.cfg
    }
    fn instruction_at(&self, label: &Label) -> &Instruction {
        self.instruction_at(label)
    }
    fn assertions_at(&self, label: &Label) -> &[Assertion] {
        self.assertions_at(label)
    }
}

impl Program {
    /// Returns a reference to the control-flow graph.
    pub fn cfg(&self) -> &Cfg {
        &self.cfg
    }

    /// Returns a reference to the instruction map.
    pub fn instructions(&self) -> &BTreeMap<Label, Instruction> {
        &self.instructions
    }

    /// Returns an iterator over all labels in the CFG (including entry and exit).
    pub fn labels(&self) -> impl Iterator<Item = &Label> {
        self.cfg.labels()
    }

    /// Returns a reference to the instruction at the given label.
    ///
    /// Panics if the label is not found in the CFG.
    pub fn instruction_at(&self, label: &Label) -> &Instruction {
        self.instructions
            .get(label)
            .unwrap_or_else(|| panic!("Label {} not found in the CFG", label))
    }

    /// Returns a mutable reference to the instruction at the given label.
    ///
    /// Panics if the label is not found in the CFG.
    pub fn instruction_at_mut(&mut self, label: &Label) -> &mut Instruction {
        self.instructions
            .get_mut(label)
            .unwrap_or_else(|| panic!("Label {} not found in the CFG", label))
    }

    /// Returns the assertions at the given label.
    ///
    /// Panics if the label is not found in the CFG.
    pub fn assertions_at(&self, label: &Label) -> &[Assertion] {
        self.assertions
            .get(label)
            .unwrap_or_else(|| panic!("Label {} not found in the CFG", label))
    }

    /// Top-level instruction labels usable as callback entries via PTR_TO_FUNC.
    pub fn callback_target_labels(&self) -> &BTreeSet<i32> {
        &self.callback_target_labels
    }

    /// Subset of `callback_target_labels` whose body can reach a top-level Exit.
    pub fn callback_targets_with_exit(&self) -> &BTreeSet<i32> {
        &self.callback_targets_with_exit
    }

    /// Build a `Program` from an instruction sequence.
    ///
    /// This converts the linear sequence into a deterministic CFG, optionally
    /// inserts loop counters (if `check_for_termination` is set), and annotates
    /// each label with its assertions.
    pub fn from_sequence(
        inst_seq: &InstructionSeq,
        info: &mut ProgramInfo,
        platform: &dyn EbpfPlatform,
        options: &EbpfVerifierOptions,
    ) -> Result<Program, InvalidControlFlow> {
        options
            .validate()
            .map_err(|message| InvalidControlFlow { message })?;
        let mut resolved_kfunc_calls = ResolvedKfuncCalls::new();
        validate_instruction_feature_support(inst_seq, info, platform, &mut resolved_kfunc_calls)?;

        // Convert the instruction sequence to a deterministic control-flow graph.
        let mut builder = instruction_seq_to_cfg(
            inst_seq,
            info,
            options.must_have_exit,
            options.runtime.max_call_stack_frames,
            &resolved_kfunc_calls,
        )?;
        let wto = Wto::new(&builder.prog.cfg);

        validate_tail_call_chain_depth(&builder.prog, &wto, platform)?;

        // Record valid callback targets for PTR_TO_FUNC:
        // top-level concrete instruction labels (no stack-frame prefix, no jump labels, no Exit).
        let mut callback_target_labels = BTreeSet::new();
        for label in builder.prog.labels() {
            if *label == Label::entry()
                || *label == Label::exit()
                || label.isjump()
                || !label.stack_frame_prefix.is_empty()
            {
                continue;
            }
            if matches!(builder.prog.instruction_at(label), Instruction::Exit(_)) {
                continue;
            }
            callback_target_labels.insert(label.from);
        }

        // Callback bodies must be able to reach a top-level Exit.
        let has_reachable_top_level_exit = |start: &Label, prog: &Program| -> bool {
            let mut seen = BTreeSet::new();
            let mut worklist = vec![start.clone()];
            while let Some(label) = worklist.pop() {
                if !seen.insert(label.clone()) {
                    continue;
                }
                if label == Label::exit() {
                    return true;
                }
                if label != Label::entry()
                    && prog.cfg().contains(&label)
                    && matches!(prog.instruction_at(&label), Instruction::Exit(_))
                    && label.stack_frame_prefix.is_empty()
                {
                    return true;
                }
                for child in prog.cfg().children_of(&label) {
                    worklist.push(child.clone());
                }
            }
            false
        };

        let mut callback_targets_with_exit = BTreeSet::new();
        for label_num in &callback_target_labels {
            let label = Label::new(*label_num);
            if has_reachable_top_level_exit(&label, &builder.prog) {
                callback_targets_with_exit.insert(*label_num);
            }
        }
        builder.prog.callback_target_labels = callback_target_labels;
        builder.prog.callback_targets_with_exit = callback_targets_with_exit;

        // Detect loops using Weak Topological Ordering (WTO) and insert counters
        // at loop entry points. WTO provides a hierarchical decomposition of the
        // CFG that identifies all strongly connected components (cycles) and their
        // entry points. These entry points serve as natural locations for loop
        // counters that help verify program termination.
        if options.runtime.check_for_termination {
            let mut loop_heads = Vec::new();
            wto.for_each_loop_head(&mut |label| loop_heads.push(label.clone()));
            for label in loop_heads {
                let counter_label = Label::make_increment_counter(&label);
                let ins = Instruction::IncrementLoopCounter(IncrementLoopCounter {
                    name: label.clone(),
                });
                builder.insert_after(&label, counter_label, ins);
            }
        }

        // Annotate the CFG by explicitly adding assertions before every instruction.
        let labels: Vec<Label> = builder.prog.cfg.labels().cloned().collect();
        for label in &labels {
            let ins = builder.prog.instruction_at(label);
            let assertions = get_assertions(ins, info, &options.runtime, &Some(label.clone()));
            builder.set_assertions(label, assertions);
        }

        Ok(builder.prog)
    }
}

// ---------------------------------------------------------------------------
// CfgBuilder — private construction helper
// ---------------------------------------------------------------------------

/// Builder for constructing a `Program` from an instruction sequence.
///
/// Wraps a `Program` under construction and provides mutation methods
/// that keep the CFG, instruction map, and assertion map in sync.
struct CfgBuilder {
    prog: Program,
}

impl CfgBuilder {
    /// Create a new builder with an empty program (entry + exit only).
    fn new() -> Self {
        let mut instructions = BTreeMap::new();
        instructions.insert(
            Label::entry(),
            Instruction::Undefined(Undefined { opcode: 0 }),
        );
        instructions.insert(
            Label::exit(),
            Instruction::Undefined(Undefined { opcode: 0 }),
        );

        let mut assertions = BTreeMap::new();
        assertions.insert(Label::entry(), Vec::new());
        assertions.insert(Label::exit(), Vec::new());

        CfgBuilder {
            prog: Program {
                instructions,
                assertions,
                cfg: Cfg::new(),
                callback_target_labels: BTreeSet::new(),
                callback_targets_with_exit: BTreeSet::new(),
            },
        }
    }

    /// Insert a new label with its instruction. Panics if the label already exists.
    fn insert(&mut self, label: Label, ins: Instruction) {
        if self.prog.cfg.contains(&label) {
            panic!("Label {} already exists", label);
        }
        self.prog.cfg.insert(label.clone());
        self.prog.instructions.insert(label, ins);
    }

    /// Insert a new label after `prev_label`, splicing it into all of prev's
    /// outgoing edges: prev -> new_label -> (all former children of prev).
    fn insert_after(&mut self, prev_label: &Label, new_label: Label, ins: Instruction) {
        assert_ne!(
            *prev_label, new_label,
            "Cannot insert after the same label {}",
            new_label
        );
        self.prog.instructions.insert(new_label.clone(), ins);
        self.prog.cfg.insert_after(prev_label, new_label);
    }

    /// Insert a jump label on the edge from `from` to `to`, with the given
    /// instruction (typically an `Assume`). Returns the new jump label.
    fn insert_jump(&mut self, from: &Label, to: &Label, ins: Instruction) -> Label {
        let jump_label = Label::make_jump(from, to);
        if self.prog.cfg.contains(&jump_label) {
            panic!("Jump label {} already exists", jump_label);
        }
        self.insert(jump_label.clone(), ins);
        self.add_child(from, &jump_label);
        self.add_child(&jump_label, to);
        jump_label
    }

    /// Add a directed edge from `a` to `b`.
    fn add_child(&mut self, a: &Label, b: &Label) {
        self.prog.cfg.add_child(a, b);
    }

    /// Remove a directed edge from `a` to `b`.
    ///
    /// NOTE: This requires `Cfg::remove_child` to be available. If it is not
    /// yet implemented on `Cfg`, this will need to be added there.
    fn remove_child(&mut self, a: &Label, b: &Label) {
        self.prog.cfg.remove_child(a, b);
    }

    /// Set the assertions for a given label. Panics if the label is not in the CFG.
    fn set_assertions(&mut self, label: &Label, assertions: Vec<Assertion>) {
        if !self.prog.cfg.contains(label) {
            panic!("Label {} not found in the CFG", label);
        }
        self.prog.assertions.insert(label.clone(), assertions);
    }
}

// ---------------------------------------------------------------------------
// Free functions: condition reversal, fall-through detection
// ---------------------------------------------------------------------------

/// Get the inverse of a comparison operator.
pub fn reverse_op(op: ConditionOp) -> ConditionOp {
    match op {
        ConditionOp::EQ => ConditionOp::NE,
        ConditionOp::NE => ConditionOp::EQ,

        ConditionOp::GE => ConditionOp::LT,
        ConditionOp::LT => ConditionOp::GE,

        ConditionOp::SGE => ConditionOp::SLT,
        ConditionOp::SLT => ConditionOp::SGE,

        ConditionOp::LE => ConditionOp::GT,
        ConditionOp::GT => ConditionOp::LE,

        ConditionOp::SLE => ConditionOp::SGT,
        ConditionOp::SGT => ConditionOp::SLE,

        ConditionOp::SET => ConditionOp::NSET,
        ConditionOp::NSET => ConditionOp::SET,
    }
}

/// Get the inverse of a full condition (flips the operator, keeps operands).
pub fn reverse_condition(cond: &Condition) -> Condition {
    Condition {
        op: reverse_op(cond.op),
        left: cond.left,
        right: cond.right,
        is64: cond.is64,
    }
}

/// Returns true if the instruction falls through to the next instruction
/// (i.e., it is not a terminator like `Exit` or an unconditional `Jmp`).
pub fn has_fall(ins: &Instruction) -> bool {
    match ins {
        Instruction::Exit(_) => false,
        Instruction::Jmp(jmp) => {
            // Unconditional jump does not fall through; conditional jump does.
            jmp.cond.is_some()
        }
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RejectKind {
    Capability,
}

#[derive(Clone, Debug)]
struct RejectionReason {
    kind: RejectKind,
    detail: String,
}

fn supports(groups: u32, group: u32) -> bool {
    (groups & group) == group
}

fn un_requires_base64(un: &Un) -> bool {
    matches!(un.op, UnOp::BE64 | UnOp::LE64 | UnOp::SWAP64)
}

/// Check that a conformance group pair (64-bit and 32-bit variants) is supported,
/// selecting the variant based on `need_64`. Returns a rejection reason if not supported.
fn require_group_pair(
    groups: u32,
    need_64: bool,
    group_64: u32,
    name_64: &str,
    group_32: u32,
    name_32: &str,
) -> Option<RejectionReason> {
    let (group, name) = if need_64 {
        (group_64, name_64)
    } else {
        (group_32, name_32)
    };
    if !supports(groups, group) {
        Some(RejectionReason {
            kind: RejectKind::Capability,
            detail: format!("requires conformance group {name}"),
        })
    } else {
        None
    }
}

fn require_base(groups: u32, need_64: bool) -> Option<RejectionReason> {
    require_group_pair(
        groups,
        need_64,
        conformance_groups::BASE64,
        "base64",
        conformance_groups::BASE32,
        "base32",
    )
}

fn check_instruction_feature_support(
    ins: &Instruction,
    info: &ProgramInfo,
) -> Option<RejectionReason> {
    let reject_capability = |detail: &str| RejectionReason {
        kind: RejectKind::Capability,
        detail: detail.to_string(),
    };
    let groups = info.supported_conformance_groups;

    if let Instruction::Call(call) = ins
        && !call.is_supported
    {
        return Some(reject_capability(
            call.unsupported_reason.to_string().as_str(),
        ));
    }
    if matches!(ins, Instruction::Callx(_)) && !supports(groups, conformance_groups::CALLX) {
        return Some(reject_capability("requires conformance group callx"));
    }
    if (matches!(ins, Instruction::Call(_))
        || matches!(ins, Instruction::CallLocal(_))
        || matches!(ins, Instruction::Callx(_))
        || matches!(ins, Instruction::CallBtf(_))
        || matches!(ins, Instruction::Exit(_)))
        && !supports(groups, conformance_groups::BASE32)
    {
        return Some(reject_capability("requires conformance group base32"));
    }
    if let Instruction::Bin(bin) = ins {
        if let r @ Some(_) = require_base(groups, bin.is64) {
            return r;
        }
        if matches!(
            bin.op,
            BinOp::MUL | BinOp::UDIV | BinOp::UMOD | BinOp::SDIV | BinOp::SMOD
        ) && let r @ Some(_) = require_group_pair(
            groups,
            bin.is64,
            conformance_groups::DIVMUL64,
            "divmul64",
            conformance_groups::DIVMUL32,
            "divmul32",
        ) {
            return r;
        }
    }
    if let Instruction::Un(un) = ins
        && let r @ Some(_) = require_base(groups, un.is64 || un_requires_base64(un))
    {
        return r;
    }
    if let Instruction::Jmp(jmp) = ins {
        let need_base64 = jmp.cond.as_ref().is_some_and(|c| c.is64);
        if let r @ Some(_) = require_base(groups, need_base64) {
            return r;
        }
    }
    if let Instruction::LoadPseudo(lp) = ins {
        if !supports(groups, conformance_groups::BASE64) {
            return Some(reject_capability("requires conformance group base64"));
        }
        match lp.addr.kind {
            // All pseudo address kinds are lowered during CFG construction.
            PseudoAddressKind::VariableAddr
            | PseudoAddressKind::CodeAddr
            | PseudoAddressKind::MapByIdx
            | PseudoAddressKind::MapValueByIdx => {}
        }
    }
    if (matches!(ins, Instruction::LoadMapFd(_)) || matches!(ins, Instruction::LoadMapAddress(_)))
        && !supports(groups, conformance_groups::BASE64)
    {
        return Some(reject_capability("requires conformance group base64"));
    }
    if let Instruction::Mem(Mem {
        access, is_signed, ..
    }) = ins
    {
        if let r @ Some(_) = require_base(groups, access.width.bytes() == 8) {
            return r;
        }
        if *is_signed && !supports(groups, conformance_groups::BASE64) {
            return Some(reject_capability("requires conformance group base64"));
        }
    }
    if matches!(ins, Instruction::Packet(_)) && !supports(groups, conformance_groups::PACKET) {
        return Some(reject_capability("requires conformance group packet"));
    }
    if let Instruction::Atomic(atomic) = ins
        && let r @ Some(_) = require_group_pair(
            groups,
            atomic.access.width.bytes() == 8,
            conformance_groups::ATOMIC64,
            "atomic64",
            conformance_groups::ATOMIC32,
            "atomic32",
        )
    {
        return r;
    }
    None
}

type ResolvedKfuncCalls = BTreeMap<Label, Call>;

fn validate_instruction_feature_support(
    insts: &InstructionSeq,
    info: &ProgramInfo,
    platform: &dyn EbpfPlatform,
    resolved_kfunc_calls: &mut ResolvedKfuncCalls,
) -> Result<(), InvalidControlFlow> {
    for (label, inst, _) in insts {
        if let Some(reason) = check_instruction_feature_support(inst, info) {
            return Err(InvalidControlFlow {
                message: match reason.kind {
                    RejectKind::Capability => format!("rejected: {} (at {})", reason.detail, label),
                },
            });
        }
        if let Instruction::CallBtf(call_btf) = inst {
            let call = platform
                .resolve_kfunc_call(call_btf.btf_id, info)
                .map_err(|why_not| InvalidControlFlow {
                    message: format!("not implemented: {} (at {})", why_not, label),
                })?;
            resolved_kfunc_calls.insert(label.clone(), call);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// instruction_seq_to_cfg
// ---------------------------------------------------------------------------

fn merge_imm32_to_u64(lo: i32, hi: i32) -> u64 {
    (lo as u32 as u64) | ((hi as u32 as u64) << 32)
}

/// Resolve a `LoadPseudo` to a concrete instruction before abstract interpretation.
fn resolve_pseudo_load(
    pseudo: &LoadPseudo,
    info: &ProgramInfo,
) -> Result<Instruction, InvalidControlFlow> {
    if matches!(pseudo.addr.kind, PseudoAddressKind::VariableAddr) {
        return Ok(Instruction::Bin(Bin {
            op: BinOp::MOV,
            dst: pseudo.dst,
            v: Value::Imm(Imm {
                v: merge_imm32_to_u64(pseudo.addr.imm, pseudo.addr.next_imm),
            }),
            is64: true,
            lddw: true,
        }));
    }

    let descriptors = &info.map_descriptors;
    if pseudo.addr.imm < 0 || (pseudo.addr.imm as usize) >= descriptors.len() {
        return Err(InvalidControlFlow {
            message: format!(
                "invalid map index {} (have {} maps)",
                pseudo.addr.imm,
                descriptors.len()
            ),
        });
    }
    let mapfd = descriptors[pseudo.addr.imm as usize].original_fd;
    match pseudo.addr.kind {
        PseudoAddressKind::MapByIdx => Ok(Instruction::LoadMapFd(LoadMapFd {
            dst: pseudo.dst,
            mapfd,
        })),
        PseudoAddressKind::MapValueByIdx => Ok(Instruction::LoadMapAddress(LoadMapAddress {
            dst: pseudo.dst,
            mapfd,
            offset: pseudo.addr.next_imm,
        })),
        _ => unreachable!("pseudo kind handled earlier: {:?}", pseudo.addr.kind),
    }
}

/// Convert an instruction sequence to a control-flow graph (CFG).
///
/// This builds the CFG in two passes:
/// 1. Add all instructions as nodes and wire up edges (jumps, fall-throughs).
/// 2. Inline function macros (`CallLocal` instructions).
fn instruction_seq_to_cfg(
    insts: &InstructionSeq,
    info: &ProgramInfo,
    must_have_exit: bool,
    max_call_stack_frames: i32,
    resolved_kfunc_calls: &ResolvedKfuncCalls,
) -> Result<CfgBuilder, InvalidControlFlow> {
    let mut builder = CfgBuilder::new();

    // First, add all instructions to the CFG without connecting.
    for (label, inst, _) in insts {
        if matches!(inst, Instruction::Undefined(_)) {
            continue;
        }
        if matches!(inst, Instruction::CallBtf(_)) {
            let call = resolved_kfunc_calls
                .get(label)
                .ok_or_else(|| InvalidControlFlow {
                    message: format!(
                        "internal error: missing validated kfunc resolution (at {})",
                        label
                    ),
                })?
                .clone();
            builder.insert(label.clone(), Instruction::Call(call));
        } else if let Instruction::LoadPseudo(pseudo) = inst {
            if pseudo.addr.kind == PseudoAddressKind::CodeAddr {
                // Keep CODE_ADDR pseudo intact so abstract transformation can type it as T_FUNC.
                builder.insert(label.clone(), inst.clone());
            } else {
                // Resolve other pseudo loads to concrete instructions.
                builder.insert(label.clone(), resolve_pseudo_load(pseudo, info)?);
            }
        } else {
            builder.insert(label.clone(), inst.clone());
        }
    }

    if insts.is_empty() {
        return Err(InvalidControlFlow {
            message: "empty instruction sequence".to_string(),
        });
    }

    // Connect entry to the first instruction.
    let first_label = &insts[0].0;
    builder.add_child(&Label::entry(), first_label);

    // Do a first pass ignoring all function macro calls.
    for i in 0..insts.len() {
        let (label, inst, _) = &insts[i];

        if matches!(inst, Instruction::Undefined(_)) {
            continue;
        }

        // Determine the fall-through target.
        let fallthrough = if i + 1 < insts.len() {
            insts[i + 1].0.clone()
        } else {
            if has_fall(inst) && must_have_exit {
                return Err(InvalidControlFlow {
                    message: "fallthrough in last instruction".to_string(),
                });
            }
            Label::exit()
        };

        if let Instruction::Jmp(jmp) = inst
            && let Some(cond) = &jmp.cond
        {
            // Conditional jump.
            let target_label = &jmp.target;
            if *target_label == fallthrough {
                // Target equals fallthrough — just add one edge.
                builder.add_child(label, &fallthrough);
                // Also handle the Exit edge below (via the exit check).
            } else {
                if !builder.prog.cfg.contains(target_label) {
                    return Err(InvalidControlFlow {
                        message: format!("jump to undefined label {}", target_label),
                    });
                }
                // Insert Assume nodes on each branch edge.
                builder.insert_jump(
                    label,
                    target_label,
                    Instruction::Assume(Assume {
                        cond: cond.clone(),
                        is_implicit: true,
                    }),
                );
                builder.insert_jump(
                    label,
                    &fallthrough,
                    Instruction::Assume(Assume {
                        cond: reverse_condition(cond),
                        is_implicit: true,
                    }),
                );
            }
        } else if let Instruction::Jmp(jmp) = inst {
            // Unconditional jump.
            builder.add_child(label, &jmp.target);
        } else if has_fall(inst) {
            builder.add_child(label, &fallthrough);
        }

        // Exit instructions also get an edge to the exit label.
        if matches!(inst, Instruction::Exit(_)) {
            builder.add_child(label, &Label::exit());
        }
    }

    // Now replace macros. We have to do this as a second pass so that
    // we only add new nodes that are actually reachable, based on the
    // results of the first pass.
    let macro_labels: Vec<(Label, Label)> = insts
        .iter()
        .filter_map(|(label, inst, _)| {
            if let Instruction::CallLocal(call_local) = inst {
                Some((label.clone(), call_local.target.clone()))
            } else {
                None
            }
        })
        .collect();

    for (label, target) in macro_labels {
        add_cfg_nodes(&mut builder, &label, &target, max_call_stack_frames)?;
    }

    Ok(builder)
}

// ---------------------------------------------------------------------------
// add_cfg_nodes — inline function macros
// ---------------------------------------------------------------------------

/// Update a control-flow graph to inline function macros.
///
/// Walks the transitive closure of CFG nodes starting at `entry_label` and
/// ending at any exit instruction, cloning them into the caller's stack frame.
fn add_cfg_nodes(
    builder: &mut CfgBuilder,
    caller_label: &Label,
    entry_label: &Label,
    max_call_stack_frames: i32,
) -> Result<(), InvalidControlFlow> {
    // Guard at the entry so the check applies uniformly to all invocations
    // (including the top-level one), matching upstream PR #1070.
    let caller_label_str = format!("{}", caller_label);
    let stack_frame_depth = caller_label_str
        .chars()
        .filter(|&c| c == STACK_FRAME_DELIMITER)
        .count() as i32
        + 2;
    if stack_frame_depth > max_call_stack_frames {
        return Err(InvalidControlFlow {
            message: "too many call stack frames".to_string(),
        });
    }

    let mut first = true;

    // Get the label of the node to go to on returning from the macro.
    let exit_to_label = builder.prog.cfg.get_child(caller_label);

    // Construct the variable prefix to use for the new stack frame
    // and store a copy in the CallLocal instruction since the instruction-specific
    // labels may only exist until the CFG is simplified.
    let stack_frame_prefix = format!("{}", caller_label);
    if let Instruction::CallLocal(pcall) = builder.prog.instruction_at_mut(caller_label) {
        pcall.stack_frame_prefix = Rc::from(stack_frame_prefix.as_str());
    }

    // Walk the transitive closure of CFG nodes starting at entry_label and ending at
    // any exit instruction.
    let mut macro_labels = BTreeSet::new();
    macro_labels.insert(entry_label.clone());
    let mut seen_labels = BTreeSet::new();
    seen_labels.insert(entry_label.clone());

    while let Some(macro_label) = macro_labels.pop_first() {
        if stack_frame_prefix == macro_label.stack_frame_prefix {
            return Err(InvalidControlFlow {
                message: format!("{}: illegal recursion", stack_frame_prefix),
            });
        }

        // Clone the macro block into a new block with the new stack frame prefix.
        let label = Label::new_full(macro_label.from, macro_label.to, stack_frame_prefix.clone());
        let mut inst = builder.prog.instruction_at(&macro_label).clone();
        match &mut inst {
            Instruction::Exit(pexit) => {
                pexit.stack_frame_prefix = Rc::from(label.stack_frame_prefix.as_str());
            }
            Instruction::Call(pcall) => {
                pcall.stack_frame_prefix = Rc::from(label.stack_frame_prefix.as_str());
            }
            _ => {}
        }
        builder.insert(label.clone(), inst);

        if first {
            // Add an edge from the caller to the new block.
            first = false;
            builder.add_child(caller_label, &label);
        }

        // Add an edge from any other predecessors.
        let prev_macro_nodes: Vec<Label> = builder
            .prog
            .cfg
            .parents_of(&macro_label)
            .iter()
            .cloned()
            .collect();
        for prev_macro_label in &prev_macro_nodes {
            let prev_label = Label::new_full(
                prev_macro_label.from,
                prev_macro_label.to,
                stack_frame_prefix.clone(),
            );
            // Check if prev_label exists in the CFG.
            if builder.prog.cfg.contains(&prev_label) {
                builder.add_child(&prev_label, &label);
            }
        }

        // Walk all successor nodes.
        let next_macro_nodes: Vec<Label> = builder
            .prog
            .cfg
            .children_of(&macro_label)
            .iter()
            .cloned()
            .collect();
        for next_macro_label in &next_macro_nodes {
            if *next_macro_label == Label::exit() {
                // This is an exit transition, so add edge to the block to execute
                // upon returning from the macro.
                builder.add_child(&label, &exit_to_label);
            } else if !seen_labels.contains(next_macro_label) {
                // Push any other unprocessed successor label onto the list to be processed.
                macro_labels.insert(next_macro_label.clone());
                seen_labels.insert(next_macro_label.clone());
            }
        }
    }

    // Remove the original edge from the caller node to its successor,
    // since processing now goes through the function macro instead.
    builder.remove_child(caller_label, &exit_to_label);

    // Finally, recurse to replace any nested function macros. The depth
    // guard at the entry of this function covers all call sites.
    let seen_labels_snapshot: Vec<Label> = seen_labels.into_iter().collect();
    for macro_label in &seen_labels_snapshot {
        let label = Label::new_full(macro_label.from, macro_label.to, caller_label_str.clone());
        if builder.prog.cfg.contains(&label)
            && let Instruction::CallLocal(cl) = builder.prog.instruction_at(&label)
        {
            let target = cl.target.clone();
            add_cfg_nodes(builder, &label, &target, max_call_stack_frames)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Get the type string of an instruction. Most of these type names are also
/// statistics header labels.
pub fn instype(ins: &Instruction) -> &'static str {
    match ins {
        Instruction::Call(call) => {
            if call.is_map_lookup {
                "call_1"
            } else if call.pairs.is_empty() {
                if call
                    .singles
                    .iter()
                    .all(|kr| kr.kind == ArgSingleKind::Anything)
                {
                    "call_nomem"
                } else {
                    "call_mem"
                }
            } else {
                "call_mem"
            }
        }
        Instruction::Callx(_) => "callx",
        Instruction::CallBtf(_) => "call_btf",
        Instruction::Mem(mem) => {
            if mem.is_load {
                "load"
            } else {
                "store"
            }
        }
        Instruction::Atomic(_) => "load_store",
        Instruction::Packet(_) => "packet_access",
        Instruction::Bin(bin) => match bin.op {
            BinOp::MOV | BinOp::MOVSX8 | BinOp::MOVSX16 | BinOp::MOVSX32 => "assign",
            _ => "arith",
        },
        Instruction::Un(_) => "arith",
        Instruction::LoadMapFd(_) => "assign",
        Instruction::LoadMapAddress(_) => "assign",
        Instruction::LoadPseudo(_) => "assign",
        Instruction::Assume(_) => "assume",
        _ => "other",
    }
}

/// Returns the list of statistics header keys.
pub fn stats_headers() -> Vec<&'static str> {
    vec![
        "instructions",
        "joins",
        "other",
        "jumps",
        "assign",
        "arith",
        "load",
        "store",
        "load_store",
        "packet_access",
        "call_1",
        "call_mem",
        "call_btf",
        "call_nomem",
        "reallocate",
        "map_in_map",
        "arith64",
        "arith32",
    ]
}

/// Collect statistics about the instructions in a program.
pub fn collect_stats(prog: &Program) -> BTreeMap<String, i32> {
    let mut res = BTreeMap::new();
    for h in stats_headers() {
        res.insert(h.to_string(), 0);
    }
    for label in prog.labels() {
        *res.get_mut("instructions").unwrap() += 1;
        let cmd = prog.instruction_at(label);

        if let Instruction::LoadMapFd(lmf) = cmd
            && lmf.mapfd == -1
        {
            res.insert("map_in_map".to_string(), 1);
        }
        if let Instruction::Call(call) = cmd
            && call.reallocate_packet
        {
            res.insert("reallocate".to_string(), 1);
        }
        if let Instruction::Bin(bin) = cmd {
            let key = if bin.is64 { "arith64" } else { "arith32" };
            *res.get_mut(key).unwrap() += 1;
        }

        let typ = instype(cmd);
        *res.get_mut(typ).unwrap() += 1;

        if prog.cfg().in_degree(label) > 1 {
            *res.get_mut("joins").unwrap() += 1;
        }
        if prog.cfg().out_degree(label) > 1 {
            *res.get_mut("jumps").unwrap() += 1;
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::label::Label;
    use crate::ir::syntax::{
        Bin, BinOp, Call, CallBtf, CallKind, Exit, Instruction, InstructionSeq, Jmp, LoadMapFd,
        LoadPseudo, PseudoAddress, PseudoAddressKind, Reg, Value,
    };
    use crate::linux::linux_platform::LinuxPlatform;
    use crate::spec::config::EbpfVerifierOptions;
    use crate::spec::type_descriptors::{EbpfMapDescriptor, ProgramInfo};
    use std::rc::Rc;

    fn create_simple_seq() -> InstructionSeq {
        // 0: MOV r1, 10
        // 1: EXIT
        vec![
            (
                Label::new(0),
                Instruction::Bin(Bin {
                    op: BinOp::MOV,
                    dst: Reg { v: 1 },
                    v: Value::Imm(crate::ir::syntax::Imm { v: 10 }),
                    is64: true,
                    lddw: false,
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(crate::ir::syntax::Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
        ]
    }

    #[test]
    fn test_program_from_sequence_simple() {
        let seq = create_simple_seq();
        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();

        let prog =
            Program::from_sequence(&seq, &mut info, &platform, &opts).expect("Result should be Ok");

        // Check CFG structure
        // Entry -> 0 -> 1 -> Exit
        let entry = Label::entry();
        let exit = Label::exit();
        let l0 = Label::new(0);
        let l1 = Label::new(1);

        assert!(prog.cfg.contains(&entry));
        assert!(prog.cfg.contains(&exit));
        assert!(prog.cfg.contains(&l0));
        assert!(prog.cfg.contains(&l1));

        // Edges
        // Entry -> 0
        let children_entry = prog.cfg.children_of(&entry);
        assert!(children_entry.contains(&l0));

        // 0 -> 1 (fallthrough)
        let children_0 = prog.cfg.children_of(&l0);
        assert!(children_0.contains(&l1));

        // 1 -> Exit
        let children_1 = prog.cfg.children_of(&l1);
        assert!(children_1.contains(&exit));
    }

    #[test]
    fn test_program_empty_error() {
        let seq: InstructionSeq = Vec::new();
        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();

        let res = Program::from_sequence(&seq, &mut info, &platform, &opts);
        assert!(res.is_err());
    }

    #[test]
    fn test_lddw_variable_addr_is_lowered_to_mov_imm64() {
        let seq = vec![
            (
                Label::new(0),
                Instruction::LoadPseudo(LoadPseudo {
                    dst: Reg { v: 1 },
                    addr: PseudoAddress {
                        kind: PseudoAddressKind::VariableAddr,
                        imm: 0x5566_7788_u32 as i32,
                        next_imm: 0x1122_3344_u32 as i32,
                    },
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
        ];

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        let program =
            Program::from_sequence(&seq, &mut info, &platform, &opts).expect("expected valid CFG");

        let lowered = program.instruction_at(&Label::new(0));
        match lowered {
            Instruction::Bin(bin) => {
                assert_eq!(bin.op, BinOp::MOV);
                assert!(bin.is64);
                assert!(bin.lddw);
                assert_eq!(bin.dst, Reg { v: 1 });
                assert_eq!(
                    bin.v,
                    Value::Imm(crate::ir::syntax::Imm {
                        v: 0x1122_3344_5566_7788
                    })
                );
            }
            _ => panic!("expected LoadPseudo to be lowered into Bin::MOV"),
        }
    }

    #[test]
    fn test_lddw_code_addr_is_preserved() {
        let seq = vec![
            (
                Label::new(0),
                Instruction::LoadPseudo(LoadPseudo {
                    dst: Reg { v: 2 },
                    addr: PseudoAddress {
                        kind: PseudoAddressKind::CodeAddr,
                        imm: 11,
                        next_imm: 0,
                    },
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
        ];

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        let program =
            Program::from_sequence(&seq, &mut info, &platform, &opts).expect("expected valid CFG");

        match program.instruction_at(&Label::new(0)) {
            Instruction::LoadPseudo(pseudo) => {
                assert_eq!(pseudo.dst, Reg { v: 2 });
                assert_eq!(pseudo.addr.kind, PseudoAddressKind::CodeAddr);
                assert_eq!(pseudo.addr.imm, 11);
            }
            other => panic!("expected code_addr LoadPseudo to be preserved, got {other:?}"),
        }
    }

    #[test]
    fn test_callback_target_sets_track_reachable_exit() {
        let seq = vec![
            (
                Label::new(0),
                Instruction::Bin(Bin {
                    op: BinOp::MOV,
                    dst: Reg { v: 0 },
                    v: Value::Imm(crate::ir::syntax::Imm { v: 0 }),
                    is64: true,
                    lddw: false,
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
            (
                Label::new(2),
                Instruction::Jmp(Jmp {
                    cond: None,
                    target: Label::new(2),
                }),
                None,
            ),
        ];

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        let prog =
            Program::from_sequence(&seq, &mut info, &platform, &opts).expect("expected valid CFG");

        assert!(prog.callback_target_labels().contains(&0));
        assert!(prog.callback_target_labels().contains(&2));

        assert!(prog.callback_targets_with_exit().contains(&0));
        assert!(!prog.callback_targets_with_exit().contains(&2));
    }

    #[test]
    fn test_tail_call_chain_depth_above_33_is_rejected() {
        let mut seq: InstructionSeq = Vec::new();
        for i in 0..34 {
            seq.push((
                Label::new(i),
                Instruction::Call(Call {
                    func: 12,
                    kind: CallKind::Helper,
                    name: Rc::from("tail_call"),
                    is_supported: true,
                    unsupported_reason: Rc::from(""),
                    is_map_lookup: false,
                    reallocate_packet: false,
                    return_ptr_type: None,
                    return_nullable: false,
                    singles: vec![],
                    pairs: vec![],
                    stack_frame_prefix: Rc::from(""),
                    alloc_size_reg: None,
                }),
                None,
            ));
        }
        seq.push((
            Label::new(34),
            Instruction::Exit(Exit {
                stack_frame_prefix: Rc::from(""),
            }),
            None,
        ));

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        let err = match Program::from_sequence(&seq, &mut info, &platform, &opts) {
            Ok(_) => panic!("must reject >33 tail calls"),
            Err(err) => err,
        };
        assert!(err.message.contains("tail call chain depth exceeds 33"));
    }

    #[test]
    fn test_tail_call_chain_depth_of_33_is_accepted() {
        let mut seq: InstructionSeq = Vec::new();
        for i in 0..33 {
            seq.push((
                Label::new(i),
                Instruction::Call(Call {
                    func: 12,
                    kind: CallKind::Helper,
                    name: Rc::from("tail_call"),
                    is_supported: true,
                    unsupported_reason: Rc::from(""),
                    is_map_lookup: false,
                    reallocate_packet: false,
                    return_ptr_type: None,
                    return_nullable: false,
                    singles: vec![],
                    pairs: vec![],
                    stack_frame_prefix: Rc::from(""),
                    alloc_size_reg: None,
                }),
                None,
            ));
        }
        seq.push((
            Label::new(33),
            Instruction::Exit(Exit {
                stack_frame_prefix: Rc::from(""),
            }),
            None,
        ));

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        Program::from_sequence(&seq, &mut info, &platform, &opts)
            .expect("depth 33 should be accepted");
    }

    #[test]
    fn test_lddw_map_by_index_still_resolves() {
        let seq = vec![
            (
                Label::new(0),
                Instruction::LoadPseudo(LoadPseudo {
                    dst: Reg { v: 1 },
                    addr: PseudoAddress {
                        kind: PseudoAddressKind::MapByIdx,
                        imm: 0,
                        next_imm: 0,
                    },
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
        ];

        let mut info = ProgramInfo::default();
        info.map_descriptors.push(EbpfMapDescriptor {
            original_fd: 123,
            map_type: 1,
            key_size: 4,
            value_size: 8,
            max_entries: 16,
            inner_map_fd: 0,
            name: String::new(),
            is_inner_map_template: false,
        });
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        let program = Program::from_sequence(&seq, &mut info, &platform, &opts)
            .expect("map-by-index must resolve");
        assert_eq!(
            program.instruction_at(&Label::new(0)),
            &Instruction::LoadMapFd(LoadMapFd {
                dst: Reg { v: 1 },
                mapfd: 123
            })
        );
    }

    #[test]
    fn test_call_btf_unknown_kfunc_is_rejected() {
        let seq = vec![
            (
                Label::new(0),
                Instruction::CallBtf(CallBtf {
                    btf_id: 1,
                    module: 0,
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
        ];

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        let err = match Program::from_sequence(&seq, &mut info, &platform, &opts) {
            Ok(_) => panic!("unknown kfunc id must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.message
                .contains("not implemented: kfunc prototype lookup failed for BTF id 1")
        );
        assert!(err.message.contains("(at 0)"));
    }

    #[test]
    fn test_call_btf_known_kfunc_is_lowered_to_call() {
        let seq = vec![
            (
                Label::new(0),
                Instruction::CallBtf(CallBtf {
                    btf_id: 1000,
                    module: 0,
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
        ];

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        let program = Program::from_sequence(&seq, &mut info, &platform, &opts)
            .expect("known kfunc must pass");
        match program.instruction_at(&Label::new(0)) {
            Instruction::Call(call) => {
                assert_eq!(call.kind, CallKind::Kfunc);
                assert_eq!(call.func, 1000);
            }
            other => panic!("expected lowered kfunc call, got {other:?}"),
        }
    }

    #[test]
    fn test_kfunc_btf_id_overlap_with_tail_call_helper_is_not_misclassified() {
        let mut seq: InstructionSeq = Vec::new();
        for i in 0..34 {
            seq.push((
                Label::new(i),
                Instruction::CallBtf(CallBtf {
                    btf_id: 12,
                    module: 0,
                }),
                None,
            ));
        }
        seq.push((
            Label::new(34),
            Instruction::Exit(Exit {
                stack_frame_prefix: Rc::from(""),
            }),
            None,
        ));

        let mut info = ProgramInfo::default();
        let platform = LinuxPlatform::new();
        let opts = EbpfVerifierOptions::default();
        Program::from_sequence(&seq, &mut info, &platform, &opts)
            .expect("kfunc id overlap must not trigger tail-call-depth rejection");
    }
}
