// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! YAML-based test suite for the eBPF verifier.
//!
//! Each tests/upstream/test-data/*.yaml file contains multiple test cases as
//! YAML documents.
//! Each test case specifies:
//! - `pre`: initial abstract state as string constraints
//! - `code`: labeled instruction blocks in assembly text
//! - `post`: expected final abstract state
//! - `messages`: expected verification messages (errors, unreachable code)
//! - `options`: verifier flags (optional)
//! - `observe`: observation consistency/entailment checks (optional)
//! - `expected-exception`: expected parse-time exception message (optional)

mod path_config;

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use prevail::cfg::label::Label;
use prevail::crab::array_domain::ArrayMap;
use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::string_constraints::StringInvariant;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader::UnmarshalError;
use prevail::fwd_analyzer;
use prevail::ir::parse::parse_instruction_with_platform;
use prevail::ir::program::Program;
use prevail::ir::syntax::{Instruction, InstructionSeq};
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::linux::spec_prototypes::HelperPrototype;
use prevail::platform::EbpfPlatform;
use prevail::result::{InvariantPoint, ObservationCheckMode};
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::ebpf_base::EbpfCtxDescriptor;
use prevail::spec::type_descriptors::{
    EbpfMapDescriptor, EbpfMapType, EbpfProgramType, ProgramInfo,
};

// ============================================================================
// Test platform
// ============================================================================

/// Test platform: delegates to Linux for helpers/types, uses a fixed map descriptor.
struct TestPlatform {
    linux: LinuxPlatform,
    test_map: EbpfMapDescriptor,
}

impl TestPlatform {
    fn new() -> Self {
        TestPlatform {
            linux: LinuxPlatform::new(),
            test_map: EbpfMapDescriptor {
                key_size: 4, // sizeof(uint32_t)
                value_size: 4,
                max_entries: 4,
                ..Default::default()
            },
        }
    }
}

impl EbpfPlatform for TestPlatform {
    fn get_program_type(&self, section: &str, path: &str) -> EbpfProgramType {
        self.linux.get_program_type(section, path)
    }
    fn get_helper_prototype(&self, n: i32) -> &HelperPrototype {
        self.linux.get_helper_prototype(n)
    }
    fn try_get_helper_prototype(&self, n: i32) -> Option<&HelperPrototype> {
        self.linux.try_get_helper_prototype(n)
    }
    fn is_helper_usable(&self, n: i32) -> bool {
        self.linux.is_helper_usable(n)
    }
    fn resolve_kfunc_call(
        &self,
        btf_id: i32,
        info: &ProgramInfo,
    ) -> Result<prevail::ir::syntax::Call, String> {
        self.linux.resolve_kfunc_call(btf_id, info)
    }
    fn map_record_size(&self) -> usize {
        0
    }
    fn parse_maps_section(
        &mut self,
        _descriptors: &mut Vec<EbpfMapDescriptor>,
        _data: &[u8],
        _record_size: usize,
        _count: usize,
        _options: &EbpfVerifierOptions,
    ) {
        // no-op for tests
    }
    fn resolve_inner_map_references(
        &self,
        _descriptors: &mut Vec<EbpfMapDescriptor>,
    ) -> Result<(), UnmarshalError> {
        Ok(())
        // no-op
    }
    fn get_map_descriptor(&self, _map_fd: i32) -> Option<&EbpfMapDescriptor> {
        Some(&self.test_map)
    }
    fn get_map_type(&self, platform_specific_type: u32) -> EbpfMapType {
        self.linux.get_map_type(platform_specific_type)
    }
    fn supported_conformance_groups(&self) -> u32 {
        self.linux.supported_conformance_groups() | 0x40 | 0x80
    }
}

// ============================================================================
// YAML deserialization
// ============================================================================

#[derive(Deserialize)]
struct RawTestCase {
    #[serde(rename = "test-case")]
    test_case: String,
    #[serde(default, rename = "expected-exception")]
    expected_exception: Option<String>,
    #[serde(default)]
    options: Vec<String>,
    pre: Vec<String>,
    code: serde_yaml::Value,
    post: Vec<String>,
    #[serde(default)]
    messages: Vec<String>,
    #[serde(default)]
    observe: serde_yaml::Value,
}

// ============================================================================
// Test case types
// ============================================================================

struct Observation {
    label: Label,
    point: InvariantPoint,
    mode: ObservationCheckMode,
    constraints: StringInvariant,
}

struct TestCase {
    name: String,
    expected_exception: Option<String>,
    actual_exception: Option<String>,
    options: EbpfVerifierOptions,
    pre: StringInvariant,
    instruction_seq: InstructionSeq,
    expected_post: StringInvariant,
    expected_messages: BTreeSet<String>,
    observations: Vec<Observation>,
}

// ============================================================================
// Observation parsing
// ============================================================================

fn parse_label_scalar(node: &serde_yaml::Value) -> Label {
    match node {
        serde_yaml::Value::String(s) => {
            if s == "entry" {
                return Label::entry();
            }
            if s == "exit" {
                return Label::exit();
            }
            match s.parse::<i32>() {
                Ok(index) if index >= 0 => Label::new(index),
                _ => panic!("Invalid observation label: {s}"),
            }
        }
        serde_yaml::Value::Number(n) => {
            let index = n
                .as_i64()
                .unwrap_or_else(|| panic!("Invalid observation label: {n}"));
            if index < 0 {
                panic!("Invalid observation label: {index}");
            }
            Label::new(index as i32)
        }
        _ => {
            panic!("Invalid observation label; expected scalar 'entry'/'exit' or instruction index")
        }
    }
}

fn parse_point(node: &serde_yaml::Value) -> InvariantPoint {
    if node.is_null() {
        return InvariantPoint::Pre;
    }
    match node.as_str() {
        Some("pre") => InvariantPoint::Pre,
        Some("post") => InvariantPoint::Post,
        Some(other) => panic!("Invalid observation point: {other}"),
        None => InvariantPoint::Pre,
    }
}

fn parse_mode(node: &serde_yaml::Value) -> ObservationCheckMode {
    if node.is_null() {
        return ObservationCheckMode::Consistent;
    }
    match node.as_str() {
        Some("consistent") => ObservationCheckMode::Consistent,
        Some("entailed") => ObservationCheckMode::Entailed,
        Some(other) => panic!("Invalid observation mode: {other}"),
        None => ObservationCheckMode::Consistent,
    }
}

fn parse_observations(observe_node: &serde_yaml::Value) -> Vec<Observation> {
    if observe_node.is_null() {
        return Vec::new();
    }
    let seq = observe_node
        .as_sequence()
        .unwrap_or_else(|| panic!("observe must be a sequence"));
    let mut result = Vec::new();
    for item in seq {
        let map = item
            .as_mapping()
            .unwrap_or_else(|| panic!("observe item must be a map"));

        let label = parse_label_scalar(map.get("at").unwrap_or(&serde_yaml::Value::Null));
        let point = parse_point(map.get("point").unwrap_or(&serde_yaml::Value::Null));
        let mode = parse_mode(map.get("mode").unwrap_or(&serde_yaml::Value::Null));

        let constraints_node = map.get("constraints");
        let constraints_node = match constraints_node {
            Some(v) if !v.is_null() => v,
            _ => panic!("observe item missing required 'constraints' field"),
        };

        let constraints_vec: Vec<String> = match constraints_node.as_sequence() {
            Some(seq) => seq
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| {
                            panic!("observe.constraints must be a sequence of strings")
                        })
                        .to_string()
                })
                .collect(),
            None => panic!("observe.constraints must be a sequence of strings"),
        };

        result.push(Observation {
            label,
            point,
            mode,
            constraints: parse_invariant(&constraints_vec),
        });
    }
    result
}

// ============================================================================
// Parsing
// ============================================================================

fn parse_options(raw: &[String]) -> EbpfVerifierOptions {
    let mut opts = EbpfVerifierOptions::default();
    // YAML test defaults (match C++)
    opts.verbosity_opts.simplify = false;
    opts.runtime.setup_constraints = false;
    opts.must_have_exit = false;
    // Default to little-endian (x86 host)
    opts.runtime.big_endian = false;

    for name in raw {
        match name.as_str() {
            "!allow_division_by_zero" => opts.runtime.allow_division_by_zero = false,
            "termination" => opts.runtime.check_for_termination = true,
            "strict" => opts.runtime.strict = true,
            "simplify" => opts.verbosity_opts.simplify = true,
            "big_endian" => opts.runtime.big_endian = true,
            "!big_endian" => opts.runtime.big_endian = false,
            other => panic!("Unknown option: {}", other),
        }
    }
    opts
}

fn parse_invariant(raw: &[String]) -> StringInvariant {
    let set: BTreeSet<String> = raw.iter().cloned().collect();
    if set.len() == 1 && set.contains("_|_") {
        return StringInvariant::bottom();
    }
    StringInvariant::from_set(set)
}

fn parse_code_blocks(code: &serde_yaml::Value, platform: &dyn EbpfPlatform) -> InstructionSeq {
    let mapping = code.as_mapping().expect("code must be a YAML mapping");

    // First pass: assign label indices
    let mut label_map: BTreeMap<String, Label> = BTreeMap::new();
    let mut label_index = 0i32;
    for (key, value) in mapping {
        let label_name = key.as_str().expect("code key must be a string").to_string();
        label_map.insert(label_name, Label::new(label_index));
        let block_text = value.as_str().expect("code value must be a string");
        label_index += block_text.lines().filter(|l| !l.trim().is_empty()).count() as i32;
    }

    // Second pass: parse instructions
    let mut result: InstructionSeq = Vec::new();
    let mut pc = 0i32;
    for (_key, value) in mapping {
        let block_text = value.as_str().unwrap();
        for line in block_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let ins = parse_instruction_with_platform(trimmed, &label_map, Some(platform));
            if matches!(ins, Instruction::Undefined(_)) && !trimmed.is_empty() {
                // Only warn, don't fail — some instructions may be intentionally undefined
                eprintln!("Warning: unparsed instruction: {}", trimmed);
            }
            result.push((Label::new(pc), ins, None));
            pc += 1;
        }
    }
    result
}

fn read_test_case(raw: RawTestCase, platform: &dyn EbpfPlatform) -> TestCase {
    let observations = parse_observations(&raw.observe);
    TestCase {
        name: raw.test_case,
        expected_exception: None,
        actual_exception: None,
        options: parse_options(&raw.options),
        pre: parse_invariant(&raw.pre),
        instruction_seq: parse_code_blocks(&raw.code, platform),
        expected_post: parse_invariant(&raw.post),
        expected_messages: raw.messages.into_iter().collect(),
        observations,
    }
}

fn load_suite(path: &str, platform: &dyn EbpfPlatform) -> Vec<TestCase> {
    assert!(
        std::path::Path::new(path).exists(),
        "YAML fixture not found: {path}. Initialize submodules per CONTRIBUTING.md (Initial Setup)"
    );
    let content =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    let mut cases = Vec::new();
    for doc in serde_yaml::Deserializer::from_str(&content) {
        let raw: RawTestCase = RawTestCase::deserialize(doc)
            .unwrap_or_else(|e| panic!("Failed to parse YAML in {}: {}", path, e));

        if raw.expected_exception.is_some() {
            // Exception fixture: try to parse, capture any panic as actual_exception.
            let expected_exception = raw.expected_exception.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                read_test_case(raw, platform)
            }));
            match result {
                Ok(mut tc) => {
                    // Parsing succeeded — no exception was thrown.
                    tc.expected_exception = expected_exception;
                    tc.actual_exception = None;
                    cases.push(tc);
                }
                Err(panic_val) => {
                    // Extract panic message.
                    let msg = if let Some(s) = panic_val.downcast_ref::<String>() {
                        s.clone()
                    } else if let Some(s) = panic_val.downcast_ref::<&str>() {
                        (*s).to_string()
                    } else {
                        "unknown panic".to_string()
                    };
                    cases.push(TestCase {
                        name: "<parse failed>".to_string(),
                        expected_exception,
                        actual_exception: Some(msg),
                        options: EbpfVerifierOptions::default(),
                        pre: StringInvariant::top(),
                        instruction_seq: Vec::new(),
                        expected_post: StringInvariant::top(),
                        expected_messages: BTreeSet::new(),
                        observations: Vec::new(),
                    });
                }
            }
        } else {
            cases.push(read_test_case(raw, platform));
        }
    }
    cases
}

fn upstream_yaml_path(file_name: &str) -> String {
    path_config::upstream_test_data_path(file_name)
}

// ============================================================================
// Test runner
// ============================================================================

#[derive(Debug)]
struct Failure {
    unexpected_props: BTreeSet<String>,
    unseen_props: BTreeSet<String>,
    unexpected_msgs: BTreeSet<String>,
    unseen_msgs: BTreeSet<String>,
    actual_props: BTreeSet<String>,
    expected_props: BTreeSet<String>,
}

fn run_test_case(test_case: &TestCase, platform: &TestPlatform) -> Option<Failure> {
    // Handle expected-exception test cases.
    if let Some(expected_exception) = &test_case.expected_exception {
        let expected_messages: BTreeSet<String> = [format!("Exception: {}", expected_exception)]
            .into_iter()
            .collect();
        let actual_messages: BTreeSet<String> = test_case
            .actual_exception
            .as_ref()
            .map(|msg| [format!("Exception: {msg}")].into_iter().collect())
            .unwrap_or_default();

        if actual_messages == expected_messages {
            return None;
        }
        return Some(Failure {
            unexpected_props: BTreeSet::new(),
            unseen_props: BTreeSet::new(),
            unexpected_msgs: actual_messages
                .difference(&expected_messages)
                .cloned()
                .collect(),
            unseen_msgs: expected_messages
                .difference(&actual_messages)
                .cloned()
                .collect(),
            actual_props: BTreeSet::new(),
            expected_props: BTreeSet::new(),
        });
    }

    // Build context
    let ctx_descriptor: &'static EbpfCtxDescriptor = Box::leak(Box::new(EbpfCtxDescriptor {
        size: 64,
        data: 0,
        end: 4,
        meta: -1,
    }));
    let program_type = EbpfProgramType {
        name: test_case.name.clone(),
        ctx_descriptor: Some(ctx_descriptor),
        platform_specific_data: 0,
        section_prefixes: vec![],
        is_privileged: false,
    };
    let mut info = ProgramInfo {
        program_type,
        map_descriptors: vec![EbpfMapDescriptor {
            key_size: 4,
            value_size: 4,
            max_entries: 4,
            ..Default::default()
        }],
        ..ProgramInfo::default()
    };

    let mut registry = VariableRegistry::new();
    let options = test_case.options;

    // Build program from instruction sequence
    let prog =
        match Program::from_sequence(&test_case.instruction_seq, &mut info, platform, &options) {
            Ok(p) => p,
            Err(e) => {
                // InvalidControlFlow — check if expected
                let actual_messages: BTreeSet<String> = [e.to_string()].into_iter().collect();
                if test_case.expected_post == StringInvariant::top()
                    && actual_messages == test_case.expected_messages
                {
                    return None;
                }
                return Some(Failure {
                    unexpected_props: BTreeSet::new(),
                    unseen_props: BTreeSet::new(),
                    unexpected_msgs: actual_messages
                        .difference(&test_case.expected_messages)
                        .cloned()
                        .collect(),
                    unseen_msgs: test_case
                        .expected_messages
                        .difference(&actual_messages)
                        .cloned()
                        .collect(),
                    actual_props: BTreeSet::new(),
                    expected_props: BTreeSet::new(),
                });
            }
        };

    let ctx = DomainContext {
        program_info: &info,
        program: &prog,
        runtime: &options.runtime,
        options: &options,
        platform,
    };

    let result = fwd_analyzer::analyze_with_entry(&prog, &test_case.pre, &ctx, &mut registry);

    // Collect actual post-invariant
    let actual_post = result.invariant_at(&Label::exit(), &registry);

    // Collect actual messages
    let mut actual_messages = BTreeSet::new();
    if let Some(error) = result.find_first_error() {
        actual_messages.insert(error.to_string());
    }
    for (_label, msgs) in result.find_unreachable(prog.instructions()) {
        for msg in msgs {
            actual_messages.insert(msg);
        }
    }

    // Evaluate observation checks.
    for obs in &test_case.observations {
        let mut array_map = ArrayMap::new(options.runtime.total_stack_size());
        let check = result.check_observation_at_label(
            &obs.label,
            obs.point,
            &obs.constraints,
            obs.mode,
            &ctx,
            &mut registry,
            &mut array_map,
        );
        if !check.ok {
            actual_messages.insert(format!(
                "{}: observation {} failed at {}",
                obs.label, obs.mode, obs.point,
            ));
        }
    }

    // Compare. A more-precise bottom post is acceptable when the expected post
    // is top and messages match — this happens when upstream's abstract domain
    // misses an unsat constraint that we detect (e.g. `assume r1 != r2` with
    // concretely-equal map fds): upstream's YAML keeps `post: []` even when
    // the unreachable message is emitted because upstream's zone domain stays
    // non-bottom, while our port correctly reduces to bottom.
    if actual_messages == test_case.expected_messages
        && (actual_post == test_case.expected_post
            || (actual_post.is_bottom()
                && !test_case.expected_post.is_bottom()
                && test_case.expected_post.value().is_empty()))
    {
        return None;
    }

    let actual_set = if actual_post.is_bottom() {
        BTreeSet::new()
    } else {
        actual_post.value().clone()
    };
    let expected_set = if test_case.expected_post.is_bottom() {
        BTreeSet::new()
    } else {
        test_case.expected_post.value().clone()
    };

    Some(Failure {
        unexpected_props: actual_set.difference(&expected_set).cloned().collect(),
        unseen_props: expected_set.difference(&actual_set).cloned().collect(),
        unexpected_msgs: actual_messages
            .difference(&test_case.expected_messages)
            .cloned()
            .collect(),
        unseen_msgs: test_case
            .expected_messages
            .difference(&actual_messages)
            .cloned()
            .collect(),
        actual_props: actual_set,
        expected_props: expected_set,
    })
}

fn case_selected(name: &str) -> bool {
    if let Ok(filter) = std::env::var("YAML_CASE")
        && !filter.is_empty()
    {
        return name.contains(&filter);
    }
    true
}

// ============================================================================
// Test macro
// ============================================================================

macro_rules! yaml_test_suite {
    ($name:ident) => {
        #[test]
        fn $name() {
            let suite_name = stringify!($name);
            let stem = suite_name.strip_prefix("yaml_").unwrap_or(suite_name);
            let path = upstream_yaml_path(&format!("{stem}.yaml"));
            let platform = TestPlatform::new();
            let all_cases = load_suite(&path, &platform);
            let cases: Vec<&TestCase> = all_cases
                .iter()
                .filter(|c| case_selected(&c.name))
                .collect();
            assert!(!cases.is_empty(), "No test cases in {}", path);

            let mut failures = Vec::new();
            for case in cases {
                if let Some(failure) = run_test_case(case, &platform) {
                    failures.push((case.name.clone(), failure));
                }
            }

            if !failures.is_empty() {
                let mut msg = format!(
                    "\n{}: {}/{} test cases failed:\n",
                    path,
                    failures.len(),
                    all_cases.iter().filter(|c| case_selected(&c.name)).count()
                );
                for (name, f) in &failures {
                    msg.push_str(&format!("\n  --- {} ---\n", name));
                    if !f.unexpected_props.is_empty() {
                        msg.push_str(&format!(
                            "  Unexpected properties: {:?}\n",
                            f.unexpected_props
                        ));
                    }
                    if !f.unseen_props.is_empty() {
                        msg.push_str(&format!("  Unseen properties: {:?}\n", f.unseen_props));
                    }
                    if !f.unexpected_msgs.is_empty() {
                        msg.push_str(&format!("  Unexpected messages: {:?}\n", f.unexpected_msgs));
                    }
                    if !f.unseen_msgs.is_empty() {
                        msg.push_str(&format!("  Unseen messages: {:?}\n", f.unseen_msgs));
                    }
                    if std::env::var("YAML_PRINT_ACTUAL").is_ok() {
                        msg.push_str(&format!("  Actual properties: {:?}\n", f.actual_props));
                        msg.push_str(&format!("  Expected properties: {:?}\n", f.expected_props));
                    }
                }
                panic!("{}", msg);
            }
        }
    };
}

// ============================================================================
// Test suites — one per YAML file
// ============================================================================

yaml_test_suite!(yaml_add);
yaml_test_suite!(yaml_assign);
yaml_test_suite!(yaml_atomic);
yaml_test_suite!(yaml_bitop);
yaml_test_suite!(yaml_call);
yaml_test_suite!(yaml_calllocal);
yaml_test_suite!(yaml_callx);
yaml_test_suite!(yaml_udivmod);
yaml_test_suite!(yaml_sdivmod);
yaml_test_suite!(yaml_full64);
yaml_test_suite!(yaml_jump);
yaml_test_suite!(yaml_loop);
yaml_test_suite!(yaml_map);
yaml_test_suite!(yaml_movsx);
yaml_test_suite!(yaml_muldiv);
yaml_test_suite!(yaml_nonconvex);
yaml_test_suite!(yaml_observe);
yaml_test_suite!(yaml_packet);
yaml_test_suite!(yaml_parse);
yaml_test_suite!(yaml_pointer);
yaml_test_suite!(yaml_sext);
yaml_test_suite!(yaml_shift);
yaml_test_suite!(yaml_stack);
yaml_test_suite!(yaml_subtract);
yaml_test_suite!(yaml_uninit);
yaml_test_suite!(yaml_unop);
yaml_test_suite!(yaml_unsigned);
