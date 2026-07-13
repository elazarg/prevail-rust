// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Regex-based parser for eBPF assembly text.
//!
//! Ported from `src/ir/parse.cpp`. Used primarily for testing -- test fixtures
//! are written as text and need to be parsed into IR structures.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::LazyLock;

use regex::Regex;

use crate::arith::linear_constraint::{LinearConstraint, expr_eq, leq};
use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::cfg::label::Label;
use crate::crab::interval::Interval;
use crate::crab::type_encoding::{DataKind, T_NUM, regkind, string_to_type_encoding};
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::{
    Assume, Atomic, AtomicOp, Bin, BinOp, CallBtf, CallLocal, Callx, Condition, ConditionOp, Deref,
    Exit, Imm, Instruction, InstructionSeq, Jmp, LoadMapAddress, LoadMapFd, LoadPseudo, Mem,
    Packet, PseudoAddress, PseudoAddressKind, Reg, Un, UnOp, Undefined, Value,
};
use crate::spec::vm_isa::AccessSize;

// ---------------------------------------------------------------------------
// Regex pattern fragments (mirrors C++ preprocessor macros)
// ---------------------------------------------------------------------------

const REG: &str = r"\s*(r\d\d?)\s*";
const WREG: &str = r"\s*([wr]\d\d?)\s*";
const IMM: &str = r"\s*\[?([-+]?(?:0x)?[0-9a-f]+)\]?\s*";
const REG_OR_IMM: &str = r"\s*([+-]?(?:0x)?[0-9a-f]+|r\d\d?)\s*";
const OPASSIGN: &str = r"\s*(\S*)=\s*";
const ASSIGN: &str = r"\s*=\s*";
const LONGLONG: &str = r"\s*(ll|)\s*";
const UNOP: &str = r"(-|be16|be32|be64|le16|le32|le64|swap16|swap32|swap64)";
const ATOMICOP: &str = r"(\+|\||&|\^|x|cx)=";
const PLUSMINUS: &str = r"(\s*[+-])\s*";
const LPAREN: &str = r"\s*\(\s*";
const RPAREN: &str = r"\s*\)\s*";
const STAR: &str = r"\s*\*\s*";
const IN: &str = r"\s*in\s*";
const TYPE_SET: &str = r"\s*\{\s*([^}]*)\s*\}\s*";
const CMPOP: &str = r"\s*(&?[=!]=|s?[<>]=?)\s*";
const LABEL_PAT: &str = r"(<\w[a-zA-Z_0-9]*>)";
const SPECIAL_VAR: &str = r"\s*(packet_size|meta_offset)\s*";
const KIND: &str = r"\s*(svalue|uvalue|ctx_offset|map_fd|map_fd_programs|packet_offset|shared_offset|stack_offset|shared_region_size|stack_numeric_size|socket_offset|btf_id_offset|alloc_mem_offset|alloc_mem_size)\s*";
const INTERVAL: &str = r"\s*\[([-+]?\d+),\s*([-+]?\d+)\]?\s*";
const ARRAY_RANGE: &str = r"\s*\[([-+]?\d+)\.\.\.\s*([-+]?\d+)\]?\s*";
const DOT: &str = r"[.]";
const TYPE_PAT: &str =
    r"\s*(shared|number|packet|stack|ctx|map_fd|map_fd_programs|socket|btf_id|alloc_mem|func)\s*";
const MAP_VAL: &str = r"\s*map_val\((\d+)\)\s*\+\s*(\d+)\s*";

fn wrapped_label() -> String {
    format!(r"\s*{}\s*", LABEL_PAT)
}

// ---------------------------------------------------------------------------
// Compiled regexes
//
// Patterns are built from the fragment `const`s above and compiled exactly
// once at first use. A compilation failure here indicates a bug in the
// fragments, not a runtime input error, so panicking on `unwrap` is
// appropriate; the `LazyLock` ensures we only panic at startup-like timing
// rather than on every call site.
// ---------------------------------------------------------------------------

fn compile(pat: &str) -> Regex {
    Regex::new(pat).unwrap_or_else(|e| panic!("invalid regex `{pat}`: {e}"))
}

// parse_instruction_with_platform
static RE_EXIT: LazyLock<Regex> = LazyLock::new(|| compile(r"^exit$"));
static RE_CALL_IMM: LazyLock<Regex> = LazyLock::new(|| compile(&format!("^call {}$", IMM)));
static RE_CALL_LABEL: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^call {}$", wrapped_label())));
static RE_CALLX: LazyLock<Regex> = LazyLock::new(|| compile(&format!("^callx {}$", REG)));
static RE_CALL_BTF_MODULE: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!(r"^call_btf {}\s+module\s+{}$", IMM, IMM)));
static RE_CALL_BTF: LazyLock<Regex> = LazyLock::new(|| compile(&format!("^call_btf {}$", IMM)));
static RE_BIN_REG: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}$", WREG, OPASSIGN, WREG)));
static RE_UN: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}{}$", WREG, ASSIGN, UNOP, WREG)));
static RE_LOAD_MAP_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}$", WREG, ASSIGN, MAP_VAL)));
static RE_LOAD_MAP_FD: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r"^{}{}map_fd(?:_programs)?\s+(\d+)\s*$",
        WREG, ASSIGN
    ))
});
static RE_PSEUDO_VARIABLE_ADDR: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}variable_addr\\s+{}$", WREG, ASSIGN, IMM)));
static RE_PSEUDO_CODE_ADDR: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}code_addr\\s+{}$", WREG, ASSIGN, IMM)));
static RE_PSEUDO_MAP_BY_IDX: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!(r"^{}{}map_by_idx\({}\)$", WREG, ASSIGN, IMM)));
static RE_PSEUDO_MVA: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r"^{}{}mva\(map_by_idx\({}\)\)\s*\+\s*{}$",
        WREG, ASSIGN, IMM, IMM
    ))
});
static RE_BIN_IMM: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}{}$", WREG, OPASSIGN, IMM, LONGLONG)));
static RE_MEM_LOAD: LazyLock<Regex> = LazyLock::new(|| {
    let deref_pat = format!("{}{}([su])(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
    let inner = format!("{}{}{}", REG, PLUSMINUS, IMM);
    compile(&format!(
        "^{}{}{}{}{}{}$",
        REG, ASSIGN, deref_pat, LPAREN, inner, RPAREN
    ))
});
static RE_MEM_STORE: LazyLock<Regex> = LazyLock::new(|| {
    let deref_pat = format!("{}{}([su])(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
    let inner = format!("{}{}{}", REG, PLUSMINUS, IMM);
    compile(&format!(
        "^{}{}{}{}{}{}$",
        deref_pat, LPAREN, inner, RPAREN, ASSIGN, REG_OR_IMM
    ))
});
static RE_ATOMIC: LazyLock<Regex> = LazyLock::new(|| {
    let deref_pat = format!("{}{}([su])(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
    let inner = format!("{}{}{}", REG, PLUSMINUS, IMM);
    compile(&format!(
        r"^lock {}{}{}{}{}{}( fetch)?$",
        deref_pat, LPAREN, inner, RPAREN, ATOMICOP, REG
    ))
});
static RE_PACKET: LazyLock<Regex> = LazyLock::new(|| {
    let deref_pat = format!("{}{}u(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
    compile(&format!(r"^r0 = {}skb\[(.*)\]$", deref_pat))
});
static RE_PACKET_REG: LazyLock<Regex> = LazyLock::new(|| compile(&format!("^{}$", REG)));
static RE_PACKET_IMM: LazyLock<Regex> = LazyLock::new(|| compile(&format!("^{}$", IMM)));
static RE_PACKET_REG_PM_REG: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}$", REG, PLUSMINUS, REG)));
static RE_PACKET_REG_PM_IMM: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}$", REG, PLUSMINUS, IMM)));
static RE_ASSUME: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^assume {}{}{}$", WREG, CMPOP, REG_OR_IMM)));
static RE_GOTO: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        "^(?:if {}{}{})?goto\\s+(?:{})?{}$",
        WREG,
        CMPOP,
        REG_OR_IMM,
        IMM,
        wrapped_label()
    ))
});

// parse_program
static RE_LABEL: LazyLock<Regex> = LazyLock::new(|| compile(&format!("{}:", LABEL_PAT)));
static RE_PREFIX: LazyLock<Regex> = LazyLock::new(|| compile(r"^\s*(\d+:)?\s*"));

// parse_linear_constraints
static RE_SPECIAL_EQ_IMM: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}={}$", SPECIAL_VAR, IMM)));
static RE_SPECIAL_EQ_INTERVAL: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}={}$", SPECIAL_VAR, INTERVAL)));
static RE_SPECIAL_EQ_REG_KIND: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}={}{}{}$", SPECIAL_VAR, REG, DOT, KIND)));
static RE_REG_KIND_EQ_SPECIAL: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}={}$", REG, DOT, KIND, SPECIAL_VAR)));
static RE_REG_KIND_EQ_REG_KIND: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}={}{}{}$", REG, DOT, KIND, REG, DOT, KIND)));
static RE_REG_TYPE_EQ_REG_TYPE: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}type={}{}type$", REG, DOT, REG, DOT)));
static RE_REG_TYPE_EQ_TYPE: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}type={}$", REG, DOT, TYPE_PAT)));
static RE_REG_TYPE_IN_TYPESET: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}type{}{}$", REG, DOT, IN, TYPE_SET)));
static RE_REG_KIND_EQ_IMM: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}={}$", REG, DOT, KIND, IMM)));
static RE_REG_KIND_EQ_INTERVAL: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^{}{}{}={}$", REG, DOT, KIND, INTERVAL)));
static RE_REG_KIND_DIFF_LEQ: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        "^{}{}{}-{}{}{}<={}$",
        REG, DOT, KIND, REG, DOT, KIND, IMM
    ))
});
static RE_STACK_RANGE_TYPE: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^s{}{}type={}$", ARRAY_RANGE, DOT, TYPE_PAT)));
static RE_STACK_RANGE_SVALUE: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^s{}{}svalue={}$", ARRAY_RANGE, DOT, IMM)));
static RE_STACK_RANGE_UVALUE: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!("^s{}{}uvalue={}$", ARRAY_RANGE, DOT, IMM)));
static RE_TYPE_TOK: LazyLock<Regex> = LazyLock::new(|| compile(TYPE_PAT));

// ---------------------------------------------------------------------------
// Lookup tables
// ---------------------------------------------------------------------------

static STR_TO_BINOP: LazyLock<HashMap<&'static str, BinOp>> = LazyLock::new(|| {
    HashMap::from([
        ("", BinOp::MOV),
        ("+", BinOp::ADD),
        ("-", BinOp::SUB),
        ("*", BinOp::MUL),
        ("/", BinOp::UDIV),
        ("%", BinOp::UMOD),
        ("|", BinOp::OR),
        ("&", BinOp::AND),
        ("<<", BinOp::LSH),
        (">>", BinOp::RSH),
        ("s>>", BinOp::ARSH),
        ("^", BinOp::XOR),
        ("s/", BinOp::SDIV),
        ("s%", BinOp::SMOD),
        ("s8", BinOp::MOVSX8),
        ("s16", BinOp::MOVSX16),
        ("s32", BinOp::MOVSX32),
    ])
});

static STR_TO_UNOP: LazyLock<HashMap<&'static str, UnOp>> = LazyLock::new(|| {
    HashMap::from([
        ("be16", UnOp::BE16),
        ("be32", UnOp::BE32),
        ("be64", UnOp::BE64),
        ("le16", UnOp::LE16),
        ("le32", UnOp::LE32),
        ("le64", UnOp::LE64),
        ("swap16", UnOp::SWAP16),
        ("swap32", UnOp::SWAP32),
        ("swap64", UnOp::SWAP64),
        ("-", UnOp::NEG),
    ])
});

static STR_TO_CMPOP: LazyLock<HashMap<&'static str, ConditionOp>> = LazyLock::new(|| {
    HashMap::from([
        ("==", ConditionOp::EQ),
        ("!=", ConditionOp::NE),
        ("&==", ConditionOp::SET),
        ("&!=", ConditionOp::NSET),
        ("<", ConditionOp::LT),
        ("<=", ConditionOp::LE),
        (">", ConditionOp::GT),
        (">=", ConditionOp::GE),
        ("s<", ConditionOp::SLT),
        ("s<=", ConditionOp::SLE),
        ("s>", ConditionOp::SGT),
        ("s>=", ConditionOp::SGE),
    ])
});

static STR_TO_ATOMICOP: LazyLock<HashMap<&'static str, AtomicOp>> = LazyLock::new(|| {
    HashMap::from([
        ("+", AtomicOp::ADD),
        ("|", AtomicOp::OR),
        ("&", AtomicOp::AND),
        ("^", AtomicOp::XOR),
        ("x", AtomicOp::XCHG),
        ("cx", AtomicOp::CMPXCHG),
    ])
});

static STR_TO_WIDTH: LazyLock<HashMap<&'static str, AccessSize>> = LazyLock::new(|| {
    HashMap::from([
        ("8", AccessSize::Byte),
        ("16", AccessSize::Half),
        ("32", AccessSize::Word),
        ("64", AccessSize::DWord),
    ])
});

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn is64_reg(s: &str) -> bool {
    s.as_bytes()[0] == b'r'
}

fn to_int(s: &str) -> i32 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i32::from_str_radix(hex, 16).unwrap()
    } else if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        -i32::from_str_radix(hex, 16).unwrap()
    } else if let Some(hex) = s.strip_prefix("+0x").or_else(|| s.strip_prefix("+0X")) {
        i32::from_str_radix(hex, 16).unwrap()
    } else {
        s.parse::<i32>().unwrap()
    }
}

fn signed_number(s: &str) -> Number {
    let v = parse_i64(s);
    Number::from(v)
}

fn unsigned_number(s: &str) -> Number {
    let v = parse_u64(s);
    Number::from(v)
}

/// Parse a string as i64 with auto-detection of hex (0x) prefix.
fn parse_i64(s: &str) -> i64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).unwrap()
    } else if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        -i64::from_str_radix(hex, 16).unwrap()
    } else if let Some(hex) = s.strip_prefix("+0x").or_else(|| s.strip_prefix("+0X")) {
        i64::from_str_radix(hex, 16).unwrap()
    } else {
        s.parse::<i64>().unwrap()
    }
}

/// Parse a string as u64 with auto-detection of hex (0x) prefix.
fn parse_u64(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap()
    } else if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        let pos = u64::from_str_radix(hex, 16).unwrap();
        (-(pos as i64)) as u64
    } else if s.starts_with('-') {
        s.parse::<i64>().unwrap() as u64
    } else if let Some(hex) = s.strip_prefix("+0x").or_else(|| s.strip_prefix("+0X")) {
        u64::from_str_radix(hex, 16).unwrap()
    } else {
        s.parse::<u64>().unwrap()
    }
}

fn reg(s: &str) -> Reg {
    let first = s.as_bytes()[0];
    assert!(first == b'r' || first == b'w');
    let num = to_int(&s[1..]) as u8;
    Reg { v: num }
}

fn regnum(s: &str) -> i32 {
    to_int(&s[1..])
}

fn imm(s: &str, lddw: bool) -> Imm {
    if lddw {
        if s.starts_with('-') {
            Imm {
                v: parse_i64(s) as u64,
            }
        } else {
            Imm { v: parse_u64(s) }
        }
    } else if s.starts_with('-') {
        Imm {
            v: parse_i64(s) as u64,
        }
    } else {
        // C++: static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(std::stoul(s, nullptr, 0))))
        let u32_val = parse_u64(s) as u32;
        Imm {
            v: u32_val as i32 as i64 as u64,
        }
    }
}

fn reg_or_imm(s: &str) -> Value {
    let first = s.as_bytes()[0];
    if first == b'w' || first == b'r' {
        Value::Reg(reg(s))
    } else {
        Value::Imm(imm(s, false))
    }
}

fn make_deref(
    _signedness: &str,
    width_str: &str,
    basereg_str: &str,
    sign_str: &str,
    offset_str: &str,
) -> Deref {
    let offset = to_int(offset_str);
    Deref {
        width: STR_TO_WIDTH[width_str],
        basereg: reg(basereg_str),
        offset: if sign_str.trim() == "-" {
            -offset
        } else {
            offset
        },
    }
}

// ---------------------------------------------------------------------------
// parse_instruction
// ---------------------------------------------------------------------------

/// Parse a single text line into an `Instruction`.
///
/// `label_name_to_label` maps named labels (like `"<entry>"`) to `Label` values.
/// `platform` is optional; when provided, `call <imm>` instructions are resolved
/// via `make_call`.
///
/// Returns `Instruction::Undefined` if the line doesn't match any known pattern.
pub fn parse_instruction(line: &str, label_name_to_label: &BTreeMap<String, Label>) -> Instruction {
    parse_instruction_with_platform(line, label_name_to_label, None)
}

/// Like `parse_instruction`, but with an optional platform for resolving `call <imm>`.
pub fn parse_instruction_with_platform(
    line: &str,
    label_name_to_label: &BTreeMap<String, Label>,
    platform: Option<&dyn crate::platform::EbpfPlatform>,
) -> Instruction {
    // Strip comments
    let text = match line.find(';') {
        Some(pos) => &line[..pos],
        None => line,
    };
    let text = text.trim_end();
    if text.is_empty() {
        return Instruction::Undefined(Undefined { opcode: 0 });
    }

    // exit
    if RE_EXIT.is_match(text) {
        return Instruction::Exit(Exit {
            stack_frame_prefix: Rc::from(""),
        });
    }

    // call <imm>
    if let Some(m) = RE_CALL_IMM.captures(text) {
        let func = to_int(m.get(1).unwrap().as_str());
        if let Some(plat) = platform {
            // An out-of-range helper id falls back to an undefined instruction
            // (which the verifier rejects) rather than aborting the parser.
            return match crate::ir::unmarshal::make_call_result(func, plat) {
                Ok(call) => Instruction::Call(call),
                Err(_) => Instruction::Undefined(Undefined { opcode: 0 }),
            };
        }
        return Instruction::Undefined(Undefined { opcode: 0 });
    }

    // call <label>
    if let Some(m) = RE_CALL_LABEL.captures(text) {
        let label_str = m.get(1).unwrap().as_str().to_string();
        return Instruction::CallLocal(CallLocal {
            target: label_name_to_label[&label_str].clone(),
            stack_frame_prefix: Rc::from(""),
        });
    }

    // callx <reg>
    if let Some(m) = RE_CALLX.captures(text) {
        return Instruction::Callx(Callx {
            func: reg(m.get(1).unwrap().as_str()),
        });
    }

    // call_btf <imm> module <imm>
    if let Some(m) = RE_CALL_BTF_MODULE.captures(text) {
        let module_val = to_int(m.get(2).unwrap().as_str());
        if module_val < 0 || module_val > i16::MAX as i32 {
            panic!("module value out of range in call_btf");
        }
        return Instruction::CallBtf(CallBtf {
            btf_id: to_int(m.get(1).unwrap().as_str()),
            module: module_val as i16,
        });
    }

    // call_btf <imm>
    if let Some(m) = RE_CALL_BTF.captures(text) {
        return Instruction::CallBtf(CallBtf {
            btf_id: to_int(m.get(1).unwrap().as_str()),
            module: 0,
        });
    }

    // <wreg> <op>= <wreg>  (binary reg-reg)
    if let Some(m) = RE_BIN_REG.captures(text) {
        let r = m.get(1).unwrap().as_str();
        let op_str = m.get(2).unwrap().as_str();
        let src = m.get(3).unwrap().as_str();
        if let Some(&op) = STR_TO_BINOP.get(op_str) {
            return Instruction::Bin(Bin {
                op,
                dst: reg(r),
                v: Value::Reg(reg(src)),
                is64: is64_reg(r),
                lddw: false,
            });
        }
    }

    // <wreg> = <unop> <wreg>  (unary operation)
    if let Some(m) = RE_UN.captures(text) {
        let dst_str = m.get(1).unwrap().as_str();
        let op_str = m.get(2).unwrap().as_str();
        let src_str = m.get(3).unwrap().as_str();
        if dst_str != src_str {
            panic!("Invalid unary operation: {}", text);
        }
        return Instruction::Un(Un {
            op: STR_TO_UNOP[op_str],
            dst: reg(dst_str),
            is64: is64_reg(dst_str),
        });
    }

    // <wreg> = map_val(<fd>) + <offset>
    if let Some(m) = RE_LOAD_MAP_ADDRESS.captures(text) {
        return Instruction::LoadMapAddress(LoadMapAddress {
            dst: reg(m.get(1).unwrap().as_str()),
            mapfd: to_int(m.get(2).unwrap().as_str()),
            offset: to_int(m.get(3).unwrap().as_str()),
        });
    }

    // <wreg> = map_fd_programs <fd>  or  <wreg> = map_fd <fd>
    if let Some(m) = RE_LOAD_MAP_FD.captures(text) {
        return Instruction::LoadMapFd(LoadMapFd {
            dst: reg(m.get(1).unwrap().as_str()),
            mapfd: to_int(m.get(2).unwrap().as_str()),
        });
    }

    // Pseudo-load instructions: variable_addr, code_addr, map_by_idx, mva(map_by_idx)
    {
        let pseudo_patterns: &[(&LazyLock<Regex>, PseudoAddressKind, bool)] = &[
            (
                &RE_PSEUDO_VARIABLE_ADDR,
                PseudoAddressKind::VariableAddr,
                false,
            ),
            (&RE_PSEUDO_CODE_ADDR, PseudoAddressKind::CodeAddr, false),
            (&RE_PSEUDO_MAP_BY_IDX, PseudoAddressKind::MapByIdx, false),
            (&RE_PSEUDO_MVA, PseudoAddressKind::MapValueByIdx, true),
        ];
        for &(re, kind, has_next_imm) in pseudo_patterns {
            if let Some(m) = re.captures(text) {
                return Instruction::LoadPseudo(LoadPseudo {
                    dst: reg(m.get(1).unwrap().as_str()),
                    addr: PseudoAddress {
                        kind,
                        imm: to_int(m.get(2).unwrap().as_str()),
                        next_imm: if has_next_imm {
                            to_int(m.get(3).unwrap().as_str())
                        } else {
                            0
                        },
                    },
                });
            }
        }
    }

    // <wreg> <op>= <imm> [ll]  (binary reg-imm)
    if let Some(m) = RE_BIN_IMM.captures(text) {
        let r = m.get(1).unwrap().as_str();
        let op_str = m.get(2).unwrap().as_str();
        let imm_str = m.get(3).unwrap().as_str();
        let ll_str = m.get(4).unwrap().as_str();
        let lddw = !ll_str.is_empty();
        if let Some(&op) = STR_TO_BINOP.get(op_str) {
            return Instruction::Bin(Bin {
                op,
                dst: reg(r),
                v: Value::Imm(imm(imm_str, lddw)),
                is64: is64_reg(r),
                lddw,
            });
        }
    }

    // <reg> = *(u<width> *)(<reg> +/- <imm>)  (memory load)
    if let Some(m) = RE_MEM_LOAD.captures(text) {
        return Instruction::Mem(Mem {
            access: make_deref(
                m.get(2).unwrap().as_str(),
                m.get(3).unwrap().as_str(),
                m.get(4).unwrap().as_str(),
                m.get(5).unwrap().as_str(),
                m.get(6).unwrap().as_str(),
            ),
            value: Value::Reg(reg(m.get(1).unwrap().as_str())),
            is_load: true,
            is_signed: m.get(2).unwrap().as_str() == "s",
        });
    }

    // *(u<width> *)(<reg> +/- <imm>) = <reg_or_imm>  (memory store)
    if let Some(m) = RE_MEM_STORE.captures(text) {
        return Instruction::Mem(Mem {
            access: make_deref(
                m.get(1).unwrap().as_str(),
                m.get(2).unwrap().as_str(),
                m.get(3).unwrap().as_str(),
                m.get(4).unwrap().as_str(),
                m.get(5).unwrap().as_str(),
            ),
            value: reg_or_imm(m.get(6).unwrap().as_str()),
            is_load: false,
            is_signed: false,
        });
    }

    // lock *(u<width> *)(<reg> +/- <imm>) <atomicop> <reg> [fetch]
    if let Some(m) = RE_ATOMIC.captures(text) {
        let op = STR_TO_ATOMICOP[m.get(6).unwrap().as_str()];
        let fetch_matched = m.get(8).is_some();
        return Instruction::Atomic(Atomic {
            op,
            fetch: fetch_matched || op == AtomicOp::XCHG || op == AtomicOp::CMPXCHG,
            access: make_deref(
                m.get(1).unwrap().as_str(),
                m.get(2).unwrap().as_str(),
                m.get(3).unwrap().as_str(),
                m.get(4).unwrap().as_str(),
                m.get(5).unwrap().as_str(),
            ),
            valreg: reg(m.get(7).unwrap().as_str()),
        });
    }

    // r0 = *(u<width> *)skb[...]  (packet access)
    if let Some(m) = RE_PACKET.captures(text) {
        let width = STR_TO_WIDTH[m.get(1).unwrap().as_str()];
        let access = m.get(2).unwrap().as_str();

        if let Some(m2) = RE_PACKET_REG.captures(access) {
            return Instruction::Packet(Packet {
                width,
                offset: 0,
                regoffset: Some(reg(m2.get(1).unwrap().as_str())),
            });
        }
        if let Some(m2) = RE_PACKET_IMM.captures(access) {
            return Instruction::Packet(Packet {
                width,
                offset: imm(m2.get(1).unwrap().as_str(), false).v as i32,
                regoffset: None,
            });
        }
        if let Some(m2) = RE_PACKET_REG_PM_REG.captures(access) {
            return Instruction::Packet(Packet {
                width,
                offset: 0, // ? (same as C++)
                regoffset: Some(reg(m2.get(2).unwrap().as_str())),
            });
        }
        if let Some(m2) = RE_PACKET_REG_PM_IMM.captures(access) {
            return Instruction::Packet(Packet {
                width,
                offset: imm(m2.get(2).unwrap().as_str(), false).v as i32,
                regoffset: Some(reg(m2.get(1).unwrap().as_str())),
            });
        }
        return Instruction::Undefined(Undefined { opcode: 0 });
    }

    // assume <wreg> <cmpop> <reg_or_imm>
    if let Some(m) = RE_ASSUME.captures(text) {
        let left_str = m.get(1).unwrap().as_str();
        let op_str = m.get(2).unwrap().as_str();
        let right_str = m.get(3).unwrap().as_str();
        return Instruction::Assume(Assume {
            cond: Condition {
                op: STR_TO_CMPOP[op_str],
                left: reg(left_str),
                right: reg_or_imm(right_str),
                is64: is64_reg(left_str),
            },
            is_implicit: false,
        });
    }

    // [if <wreg> <cmpop> <reg_or_imm> ]goto [<imm>] <label>
    {
        if let Some(m) = RE_GOTO.captures(text) {
            let label_str = m.get(5).unwrap().as_str().to_string();
            let cond = if let Some(m1) = m.get(1) {
                let left_str = m1.as_str();
                Some(Condition {
                    op: STR_TO_CMPOP[m.get(2).unwrap().as_str()],
                    left: reg(left_str),
                    right: reg_or_imm(m.get(3).unwrap().as_str()),
                    is64: is64_reg(left_str),
                })
            } else {
                None
            };
            return Instruction::Jmp(Jmp {
                cond,
                target: label_name_to_label[&label_str].clone(),
            });
        }
    }

    Instruction::Undefined(Undefined { opcode: 0 })
}

// ---------------------------------------------------------------------------
// parse_program (for completeness; marked [[maybe_unused]] in C++)
// ---------------------------------------------------------------------------

/// Parse a multi-line eBPF assembly program into an instruction sequence.
///
/// Each line may optionally be preceded by a label of the form `<name>:`.
/// Lines with only whitespace or that parse to `Undefined` are skipped.
pub fn parse_program(source: &str) -> InstructionSeq {
    let mut labeled_insts: InstructionSeq = Vec::new();
    let mut seen_labels: BTreeSet<Label> = BTreeSet::new();
    let mut next_label: Option<Label> = None;

    for line in source.lines() {
        let mut remaining = line.to_string();

        if let Some(m) = RE_LABEL.find(&remaining) {
            let caps = RE_LABEL.captures(&remaining).unwrap();
            let label_text = caps.get(1).unwrap().as_str();
            let l = Label::new(to_int(label_text));
            if seen_labels.contains(&l) {
                panic!("duplicate labels");
            }
            seen_labels.insert(l.clone());
            next_label = Some(l);
            remaining = remaining[m.end()..].to_string();
        }

        if let Some(m) = RE_PREFIX.find(&remaining) {
            remaining = remaining[m.end()..].to_string();
        }

        if remaining.is_empty() {
            continue;
        }

        let ins = parse_instruction(&remaining, &BTreeMap::new());
        if matches!(ins, Instruction::Undefined(_)) {
            continue;
        }

        if next_label.is_none() {
            next_label = Some(Label::new(labeled_insts.len() as i32));
        }

        labeled_insts.push((next_label.take().unwrap(), ins, None));
    }

    labeled_insts
}

// ---------------------------------------------------------------------------
// special_var
// ---------------------------------------------------------------------------

/// Parse a register variable from regex capture groups: `regkind(kind_str)` + `regnum(reg_str)`.
fn parse_reg_var(
    m: &regex::Captures,
    regnum_group: usize,
    kind_group: usize,
    registry: &mut VariableRegistry,
) -> Variable {
    let kind_str = m.get(kind_group).unwrap().as_str();
    let kind = regkind(kind_str).unwrap_or_else(|| panic!("Unknown kind: {}", kind_str));
    registry.reg(kind, regnum(m.get(regnum_group).unwrap().as_str()))
}

fn special_var(s: &str, registry: &mut VariableRegistry) -> Variable {
    match s {
        "packet_size" => registry.packet_size(),
        "meta_offset" => registry.meta_offset(),
        _ => panic!("Bad special variable: {}", s),
    }
}

// ---------------------------------------------------------------------------
// TypeValueConstraints
// ---------------------------------------------------------------------------

/// Parsed type and value constraints from a set of string constraints.
pub struct TypeValueConstraints {
    /// Type equality constraints: `(v1, v2)` means `v1.type = v2.type`.
    pub type_equalities: Vec<(Variable, Variable)>,
    /// Direct TypeSet restrictions for type variables.
    pub type_restrictions: Vec<(Variable, crate::crab::type_encoding::TypeSet)>,
    pub value_csts: Vec<LinearConstraint>,
}

// ---------------------------------------------------------------------------
// parse_linear_constraints
// ---------------------------------------------------------------------------

/// Parse a set of string constraints into type constraints, value constraints,
/// and numeric ranges.
///
/// `constraints` is a set of strings like `"r0.type=number"`, `"r1.svalue=42"`, etc.
/// `numeric_ranges` is populated with `Interval` values for stack numeric-typed ranges.
pub fn parse_linear_constraints(
    constraints: &BTreeSet<String>,
    numeric_ranges: &mut Vec<Interval>,
    registry: &mut VariableRegistry,
) -> TypeValueConstraints {
    let mut value_csts: Vec<LinearConstraint> = Vec::new();
    let mut type_equalities: Vec<(Variable, Variable)> = Vec::new();
    let mut type_restrictions: Vec<(Variable, crate::crab::type_encoding::TypeSet)> = Vec::new();

    for cst_text in constraints {
        if let Some(m) = RE_SPECIAL_EQ_IMM.captures(cst_text) {
            // SPECIAL_VAR = IMM
            let d = special_var(m.get(1).unwrap().as_str(), registry);
            let val = signed_number(m.get(2).unwrap().as_str());
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(val),
            ));
        } else if let Some(m) = RE_SPECIAL_EQ_INTERVAL.captures(cst_text) {
            // SPECIAL_VAR = [lb, ub]
            let d = special_var(m.get(1).unwrap().as_str(), registry);
            let lb = signed_number(m.get(2).unwrap().as_str());
            let ub = signed_number(m.get(3).unwrap().as_str());
            value_csts.push(leq(LinearExpression::from(lb), LinearExpression::from(d)));
            value_csts.push(leq(LinearExpression::from(d), LinearExpression::from(ub)));
        } else if let Some(m) = RE_SPECIAL_EQ_REG_KIND.captures(cst_text) {
            // SPECIAL_VAR = REG.KIND
            let d = special_var(m.get(1).unwrap().as_str(), registry);
            let s = parse_reg_var(&m, 2, 3, registry);
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(s),
            ));
        } else if let Some(m) = RE_REG_KIND_EQ_SPECIAL.captures(cst_text) {
            // REG.KIND = SPECIAL_VAR
            let d = parse_reg_var(&m, 1, 2, registry);
            let s = special_var(m.get(3).unwrap().as_str(), registry);
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(s),
            ));
        } else if let Some(m) = RE_REG_KIND_EQ_REG_KIND.captures(cst_text) {
            // REG.KIND = REG.KIND
            let d = parse_reg_var(&m, 1, 2, registry);
            let s = parse_reg_var(&m, 3, 4, registry);
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(s),
            ));
        } else if let Some(m) = RE_REG_TYPE_EQ_REG_TYPE.captures(cst_text) {
            // REG.type = REG.type
            let d = registry.type_reg(regnum(m.get(1).unwrap().as_str()));
            let s = registry.type_reg(regnum(m.get(2).unwrap().as_str()));
            type_equalities.push((d, s));
        } else if let Some(m) = RE_REG_TYPE_EQ_TYPE.captures(cst_text) {
            // REG.type = TYPE
            let d = registry.type_reg(regnum(m.get(1).unwrap().as_str()));
            let enc = string_to_type_encoding(m.get(2).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown type encoding: {}", m.get(2).unwrap().as_str()));
            type_restrictions.push((d, crate::crab::type_encoding::TypeSet::singleton(enc)));
        } else if let Some(m) = RE_REG_TYPE_IN_TYPESET.captures(cst_text) {
            // REG.type in { TYPE, TYPE, ... }
            let d = registry.type_reg(regnum(m.get(1).unwrap().as_str()));
            let inside = m.get(2).unwrap().as_str();

            let mut ts = crate::crab::type_encoding::TypeSet::empty();
            for cap in RE_TYPE_TOK.captures_iter(inside) {
                let sym = cap.get(1).unwrap().as_str();
                let enc = string_to_type_encoding(sym)
                    .unwrap_or_else(|| panic!("Unknown type encoding: {}", sym));
                ts = ts.union(crate::crab::type_encoding::TypeSet::singleton(enc));
            }

            if ts.is_empty() {
                panic!("Empty type set in 'in {{...}}' constraint: {}", cst_text);
            }

            type_restrictions.push((d, ts));
        } else if let Some(m) = RE_REG_KIND_EQ_IMM.captures(cst_text) {
            // REG.KIND = IMM
            let d = parse_reg_var(&m, 1, 2, registry);
            let value = if m.get(2).unwrap().as_str() == "uvalue" {
                unsigned_number(m.get(3).unwrap().as_str())
            } else {
                signed_number(m.get(3).unwrap().as_str())
            };
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(value),
            ));
        } else if let Some(m) = RE_REG_KIND_EQ_INTERVAL.captures(cst_text) {
            // REG.KIND = [lb, ub]
            let d = parse_reg_var(&m, 1, 2, registry);
            let (lb, ub) = if m.get(2).unwrap().as_str() == "uvalue" {
                (
                    unsigned_number(m.get(3).unwrap().as_str()),
                    unsigned_number(m.get(4).unwrap().as_str()),
                )
            } else {
                (
                    signed_number(m.get(3).unwrap().as_str()),
                    signed_number(m.get(4).unwrap().as_str()),
                )
            };
            value_csts.push(leq(LinearExpression::from(lb), LinearExpression::from(d)));
            value_csts.push(leq(LinearExpression::from(d), LinearExpression::from(ub)));
        } else if let Some(m) = RE_REG_KIND_DIFF_LEQ.captures(cst_text) {
            // REG.KIND - REG.KIND <= IMM
            let d = parse_reg_var(&m, 1, 2, registry);
            let s = parse_reg_var(&m, 3, 4, registry);
            let diff = signed_number(m.get(5).unwrap().as_str());
            // d - s <= diff
            value_csts.push(leq(
                LinearExpression::from(d) - LinearExpression::from(s),
                LinearExpression::from(diff),
            ));
        } else if let Some(m) = RE_STACK_RANGE_TYPE.captures(cst_text) {
            // s[lb...ub].type = TYPE
            let type_enc = string_to_type_encoding(m.get(3).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown type encoding: {}", m.get(3).unwrap().as_str()));
            let lb = signed_number(m.get(1).unwrap().as_str());
            let ub = signed_number(m.get(2).unwrap().as_str());
            if type_enc == T_NUM {
                numeric_ranges.push(Interval::from_number_pair(lb, ub));
            } else {
                let size = ub - lb + Number::from(1i32);
                let d = registry.cell_var(DataKind::Types, &lb, &size);
                type_restrictions
                    .push((d, crate::crab::type_encoding::TypeSet::singleton(type_enc)));
            }
        } else if let Some(m) = RE_STACK_RANGE_SVALUE.captures(cst_text) {
            // s[lb...ub].svalue = IMM
            let lb = signed_number(m.get(1).unwrap().as_str());
            let ub = signed_number(m.get(2).unwrap().as_str());
            let size = ub - lb + Number::from(1i32);
            let d = registry.cell_var(DataKind::Svalues, &lb, &size);
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(signed_number(m.get(3).unwrap().as_str())),
            ));
        } else if let Some(m) = RE_STACK_RANGE_UVALUE.captures(cst_text) {
            // s[lb...ub].uvalue = IMM
            let lb = signed_number(m.get(1).unwrap().as_str());
            let ub = signed_number(m.get(2).unwrap().as_str());
            let size = ub - lb + Number::from(1i32);
            let d = registry.cell_var(DataKind::Uvalues, &lb, &size);
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(unsigned_number(m.get(3).unwrap().as_str())),
            ));
        } else {
            panic!("Unknown constraint: {}", cst_text);
        }
    }

    TypeValueConstraints {
        type_equalities,
        type_restrictions,
        value_csts,
    }
}
