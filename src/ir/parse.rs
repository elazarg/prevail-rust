// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Regex-based parser for eBPF assembly text.
//!
//! Ported from `src/ir/parse.cpp`. Used primarily for testing -- test fixtures
//! are written as text and need to be parsed into IR structures.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

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
    Assume, Atomic, AtomicOp, Bin, BinOp, CallLocal, Callx, Condition, ConditionOp, Deref, Exit,
    Imm, Instruction, InstructionSeq, Jmp, LoadMapAddress, LoadMapFd, Mem, Packet, Reg, Un, UnOp,
    Undefined, Value,
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
const KIND: &str = r"\s*(svalue|uvalue|ctx_offset|map_fd|map_fd_programs|packet_offset|shared_offset|stack_offset|shared_region_size|stack_numeric_size)\s*";
const INTERVAL: &str = r"\s*\[([-+]?\d+),\s*([-+]?\d+)\]?\s*";
const ARRAY_RANGE: &str = r"\s*\[([-+]?\d+)\.\.\.\s*([-+]?\d+)\]?\s*";
const DOT: &str = r"[.]";
const TYPE_PAT: &str = r"\s*(shared|number|packet|stack|ctx|map_fd|map_fd_programs)\s*";
const MAP_VAL: &str = r"\s*map_val\((\d+)\)\s*\+\s*(\d+)\s*";
const MAP_FD: &str = r"\s*map_fd\s+(\d+)\s*";
const MAP_FD_PROGRAMS: &str = r"\s*map_fd_programs\s+(\d+)\s*";

fn wrapped_label() -> String {
    format!(r"\s*{}\s*", LABEL_PAT)
}

// ---------------------------------------------------------------------------
// Lookup tables
// ---------------------------------------------------------------------------

fn str_to_binop() -> HashMap<&'static str, BinOp> {
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
}

fn str_to_unop() -> HashMap<&'static str, UnOp> {
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
}

fn str_to_cmpop() -> HashMap<&'static str, ConditionOp> {
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
}

fn str_to_atomicop() -> HashMap<&'static str, AtomicOp> {
    HashMap::from([
        ("+", AtomicOp::ADD),
        ("|", AtomicOp::OR),
        ("&", AtomicOp::AND),
        ("^", AtomicOp::XOR),
        ("x", AtomicOp::XCHG),
        ("cx", AtomicOp::CMPXCHG),
    ])
}

fn str_to_width() -> HashMap<&'static str, AccessSize> {
    HashMap::from([
        ("8", AccessSize::Byte),
        ("16", AccessSize::Half),
        ("32", AccessSize::Word),
        ("64", AccessSize::DWord),
    ])
}

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
        -(i32::from_str_radix(hex, 16).unwrap())
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
        -(i64::from_str_radix(hex, 16).unwrap())
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

fn make_deref(width_str: &str, basereg_str: &str, sign_str: &str, offset_str: &str) -> Deref {
    let offset = to_int(offset_str);
    let widths = str_to_width();
    Deref {
        width: widths[width_str],
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

    let binops = str_to_binop();
    let unops = str_to_unop();
    let cmpops = str_to_cmpop();
    let atomicops = str_to_atomicop();
    let widths = str_to_width();

    // exit
    if let Some(_m) = Regex::new(r"^exit$").unwrap().captures(text) {
        return Instruction::Exit(Exit {
            stack_frame_prefix: Rc::from(""),
        });
    }

    // call <imm>
    {
        let pat = format!("^call {}$", IMM);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let func = to_int(m.get(1).unwrap().as_str());
            if let Some(plat) = platform {
                return Instruction::Call(crate::ir::unmarshal::make_call(func, plat));
            }
            return Instruction::Undefined(Undefined { opcode: 0 });
        }
    }

    // call <label>
    {
        let pat = format!("^call {}$", wrapped_label());
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let label_str = m.get(1).unwrap().as_str().to_string();
            return Instruction::CallLocal(CallLocal {
                target: label_name_to_label[&label_str].clone(),
                stack_frame_prefix: Rc::from(""),
            });
        }
    }

    // callx <reg>
    {
        let pat = format!("^callx {}$", REG);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            return Instruction::Callx(Callx {
                func: reg(m.get(1).unwrap().as_str()),
            });
        }
    }

    // <wreg> <op>= <wreg>  (binary reg-reg)
    {
        let pat = format!("^{}{}{}$", WREG, OPASSIGN, WREG);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let r = m.get(1).unwrap().as_str();
            let op_str = m.get(2).unwrap().as_str();
            let src = m.get(3).unwrap().as_str();
            if let Some(&op) = binops.get(op_str) {
                return Instruction::Bin(Bin {
                    op,
                    dst: reg(r),
                    v: Value::Reg(reg(src)),
                    is64: is64_reg(r),
                    lddw: false,
                });
            }
        }
    }

    // <wreg> = <unop> <wreg>  (unary operation)
    {
        let pat = format!("^{}{}{}{}$", WREG, ASSIGN, UNOP, WREG);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let dst_str = m.get(1).unwrap().as_str();
            let op_str = m.get(2).unwrap().as_str();
            let src_str = m.get(3).unwrap().as_str();
            if dst_str != src_str {
                panic!("Invalid unary operation: {}", text);
            }
            return Instruction::Un(Un {
                op: unops[op_str],
                dst: reg(dst_str),
                is64: is64_reg(dst_str),
            });
        }
    }

    // <wreg> = map_val(<fd>) + <offset>
    {
        let pat = format!("^{}{}{}$", WREG, ASSIGN, MAP_VAL);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            return Instruction::LoadMapAddress(LoadMapAddress {
                dst: reg(m.get(1).unwrap().as_str()),
                mapfd: to_int(m.get(2).unwrap().as_str()),
                offset: to_int(m.get(3).unwrap().as_str()),
            });
        }
    }

    // <wreg> = map_fd_programs <fd>
    {
        let pat = format!("^{}{}{}$", WREG, ASSIGN, MAP_FD_PROGRAMS);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            return Instruction::LoadMapFd(LoadMapFd {
                dst: reg(m.get(1).unwrap().as_str()),
                mapfd: to_int(m.get(2).unwrap().as_str()),
            });
        }
    }

    // <wreg> = map_fd <fd>
    {
        let pat = format!("^{}{}{}$", WREG, ASSIGN, MAP_FD);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            return Instruction::LoadMapFd(LoadMapFd {
                dst: reg(m.get(1).unwrap().as_str()),
                mapfd: to_int(m.get(2).unwrap().as_str()),
            });
        }
    }

    // <wreg> <op>= <imm> [ll]  (binary reg-imm)
    {
        let pat = format!("^{}{}{}{}$", WREG, OPASSIGN, IMM, LONGLONG);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let r = m.get(1).unwrap().as_str();
            let op_str = m.get(2).unwrap().as_str();
            let imm_str = m.get(3).unwrap().as_str();
            let ll_str = m.get(4).unwrap().as_str();
            let lddw = !ll_str.is_empty();
            if let Some(&op) = binops.get(op_str) {
                return Instruction::Bin(Bin {
                    op,
                    dst: reg(r),
                    v: Value::Imm(imm(imm_str, lddw)),
                    is64: is64_reg(r),
                    lddw,
                });
            }
        }
    }

    // <reg> = *(u<width> *)(<reg> +/- <imm>)  (memory load)
    {
        let deref_pat = format!("{}{}u(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
        let inner = format!("{}{}{}", REG, PLUSMINUS, IMM);
        let pat = format!(
            "^{}{}{}{}{}{}$",
            REG, ASSIGN, deref_pat, LPAREN, inner, RPAREN
        );
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            return Instruction::Mem(Mem {
                access: make_deref(
                    m.get(2).unwrap().as_str(),
                    m.get(3).unwrap().as_str(),
                    m.get(4).unwrap().as_str(),
                    m.get(5).unwrap().as_str(),
                ),
                value: Value::Reg(reg(m.get(1).unwrap().as_str())),
                is_load: true,
            });
        }
    }

    // *(u<width> *)(<reg> +/- <imm>) = <reg_or_imm>  (memory store)
    {
        let deref_pat = format!("{}{}u(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
        let inner = format!("{}{}{}", REG, PLUSMINUS, IMM);
        let pat = format!(
            "^{}{}{}{}{}{}$",
            deref_pat, LPAREN, inner, RPAREN, ASSIGN, REG_OR_IMM
        );
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            return Instruction::Mem(Mem {
                access: make_deref(
                    m.get(1).unwrap().as_str(),
                    m.get(2).unwrap().as_str(),
                    m.get(3).unwrap().as_str(),
                    m.get(4).unwrap().as_str(),
                ),
                value: reg_or_imm(m.get(5).unwrap().as_str()),
                is_load: false,
            });
        }
    }

    // lock *(u<width> *)(<reg> +/- <imm>) <atomicop> <reg> [fetch]
    {
        let deref_pat = format!("{}{}u(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
        let inner = format!("{}{}{}", REG, PLUSMINUS, IMM);
        let pat = format!(
            r"^lock {}{}{}{}{}{}( fetch)?$",
            deref_pat, LPAREN, inner, RPAREN, ATOMICOP, REG
        );
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let op = atomicops[m.get(5).unwrap().as_str()];
            let fetch_matched = m.get(7).is_some();
            return Instruction::Atomic(Atomic {
                op,
                fetch: fetch_matched || op == AtomicOp::XCHG || op == AtomicOp::CMPXCHG,
                access: make_deref(
                    m.get(1).unwrap().as_str(),
                    m.get(2).unwrap().as_str(),
                    m.get(3).unwrap().as_str(),
                    m.get(4).unwrap().as_str(),
                ),
                valreg: reg(m.get(6).unwrap().as_str()),
            });
        }
    }

    // r0 = *(u<width> *)skb[...]  (packet access)
    {
        let deref_pat = format!("{}{}u(\\d+){}{}", STAR, LPAREN, STAR, RPAREN);
        let pat = format!(r"^r0 = {}skb\[(.*)\]$", deref_pat);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let width = widths[m.get(1).unwrap().as_str()];
            let access = m.get(2).unwrap().as_str();

            // Try matching the access expression
            let reg_pat = format!("^{}$", REG);
            let imm_pat = format!("^{}$", IMM);
            let reg_plusminus_reg_pat = format!("^{}{}{}$", REG, PLUSMINUS, REG);
            let reg_plusminus_imm_pat = format!("^{}{}{}$", REG, PLUSMINUS, IMM);

            if let Some(m2) = Regex::new(&reg_pat).unwrap().captures(access) {
                return Instruction::Packet(Packet {
                    width,
                    offset: 0,
                    regoffset: Some(reg(m2.get(1).unwrap().as_str())),
                });
            }
            if let Some(m2) = Regex::new(&imm_pat).unwrap().captures(access) {
                return Instruction::Packet(Packet {
                    width,
                    offset: imm(m2.get(1).unwrap().as_str(), false).v as i32,
                    regoffset: None,
                });
            }
            if let Some(m2) = Regex::new(&reg_plusminus_reg_pat).unwrap().captures(access) {
                return Instruction::Packet(Packet {
                    width,
                    offset: 0, // ? (same as C++)
                    regoffset: Some(reg(m2.get(2).unwrap().as_str())),
                });
            }
            if let Some(m2) = Regex::new(&reg_plusminus_imm_pat).unwrap().captures(access) {
                return Instruction::Packet(Packet {
                    width,
                    offset: imm(m2.get(2).unwrap().as_str(), false).v as i32,
                    regoffset: Some(reg(m2.get(1).unwrap().as_str())),
                });
            }
            return Instruction::Undefined(Undefined { opcode: 0 });
        }
    }

    // assume <wreg> <cmpop> <reg_or_imm>
    {
        let pat = format!("^assume {}{}{}$", WREG, CMPOP, REG_OR_IMM);
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let left_str = m.get(1).unwrap().as_str();
            let op_str = m.get(2).unwrap().as_str();
            let right_str = m.get(3).unwrap().as_str();
            return Instruction::Assume(Assume {
                cond: Condition {
                    op: cmpops[op_str],
                    left: reg(left_str),
                    right: reg_or_imm(right_str),
                    is64: is64_reg(left_str),
                },
                is_implicit: false,
            });
        }
    }

    // [if <wreg> <cmpop> <reg_or_imm> ]goto [<imm>] <label>
    {
        let pat = format!(
            "^(?:if {}{}{})?goto\\s+(?:{})?{}$",
            WREG,
            CMPOP,
            REG_OR_IMM,
            IMM,
            wrapped_label()
        );
        if let Some(m) = Regex::new(&pat).unwrap().captures(text) {
            let label_str = m.get(5).unwrap().as_str().to_string();
            let cond = if m.get(1).is_some() {
                let left_str = m.get(1).unwrap().as_str();
                Some(Condition {
                    op: cmpops[m.get(2).unwrap().as_str()],
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
    let label_re = Regex::new(&format!("{}:", LABEL_PAT)).unwrap();
    let prefix_re = Regex::new(r"^\s*(\d+:)?\s*").unwrap();

    let mut labeled_insts: InstructionSeq = Vec::new();
    let mut seen_labels: BTreeSet<Label> = BTreeSet::new();
    let mut next_label: Option<Label> = None;

    for line in source.lines() {
        let mut remaining = line.to_string();

        if let Some(m) = label_re.find(&remaining) {
            let caps = label_re.captures(&remaining).unwrap();
            let label_text = caps.get(1).unwrap().as_str();
            let l = Label::new(to_int(label_text));
            if seen_labels.contains(&l) {
                panic!("duplicate labels");
            }
            seen_labels.insert(l.clone());
            next_label = Some(l);
            remaining = remaining[m.end()..].to_string();
        }

        if let Some(m) = prefix_re.find(&remaining) {
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
    pub type_csts: Vec<LinearConstraint>,
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
    let mut type_csts: Vec<LinearConstraint> = Vec::new();

    // Pre-compile all the regex patterns.
    let re_special_eq_imm = Regex::new(&format!("^{}={}$", SPECIAL_VAR, IMM)).unwrap();
    let re_special_eq_interval = Regex::new(&format!("^{}={}$", SPECIAL_VAR, INTERVAL)).unwrap();
    let re_special_eq_reg_kind =
        Regex::new(&format!("^{}={}{}{}$", SPECIAL_VAR, REG, DOT, KIND)).unwrap();
    let re_reg_kind_eq_special =
        Regex::new(&format!("^{}{}{}={}$", REG, DOT, KIND, SPECIAL_VAR)).unwrap();
    let re_reg_kind_eq_reg_kind =
        Regex::new(&format!("^{}{}{}={}{}{}$", REG, DOT, KIND, REG, DOT, KIND)).unwrap();
    let re_reg_type_eq_reg_type =
        Regex::new(&format!("^{}{}type={}{}type$", REG, DOT, REG, DOT)).unwrap();
    let re_reg_type_eq_type = Regex::new(&format!("^{}{}type={}$", REG, DOT, TYPE_PAT)).unwrap();
    let re_reg_type_in_typeset =
        Regex::new(&format!("^{}{}type{}{}$", REG, DOT, IN, TYPE_SET)).unwrap();
    let re_reg_kind_eq_imm = Regex::new(&format!("^{}{}{}={}$", REG, DOT, KIND, IMM)).unwrap();
    let re_reg_kind_eq_interval =
        Regex::new(&format!("^{}{}{}={}$", REG, DOT, KIND, INTERVAL)).unwrap();
    let re_reg_kind_diff_leq = Regex::new(&format!(
        "^{}{}{}-{}{}{}<={}$",
        REG, DOT, KIND, REG, DOT, KIND, IMM
    ))
    .unwrap();
    let re_stack_range_type =
        Regex::new(&format!("^s{}{}type={}$", ARRAY_RANGE, DOT, TYPE_PAT)).unwrap();
    let re_stack_range_svalue =
        Regex::new(&format!("^s{}{}svalue={}$", ARRAY_RANGE, DOT, IMM)).unwrap();
    let re_stack_range_uvalue =
        Regex::new(&format!("^s{}{}uvalue={}$", ARRAY_RANGE, DOT, IMM)).unwrap();

    let type_tok_regex = Regex::new(TYPE_PAT).unwrap();

    for cst_text in constraints {
        if let Some(m) = re_special_eq_imm.captures(cst_text) {
            // SPECIAL_VAR = IMM
            let d = special_var(m.get(1).unwrap().as_str(), registry);
            let val = signed_number(m.get(2).unwrap().as_str());
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(val),
            ));
        } else if let Some(m) = re_special_eq_interval.captures(cst_text) {
            // SPECIAL_VAR = [lb, ub]
            let d = special_var(m.get(1).unwrap().as_str(), registry);
            let lb = signed_number(m.get(2).unwrap().as_str());
            let ub = signed_number(m.get(3).unwrap().as_str());
            value_csts.push(leq(LinearExpression::from(lb), LinearExpression::from(d)));
            value_csts.push(leq(LinearExpression::from(d), LinearExpression::from(ub)));
        } else if let Some(m) = re_special_eq_reg_kind.captures(cst_text) {
            // SPECIAL_VAR = REG.KIND
            let d = special_var(m.get(1).unwrap().as_str(), registry);
            let kind = regkind(m.get(3).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown kind: {}", m.get(3).unwrap().as_str()));
            let s = registry.reg(kind, regnum(m.get(2).unwrap().as_str()));
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(s),
            ));
        } else if let Some(m) = re_reg_kind_eq_special.captures(cst_text) {
            // REG.KIND = SPECIAL_VAR
            let kind = regkind(m.get(2).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown kind: {}", m.get(2).unwrap().as_str()));
            let d = registry.reg(kind, regnum(m.get(1).unwrap().as_str()));
            let s = special_var(m.get(3).unwrap().as_str(), registry);
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(s),
            ));
        } else if let Some(m) = re_reg_kind_eq_reg_kind.captures(cst_text) {
            // REG.KIND = REG.KIND
            let kind1 = regkind(m.get(2).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown kind: {}", m.get(2).unwrap().as_str()));
            let d = registry.reg(kind1, regnum(m.get(1).unwrap().as_str()));
            let kind2 = regkind(m.get(4).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown kind: {}", m.get(4).unwrap().as_str()));
            let s = registry.reg(kind2, regnum(m.get(3).unwrap().as_str()));
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(s),
            ));
        } else if let Some(m) = re_reg_type_eq_reg_type.captures(cst_text) {
            // REG.type = REG.type
            let d = registry.type_reg(regnum(m.get(1).unwrap().as_str()));
            let s = registry.type_reg(regnum(m.get(2).unwrap().as_str()));
            type_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(s),
            ));
        } else if let Some(m) = re_reg_type_eq_type.captures(cst_text) {
            // REG.type = TYPE
            let d = registry.type_reg(regnum(m.get(1).unwrap().as_str()));
            let enc = string_to_type_encoding(m.get(2).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown type encoding: {}", m.get(2).unwrap().as_str()));
            type_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(enc as i32),
            ));
        } else if let Some(m) = re_reg_type_in_typeset.captures(cst_text) {
            // REG.type in { TYPE, TYPE, ... }
            let d = registry.type_reg(regnum(m.get(1).unwrap().as_str()));
            let inside = m.get(2).unwrap().as_str();

            let mut any = false;
            let mut lb_val = Number::from(0i32);
            let mut ub_val = Number::from(0i32);

            for cap in type_tok_regex.captures_iter(inside) {
                let sym = cap.get(1).unwrap().as_str();
                let enc = string_to_type_encoding(sym)
                    .unwrap_or_else(|| panic!("Unknown type encoding: {}", sym));
                let n = Number::from(enc as i32);
                if !any {
                    lb_val = n;
                    ub_val = n;
                    any = true;
                } else {
                    if n < lb_val {
                        lb_val = n;
                    }
                    if n > ub_val {
                        ub_val = n;
                    }
                }
            }

            if !any {
                panic!("Empty type set in 'in {{...}}' constraint: {}", cst_text);
            }

            type_csts.push(leq(
                LinearExpression::from(lb_val),
                LinearExpression::from(d),
            ));
            type_csts.push(leq(
                LinearExpression::from(d),
                LinearExpression::from(ub_val),
            ));
        } else if let Some(m) = re_reg_kind_eq_imm.captures(cst_text) {
            // REG.KIND = IMM
            let kind_str = m.get(2).unwrap().as_str();
            let kind = regkind(kind_str).unwrap_or_else(|| panic!("Unknown kind: {}", kind_str));
            let d = registry.reg(kind, regnum(m.get(1).unwrap().as_str()));
            let value = if kind_str == "uvalue" {
                unsigned_number(m.get(3).unwrap().as_str())
            } else {
                signed_number(m.get(3).unwrap().as_str())
            };
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(value),
            ));
        } else if let Some(m) = re_reg_kind_eq_interval.captures(cst_text) {
            // REG.KIND = [lb, ub]
            let kind_str = m.get(2).unwrap().as_str();
            let kind = regkind(kind_str).unwrap_or_else(|| panic!("Unknown kind: {}", kind_str));
            let d = registry.reg(kind, regnum(m.get(1).unwrap().as_str()));
            let (lb, ub) = if kind_str == "uvalue" {
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
        } else if let Some(m) = re_reg_kind_diff_leq.captures(cst_text) {
            // REG.KIND - REG.KIND <= IMM
            let kind1 = regkind(m.get(2).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown kind: {}", m.get(2).unwrap().as_str()));
            let d = registry.reg(kind1, regnum(m.get(1).unwrap().as_str()));
            let kind2 = regkind(m.get(4).unwrap().as_str())
                .unwrap_or_else(|| panic!("Unknown kind: {}", m.get(4).unwrap().as_str()));
            let s = registry.reg(kind2, regnum(m.get(3).unwrap().as_str()));
            let diff = signed_number(m.get(5).unwrap().as_str());
            // d - s <= diff
            value_csts.push(leq(
                LinearExpression::from(d) - LinearExpression::from(s),
                LinearExpression::from(diff),
            ));
        } else if let Some(m) = re_stack_range_type.captures(cst_text) {
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
                type_csts.push(expr_eq(
                    LinearExpression::from(d),
                    LinearExpression::from(type_enc as i32),
                ));
            }
        } else if let Some(m) = re_stack_range_svalue.captures(cst_text) {
            // s[lb...ub].svalue = IMM
            let lb = signed_number(m.get(1).unwrap().as_str());
            let ub = signed_number(m.get(2).unwrap().as_str());
            let size = ub - lb + Number::from(1i32);
            let d = registry.cell_var(DataKind::Svalues, &lb, &size);
            value_csts.push(expr_eq(
                LinearExpression::from(d),
                LinearExpression::from(signed_number(m.get(3).unwrap().as_str())),
            ));
        } else if let Some(m) = re_stack_range_uvalue.captures(cst_text) {
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
        type_csts,
        value_csts,
    }
}
