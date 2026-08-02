// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Label type for control-flow graph nodes.

use std::fmt;

const STACK_FRAME_DELIMITER: char = '/';

/// Program counter type. cpu=v4 supports 32-bit PC offsets.
pub type Pc = u32;

/// A label identifying a node in the control-flow graph.
///
/// Each label represents either a single instruction or a jump edge.
/// The `from` field is the instruction index, and `to` is the jump target
/// (or -1 for non-jump instructions).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Label {
    /// Variable prefix when calling this label (for inlined function macros).
    pub stack_frame_prefix: String,
    /// Jump source, or simply index of instruction.
    pub from: i32,
    /// Jump target or -1.
    pub to: i32,
    /// Special label for special instructions (e.g. "counter").
    pub special_label: String,
}

impl Label {
    /// The entry node of a CFG.
    pub fn entry() -> Label {
        Label {
            stack_frame_prefix: String::new(),
            from: -1,
            to: -1,
            special_label: String::new(),
        }
    }

    /// The exit node of a CFG.
    pub fn exit() -> Label {
        Label {
            stack_frame_prefix: String::new(),
            from: i32::MAX,
            to: i32::MAX,
            special_label: String::new(),
        }
    }

    /// Create a label for a single instruction (non-jump).
    pub fn new(index: i32) -> Label {
        Label {
            stack_frame_prefix: String::new(),
            from: index,
            to: -1,
            special_label: String::new(),
        }
    }

    /// Create a label with explicit from/to.
    pub fn new_with_to(index: i32, to: i32) -> Label {
        Label {
            stack_frame_prefix: String::new(),
            from: index,
            to,
            special_label: String::new(),
        }
    }

    /// Create a label with explicit from/to/prefix.
    pub fn new_full(index: i32, to: i32, stack_frame_prefix: String) -> Label {
        Label {
            stack_frame_prefix,
            from: index,
            to,
            special_label: String::new(),
        }
    }

    /// Create a jump label from a source label to a target label.
    pub fn make_jump(src_label: &Label, target_label: &Label) -> Label {
        Label {
            stack_frame_prefix: target_label.stack_frame_prefix.clone(),
            from: src_label.from,
            to: target_label.from,
            special_label: String::new(),
        }
    }

    /// Create a label for incrementing a loop counter.
    pub fn make_increment_counter(label: &Label) -> Label {
        Label {
            stack_frame_prefix: label.stack_frame_prefix.clone(),
            from: label.from,
            to: label.to,
            special_label: "counter".to_string(),
        }
    }

    /// Returns true if this label represents a jump (i.e., `to != -1`).
    pub fn isjump(&self) -> bool {
        self.to != -1
    }

    /// Returns the call stack depth.
    ///
    /// The call stack depth is the number of '/' separated components in the label,
    /// which is one more than the number of '/' separated components in the prefix,
    /// hence two more than the number of '/' in the prefix, if any.
    pub fn call_stack_depth(&self) -> i32 {
        if self.stack_frame_prefix.is_empty() {
            return 1;
        }
        2 + self
            .stack_frame_prefix
            .chars()
            .filter(|&c| c == STACK_FRAME_DELIMITER)
            .count() as i32
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Label::entry() {
            return write!(f, "entry");
        }
        if *self == Label::exit() {
            return write!(f, "exit");
        }
        if !self.stack_frame_prefix.is_empty() {
            write!(f, "{}{}", self.stack_frame_prefix, STACK_FRAME_DELIMITER)?;
        }
        write!(f, "{}", self.from)?;
        if self.to != -1 {
            write!(f, ":{}", self.to)?;
        }
        if !self.special_label.is_empty() {
            write!(f, " ({})", self.special_label)?;
        }
        Ok(())
    }
}

/// Convert a label to a 16-bit offset relative to `pc`.
///
/// Returns the offset if it fits in an i16, or 0 otherwise.
pub fn label_to_offset16(pc: Pc, label: &Label) -> i16 {
    let offset = label.from as i64 - pc as i64 - 1;
    let is16 = (i16::MIN as i64) <= offset && offset <= (i16::MAX as i64);
    if is16 { offset as i16 } else { 0 }
}

/// Convert a label to a 32-bit offset relative to `pc`.
///
/// Returns the offset if it does NOT fit in an i16, or 0 otherwise.
/// This is used with the JA32 opcode where the offset goes in `imm`.
pub fn label_to_offset32(pc: Pc, label: &Label) -> i32 {
    let offset = label.from as i64 - pc as i64 - 1;
    let is16 = (i16::MIN as i64) <= offset && offset <= (i16::MAX as i64);
    if is16 { 0 } else { offset as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_exit() {
        let entry = Label::entry();
        let exit = Label::exit();
        assert_eq!(entry.from, -1);
        assert_eq!(entry.to, -1);
        assert_eq!(exit.from, i32::MAX);
        assert_eq!(exit.to, i32::MAX);
        assert_ne!(entry, exit);
    }

    #[test]
    fn test_display_entry_exit() {
        assert_eq!(format!("{}", Label::entry()), "entry");
        assert_eq!(format!("{}", Label::exit()), "exit");
    }

    #[test]
    fn test_display_simple() {
        let label = Label::new(5);
        assert_eq!(format!("{label}"), "5");
    }

    #[test]
    fn test_display_jump() {
        let label = Label::new_with_to(3, 7);
        assert_eq!(format!("{label}"), "3:7");
    }

    #[test]
    fn test_display_with_prefix() {
        let label = Label::new_full(3, 7, "foo".to_string());
        assert_eq!(format!("{label}"), "foo/3:7");
    }

    #[test]
    fn test_display_with_special() {
        let mut label = Label::new_with_to(3, 7);
        label.special_label = "counter".to_string();
        assert_eq!(format!("{label}"), "3:7 (counter)");
    }

    #[test]
    fn test_isjump() {
        assert!(!Label::new(5).isjump());
        assert!(Label::new_with_to(3, 7).isjump());
    }

    #[test]
    fn test_call_stack_depth() {
        assert_eq!(Label::new(5).call_stack_depth(), 1);
        assert_eq!(
            Label::new_full(5, -1, "a".to_string()).call_stack_depth(),
            2
        );
        assert_eq!(
            Label::new_full(5, -1, "a/b".to_string()).call_stack_depth(),
            3
        );
    }

    #[test]
    fn test_ordering() {
        // Labels are ordered by (stack_frame_prefix, from, to, special_label)
        let a = Label::new(1);
        let b = Label::new(2);
        assert!(a < b);

        // entry < everything < exit
        assert!(Label::entry() < a);
        assert!(b < Label::exit());
    }

    #[test]
    fn test_make_jump() {
        let src = Label::new(3);
        let target = Label::new(7);
        let jump = Label::make_jump(&src, &target);
        assert_eq!(jump.from, 3);
        assert_eq!(jump.to, 7);
        assert!(jump.isjump());
    }

    #[test]
    fn test_make_increment_counter() {
        let label = Label::new_with_to(3, 7);
        let counter = Label::make_increment_counter(&label);
        assert_eq!(counter.from, 3);
        assert_eq!(counter.to, 7);
        assert_eq!(counter.special_label, "counter");
    }

    #[test]
    fn test_label_to_offset16() {
        // Offset fits in i16
        assert_eq!(label_to_offset16(10, &Label::new(20)), 9);
        // Offset doesn't fit in i16 — returns 0
        assert_eq!(label_to_offset16(0, &Label::new(40000)), 0);
    }

    #[test]
    fn test_label_to_offset32() {
        // Offset fits in i16 — returns 0
        assert_eq!(label_to_offset32(10, &Label::new(20)), 0);
        // Offset doesn't fit in i16 — returns the offset as i32
        assert_eq!(label_to_offset32(0, &Label::new(40000)), 39999);
    }
}
