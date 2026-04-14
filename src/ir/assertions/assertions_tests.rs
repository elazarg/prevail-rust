// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use super::*;
use crate::ir::syntax::{AccessType, Bin, BinOp, Deref, Reg, Value};
use crate::spec::config::EbpfRuntimeConfig;
use crate::spec::type_descriptors::ProgramInfo;
use crate::spec::vm_isa::AccessSize;

#[test]
fn test_assertions_add_reg() {
    let ins = Instruction::Bin(Bin {
        op: BinOp::ADD,
        dst: Reg { v: 1 },
        v: Value::Reg(Reg { v: 2 }),
        is64: true,
        lddw: false,
    });

    let info = ProgramInfo::default();
    let assertions = get_assertions(&ins, &info, &EbpfRuntimeConfig::default(), &None);

    // ADD dst, src (reg) should generate:
    // 1. TypeConstraint(dst, PtrOrNum)
    // 2. TypeConstraint(src, PtrOrNum)
    // 3. Addable(src, dst)
    // 4. Addable(dst, src)
    assert_eq!(assertions.len(), 4);

    if let Assertion::TypeConstraint(tc) = &assertions[0] {
        assert_eq!(tc.reg.v, 1);
        assert!(matches!(tc.types, TypeGroup::PtrOrNum));
    } else {
        panic!("Expected TypeConstraint");
    }
}

#[test]
fn test_assertions_add_imm() {
    let ins = Instruction::Bin(Bin {
        op: BinOp::ADD,
        dst: Reg { v: 1 },
        v: Value::Imm(Imm { v: 10 }),
        is64: true,
        lddw: false,
    });

    let info = ProgramInfo::default();
    let assertions = get_assertions(&ins, &info, &EbpfRuntimeConfig::default(), &None);

    // ADD dst, imm should generate:
    // 1. TypeConstraint(dst, PtrOrNum)
    assert_eq!(assertions.len(), 1);

    if let Assertion::TypeConstraint(tc) = &assertions[0] {
        assert_eq!(tc.reg.v, 1);
        assert!(matches!(tc.types, TypeGroup::PtrOrNum));
    } else {
        panic!("Expected TypeConstraint");
    }
}

#[test]
fn test_assertions_mem_load() {
    let val_reg = Reg { v: 2 };
    let base_reg = Reg { v: 1 };
    let ins = Instruction::Mem(Mem {
        access: Deref {
            basereg: base_reg,
            offset: 0,
            width: AccessSize::DWord,
        },
        value: Value::Reg(val_reg),
        is_load: true,
        is_signed: false,
    });

    let info = ProgramInfo::default();
    let assertions = get_assertions(&ins, &info, &EbpfRuntimeConfig::default(), &None);

    // Load should generate:
    // 1. TypeConstraint(base, Pointer)
    // 2. ValidAccess(base, offset=0, width=8, Read)
    assert_eq!(assertions.len(), 2);

    if let Assertion::TypeConstraint(tc) = &assertions[0] {
        assert_eq!(tc.reg.v, 1);
        assert!(matches!(tc.types, TypeGroup::Pointer));
    } else {
        panic!("Expected TypeConstraint for base register");
    }

    if let Assertion::ValidAccess(va) = &assertions[1] {
        assert_eq!(va.reg.v, 1);
        assert_eq!(va.offset, 0);
        assert!(matches!(va.access_type, AccessType::Read));
    } else {
        panic!("Expected ValidAccess");
    }
}
