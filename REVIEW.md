# Type Domain DSU Implementation — Review Notes

## Summary

Replaced zone-based `TypeDomain` with DSU (Disjoint Set Union) based domain that
tracks must-equality between type variables and exact type sets per equivalence class.

## Bugs Found in Original Implementation

### 1. Zone Domain Overapproximation for Types (Design Issue)

The original `TypeDomain` used a `NumAbsDomain` (zone/DBM domain) to track types as
integer-valued variables. Since zone domains are **convex**, they represent intervals,
not arbitrary subsets. This means `{T_MAP(-5), T_SHARED(0)}` becomes the interval
`[-5, 0]`, which includes 4 spurious intermediate types (T_MAP_PROGRAMS, T_CTX,
T_PACKET, T_STACK).

The DSU-based replacement tracks exact type sets using a `u8` bitset (`TypeSet`),
eliminating all spurious types.

**Impact**: The zone domain's `iterate_types` and type group checks could consider
types that are actually impossible. For example, a variable with types
`{map, shared}` would pass `is_in_group(Pointer)` in the zone domain (since the
interval `[-5, 0]` is a subset of `[-5, 0]` i.e. all pointer types), but the DSU
domain correctly reports that `map` is NOT a singleton pointer type.

This is the motivating issue for the entire refactoring.

### 2. `is_in_group` Encoding-Order Dependency (Design Issue)

The original `is_in_group` implementation for several `TypeGroup` variants relied on
the integer ordering of type encodings. For example:

```rust
TypeGroup::Pointer => self.inv.entail(&geq(t_expr, (T_CTX as i64).into()), registry),
TypeGroup::SingletonPtr => geq(T_CTX) && leq(T_STACK),
```

This only works because `T_CTX = -5`, `T_PACKET = -4`, `T_STACK = -3` are
contiguous in the encoding. Groups like `MemOrNum` used a combination of
`geq(T_NUM)` and `neq(T_CTX)` — correct only because the encoding happens to place
`T_NUM` at -1 and `T_CTX` at -5.

The DSU-based domain uses `TypeSet::is_subset_of(group.to_typeset())` which is
encoding-independent and correct for any assignment of integer values to types.

### 3. Implicit Stack Type Number Suppression (Undocumented Convention)

The zone domain's `to_set()` method (line 934 of `zone_domain.rs`) explicitly
skips stack cell type variables that have singleton type `number`:

```rust
if registry.is_in_stack(var) && lb_t == TypeEncoding::TNum {
    // Skip: stack variables with type=number are implicit
    continue;
}
```

This convention was not documented anywhere. The new `TypeDomain::to_set()` needed
the same filter to match test expectations. Without it, every numeric stack store
would produce a spurious `s[offset...end].type=number` in the invariant output.

## Design Decisions

### Singleton-Aware Join

The standard DSU join (intersection of equivalence relations) loses precision when
two variables happen to have the same singleton type in both branches but aren't
explicitly unified. For example:

- Branch A: `r1={number}, r2={number}` (separate DSU classes)
- Branch B: `r1={ctx}, r2={ctx}` (separate DSU classes)
- Naive join: `r1 in {number, ctx}, r2 in {number, ctx}` (no equality)
- Correct join: `r1 = r2 in {number, ctx}`

The fix: during join key computation, variables with the same singleton TypeSet in
an operand use a canonical key (the TypeEncoding value) instead of their DSU
representative. This makes the join detect implicit equalities, matching the
precision of the zone domain's difference constraints.

**Soundness argument**: If two variables both have TypeSet `{T}` for a single type T,
they must hold the same type T in ALL represented states, so they ARE semantically
equal. Unifying them in the join preserves only facts that hold in both operands.
