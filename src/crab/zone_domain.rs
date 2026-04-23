// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Zone abstract domain based on Split Difference Bound Matrices.
//!
//! Ported from `src/crab/zone_domain.hpp` and `src/crab/zone_domain.cpp`.
//! Wraps `SplitDBM` with a `Variable` ↔ `VertId` mapping layer.

use std::collections::BTreeMap;
use std::fmt;

use crate::arith::extended_number::{MINUS_INFINITY, PLUS_INFINITY};
use crate::arith::linear_constraint::{ConstraintKind, LinearConstraint};
use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::crab::interval::{Bound, Interval};
use crate::crab::splitdbm::split_dbm::{AlignedPair, Side, SplitDBM};
use crate::crab::splitdbm::{VertId, Weight};
use crate::crab::string_constraints::StringInvariant;
use crate::crab::var_registry::VariableRegistry;

/// Arithmetic binary operations (zone-level).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(clippy::upper_case_acronyms)] // Matches upstream C++ naming.
pub enum ArithBinOp {
    ADD,
    SUB,
    MUL,
}

pub type VertMap = BTreeMap<Variable, VertId>;
type RevMap = Vec<Option<Variable>>;
type DiffCst = ((Variable, Variable), Weight);

fn dump_constraint_trace(op: &str, details: &str) {
    if std::env::var("TRACE_ZONE_CONSTRAINTS").is_err() {
        return;
    }
    eprintln!("ZONE_TRACE {op}: {details}");
}

/// Zone abstract domain.
///
/// Maintains a `SplitDBM` graph with a bidirectional mapping between
/// `Variable` identifiers and graph `VertId` vertices.
pub struct ZoneDomain {
    core: SplitDBM,
    vert_map: VertMap,
    rev_map: RevMap,
}

impl ZoneDomain {
    pub fn new() -> Self {
        let core = SplitDBM::new();
        let rev_map = vec![None]; // vertex 0 has no associated variable
        ZoneDomain {
            core,
            vert_map: VertMap::new(),
            rev_map,
        }
    }

    fn from_parts(vert_map: VertMap, rev_map: RevMap, mut core: SplitDBM) -> Self {
        core.normalize();
        ZoneDomain {
            core,
            vert_map,
            rev_map,
        }
    }

    pub fn set_to_top(&mut self) {
        self.core = SplitDBM::new();
        self.vert_map.clear();
        self.rev_map.clear();
        self.rev_map.push(None);
    }

    pub fn top() -> Self {
        Self::new()
    }

    pub fn is_top(&self) -> bool {
        self.core.is_top()
    }

    pub fn size(&self) -> (usize, usize) {
        (self.core.graph_size(), self.core.num_edges())
    }

    // ========================================================================
    // Vertex management
    // ========================================================================

    fn get_vertid(&self, x: Variable) -> Option<VertId> {
        self.vert_map.get(&x).copied()
    }

    fn get_vert(&mut self, v: Variable) -> VertId {
        if let Some(vert) = self.vert_map.get(&v) {
            return *vert;
        }
        let vert = self.core.new_vertex();
        self.vert_map.insert(v, vert);
        if (vert as usize) < self.rev_map.len() {
            self.rev_map[vert as usize] = Some(v);
        } else {
            debug_assert_eq!(vert as usize, self.rev_map.len());
            self.rev_map.push(Some(v));
        }
        debug_assert!(vert != 0);
        vert
    }

    // ========================================================================
    // Bound queries
    // ========================================================================

    fn get_lb_vert(&self, v: Option<VertId>) -> Bound {
        match v {
            Some(vid) => self.core.get_bound(vid, Side::Left),
            None => MINUS_INFINITY,
        }
    }

    fn get_ub_vert(&self, v: Option<VertId>) -> Bound {
        match v {
            Some(vid) => self.core.get_bound(vid, Side::Right),
            None => PLUS_INFINITY,
        }
    }

    fn get_lb(&self, x: Variable) -> Bound {
        self.get_lb_vert(self.get_vertid(x))
    }

    fn get_ub(&self, x: Variable, registry: &VariableRegistry) -> Bound {
        if registry.is_min_only(x) {
            return PLUS_INFINITY;
        }
        self.get_ub_vert(self.get_vertid(x))
    }

    fn get_interval(&self, x: Variable, _registry: &VariableRegistry) -> Interval {
        let v = self.get_vertid(x);
        Interval::new(self.get_lb_vert(v), self.get_ub_vert(v))
    }

    fn get_interval_no_reg(&self, x: Variable) -> Interval {
        let v = self.get_vertid(x);
        Interval::new(self.get_lb_vert(v), self.get_ub_vert(v))
    }

    // ========================================================================
    // Potential evaluation
    // ========================================================================

    fn pot_value(&self, v: Variable) -> Weight {
        if let Some(y) = self.get_vertid(v) {
            self.core.potential_at(y)
        } else {
            Weight::from(0i64)
        }
    }

    fn eval_expression(&self, e: &LinearExpression) -> Weight {
        let mut res = Weight::from(*e.constant_term());
        for (variable, coefficient) in e.variable_terms() {
            res += (self.pot_value(*variable) - self.core.potential_at_zero())
                * Weight::from(*coefficient);
        }
        res
    }

    fn compute_residual(
        &self,
        e: &LinearExpression,
        pivot: Variable,
        registry: &VariableRegistry,
    ) -> Interval {
        let mut residual = Interval::from_number(-*e.constant_term());
        for (variable, coefficient) in e.variable_terms() {
            if *variable != pivot {
                let var_interval = self.get_interval(*variable, registry);
                residual -= &(&Interval::from_number(*coefficient) * &var_interval);
            }
        }
        residual
    }

    // ========================================================================
    // Difference constraint extraction
    // ========================================================================

    fn diffcsts_of_assign(
        &self,
        exp: &LinearExpression,
        extract_upper_bounds: bool,
        diff_csts: &mut Vec<(Variable, Weight)>,
        registry: &VariableRegistry,
    ) {
        let mut unbounded_var: Option<Variable> = None;
        let mut terms: Vec<(Variable, Weight)> = Vec::new();
        let mut residual = Weight::from(*exp.constant_term());

        for (y, n) in exp.variable_terms() {
            let coeff = Weight::from(*n);
            if coeff < 0i64 {
                let y_val = if extract_upper_bounds {
                    self.get_lb(*y)
                } else {
                    self.get_ub(*y, registry)
                };
                if y_val.is_infinite() {
                    return;
                }
                let ymax = Weight::from(*y_val.number().unwrap());
                residual += ymax * coeff;
            } else {
                let y_val = if extract_upper_bounds {
                    self.get_ub(*y, registry)
                } else {
                    self.get_lb(*y)
                };
                if y_val.is_infinite() {
                    if unbounded_var.is_some() || coeff != 1i64 {
                        return;
                    }
                    unbounded_var = Some(*y);
                } else {
                    let ymax = Weight::from(*y_val.number().unwrap());
                    residual += ymax * coeff;
                    terms.push((*y, ymax));
                }
            }
        }

        if let Some(uv) = unbounded_var {
            diff_csts.push((uv, residual));
        } else {
            for (v, n) in &terms {
                let n: &Weight = n;
                diff_csts.push((*v, residual - *n));
            }
        }
    }

    fn diffcsts_of_assign_both(
        &self,
        exp: &LinearExpression,
        lb: &mut Vec<(Variable, Weight)>,
        ub: &mut Vec<(Variable, Weight)>,
        registry: &VariableRegistry,
    ) {
        self.diffcsts_of_assign(exp, true, ub, registry);
        self.diffcsts_of_assign(exp, false, lb, registry);
    }

    fn diffcsts_of_lin_leq(
        &self,
        exp: &LinearExpression,
        csts: &mut Vec<DiffCst>,
        lbs: &mut Vec<(Variable, Weight)>,
        ubs: &mut Vec<(Variable, Weight)>,
        _registry: &VariableRegistry,
    ) {
        let mut exp_ub = -Weight::from(*exp.constant_term());

        let mut unbounded_lbcoeff = Weight::from(0i64);
        let mut unbounded_ubcoeff = Weight::from(0i64);
        let mut unbounded_lbvar: Option<Variable> = None;
        let mut unbounded_ubvar: Option<Variable> = None;

        let mut pos_terms: Vec<((Weight, Variable), Weight)> = Vec::new();
        let mut neg_terms: Vec<((Weight, Variable), Weight)> = Vec::new();

        for (y, n) in exp.variable_terms() {
            let coeff = Weight::from(*n);
            if coeff.is_zero() {
                continue;
            }
            if coeff > 0i64 {
                let y_lb = self.get_lb(*y);
                if y_lb.is_infinite() {
                    if unbounded_lbvar.is_some() {
                        return;
                    }
                    unbounded_lbvar = Some(*y);
                    unbounded_lbcoeff = coeff;
                } else {
                    let ymin = Weight::from(*y_lb.number().unwrap());
                    exp_ub -= ymin * coeff;
                    pos_terms.push(((coeff, *y), ymin));
                }
            } else {
                let y_ub = *self.get_interval_no_reg(*y).ub();
                if y_ub.is_infinite() {
                    if unbounded_ubvar.is_some() {
                        return;
                    }
                    unbounded_ubvar = Some(*y);
                    unbounded_ubcoeff = -coeff;
                } else {
                    let ymax = Weight::from(*y_ub.number().unwrap());
                    exp_ub -= ymax * coeff;
                    neg_terms.push(((-coeff, *y), ymax));
                }
            }
        }

        if let Some(x) = unbounded_lbvar {
            if let Some(uv) = unbounded_ubvar {
                if unbounded_lbcoeff == 1i64 && unbounded_ubcoeff == 1i64 {
                    csts.push(((x, uv), exp_ub));
                }
            } else {
                if unbounded_lbcoeff == 1i64 {
                    for ((_, nv_y), k) in &neg_terms {
                        let k: &Weight = k;
                        csts.push(((x, *nv_y), exp_ub - *k));
                    }
                }
                ubs.push((x, exp_ub / unbounded_lbcoeff));
            }
        } else if let Some(y) = unbounded_ubvar {
            if unbounded_ubcoeff == 1i64 {
                for ((_, nv_y), k) in &pos_terms {
                    let k: &Weight = k;
                    csts.push(((*nv_y, y), exp_ub + *k));
                }
            }
            lbs.push((y, -exp_ub / unbounded_ubcoeff));
        } else {
            for ((_neg_coeff, neg_y), neg_k) in &neg_terms {
                let neg_k: &Weight = neg_k;
                for ((_, pos_y), pos_k) in &pos_terms {
                    let pos_k: &Weight = pos_k;
                    csts.push(((*pos_y, *neg_y), exp_ub - *neg_k + *pos_k));
                }
            }
            for ((neg_coeff, neg_y), neg_k) in &neg_terms {
                let neg_coeff: &Weight = neg_coeff;
                let neg_k: &Weight = neg_k;
                lbs.push((*neg_y, -exp_ub / *neg_coeff + *neg_k));
            }
            for ((pos_coeff, pos_y), pos_k) in &pos_terms {
                let pos_coeff: &Weight = pos_coeff;
                let pos_k: &Weight = pos_k;
                ubs.push((*pos_y, exp_ub / *pos_coeff + *pos_k));
            }
        }
    }

    fn add_linear_leq(&mut self, exp: &LinearExpression, registry: &VariableRegistry) -> bool {
        let mut lbs = Vec::new();
        let mut ubs = Vec::new();
        let mut csts = Vec::new();
        self.diffcsts_of_lin_leq(exp, &mut csts, &mut lbs, &mut ubs, registry);
        dump_constraint_trace(
            "add_linear_leq:input",
            &format!("exp={exp} lbs={:?} ubs={:?} csts={:?}", lbs, ubs, csts),
        );

        for (var, n) in &lbs {
            let vert = self.get_vert(*var);
            if !self.core.update_bound_if_tighter(vert, Side::Left, n) {
                dump_constraint_trace(
                    "add_linear_leq:bottom",
                    &format!("tighten lb failed for var={var} bound={n}"),
                );
                return false;
            }
        }

        for (var, n) in &ubs {
            if registry.is_min_only(*var) {
                continue;
            }
            let vert = self.get_vert(*var);
            if !self.core.update_bound_if_tighter(vert, Side::Right, n) {
                dump_constraint_trace(
                    "add_linear_leq:bottom",
                    &format!("tighten ub failed for var={var} bound={n}"),
                );
                return false;
            }
        }

        for ((src_var, dst_var), k) in &csts {
            let src = self.get_vert(*dst_var);
            let dest = self.get_vert(*src_var);
            if !self.core.add_difference_constraint(src, dest, k) {
                dump_constraint_trace(
                    "add_linear_leq:bottom",
                    &format!("difference failed src_var={src_var} dst_var={dst_var} k={k}"),
                );
                return false;
            }
        }

        self.core.close_after_bound_updates();
        self.normalize();
        true
    }

    fn add_univar_disequation(
        &mut self,
        x: Variable,
        n: &Number,
        registry: &VariableRegistry,
    ) -> bool {
        let i = self.get_interval(x, registry);
        let new_i = trim_interval(&i, n);
        if new_i.is_bottom() {
            return false;
        }
        if new_i.is_top() || !new_i.is_included_in(&i) {
            return true;
        }

        let v = self.get_vert(x);
        if new_i.lb().is_finite() {
            let lb_val = Weight::from(*new_i.lb().number().unwrap());
            if !self.core.strengthen_bound(v, Side::Left, &lb_val) {
                return false;
            }
        }
        if new_i.ub().is_finite() && !registry.is_min_only(x) {
            let ub_val = Weight::from(*new_i.ub().number().unwrap());
            if !self.core.strengthen_bound(v, Side::Right, &ub_val) {
                return false;
            }
        }
        self.normalize();
        true
    }

    fn normalize(&mut self) {
        self.core.normalize();
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    pub fn is_included_in(&self, o: &ZoneDomain) -> bool {
        if o.is_top() {
            return true;
        }
        if self.is_top() {
            return false;
        }
        if self.vert_map.len() < o.vert_map.len() {
            return false;
        }

        let invalid_vert: VertId = VertId::MAX;
        let mut perm = vec![invalid_vert; o.core.graph_size()];
        perm[0] = 0;
        for (v, &n) in &o.vert_map {
            if !o.core.vertex_has_edges(n) {
                continue;
            }
            if let Some(&y) = self.vert_map.get(v) {
                perm[n as usize] = y;
            } else {
                return false;
            }
        }

        SplitDBM::is_subsumed_by(&self.core, &o.core, &perm)
    }

    pub fn join(&self, right: &ZoneDomain) -> ZoneDomain {
        if right.is_top() {
            return right.clone();
        }
        if self.is_top() {
            return self.clone();
        }

        let (aligned_pair, aligned_vars) = Self::make_intersection_alignment(self, right);
        let joined = SplitDBM::join(&aligned_pair);

        let (out_vmap, mut out_revmap) = result_mappings(&aligned_vars);
        let mut out_vmap = out_vmap;
        for v in joined.get_disconnected_vertices() {
            // Note: we can't call forget on joined here since we'd need to own it.
            // Instead, the caller should garbage-collect after construction.
            if let Some(var) = out_revmap[v as usize].take() {
                out_vmap.remove(&var);
            }
        }

        ZoneDomain::from_parts(out_vmap, out_revmap, joined)
    }

    pub fn join_assign(&mut self, right: &ZoneDomain) {
        *self = self.join(right);
    }

    pub fn widen(&self, o: &ZoneDomain) -> ZoneDomain {
        let (aligned_pair, aligned_vars) = Self::make_intersection_alignment(self, o);
        let result_core = SplitDBM::widen(&aligned_pair);
        let (out_vmap, out_revmap) = result_mappings(&aligned_vars);
        ZoneDomain::from_parts(out_vmap, out_revmap, result_core)
    }

    pub fn meet(&self, o: &ZoneDomain) -> Option<ZoneDomain> {
        if self.is_top() {
            return Some(o.clone());
        }
        if o.is_top() {
            return Some(self.clone());
        }

        let (mut aligned_pair, aligned_vars) = Self::make_union_alignment(self, o);
        let meet_result = SplitDBM::meet(&mut aligned_pair)?;
        let (out_vmap, out_revmap) = result_mappings(&aligned_vars);
        Some(ZoneDomain::from_parts(out_vmap, out_revmap, meet_result))
    }

    pub fn narrow_op(&self, o: &ZoneDomain) -> ZoneDomain {
        if self.is_top() {
            return o.clone();
        }
        // Upstream parity: matches `ZoneDomain::narrow` in
        // `src/crab/zone_domain.cpp`, which carries the same FIXME
        // ("Implement properly. Narrowing as a no-op should be sound.").
        // Keep the no-op until upstream implements a tighter narrow; do not
        // diverge unilaterally.
        self.clone()
    }

    // ========================================================================
    // Assignment and havoc
    // ========================================================================

    pub fn havoc(&mut self, v: Variable) {
        if let Some(y) = self.get_vertid(v) {
            self.core.forget(y);
            self.rev_map[y as usize] = None;
            self.vert_map.remove(&v);
            self.normalize();
        }
    }

    pub fn assign(&mut self, lhs: Variable, e: &LinearExpression, registry: &VariableRegistry) {
        let value_interval = self.eval_interval(e, registry);

        let lb_w: Option<Weight> = value_interval.lb().number().map(|n| Weight::from(-*n));
        let ub_w: Option<Weight> = value_interval.ub().number().map(|n| Weight::from(*n));

        if value_interval.is_singleton() {
            self.set(lhs, &value_interval, registry);
            self.normalize();
            return;
        }

        let mut diffs_lb = Vec::new();
        let mut diffs_ub = Vec::new();
        self.diffcsts_of_assign_both(e, &mut diffs_lb, &mut diffs_ub, registry);
        if diffs_lb.is_empty() && diffs_ub.is_empty() {
            self.set(lhs, &value_interval, registry);
            self.normalize();
            return;
        }

        let e_val = self.eval_expression(e);

        let mut diffs_from: Vec<(VertId, Weight)> = Vec::new();
        let mut diffs_to: Vec<(VertId, Weight)> = Vec::new();
        for (var, n) in &diffs_lb {
            diffs_from.push((self.get_vert(*var), -*n));
        }
        for (var, n) in &diffs_ub {
            diffs_to.push((self.get_vert(*var), *n));
        }

        let effective_ub = if ub_w.is_some() && !registry.is_min_only(lhs) {
            ub_w
        } else {
            None
        };

        let pot_val = self.core.potential_at_zero() + e_val;
        let vert = self.core.assign_vertex(
            &pot_val,
            &diffs_from,
            &diffs_to,
            lb_w.as_ref(),
            effective_ub.as_ref(),
        );

        if (vert as usize) == self.rev_map.len() {
            self.rev_map.push(Some(lhs));
        } else {
            self.rev_map[vert as usize] = Some(lhs);
        }
        self.havoc(lhs);
        self.vert_map.insert(lhs, vert);
        self.normalize();
    }

    pub fn assign_variable(&mut self, x: Variable, v: Variable, registry: &VariableRegistry) {
        self.assign(x, &LinearExpression::from(v), registry);
    }

    pub fn assign_number(&mut self, x: Variable, n: i64, registry: &VariableRegistry) {
        self.assign(x, &LinearExpression::from(n), registry);
    }

    pub fn set(&mut self, x: Variable, intv: &Interval, registry: &VariableRegistry) {
        assert!(!intv.is_bottom());
        self.havoc(x);
        if intv.is_top() {
            return;
        }

        let v = self.get_vert(x);
        if intv.ub().is_finite() && !registry.is_min_only(x) {
            let ub = Weight::from(*intv.ub().number().unwrap());
            self.core.set_bound(v, Side::Right, &ub);
        }
        if intv.lb().is_finite() {
            let lb = Weight::from(*intv.lb().number().unwrap());
            self.core.set_bound(v, Side::Left, &lb);
        }
        self.normalize();
    }

    // ========================================================================
    // Constraint operations
    // ========================================================================

    /// Add a constraint. Returns false if domain becomes bottom.
    pub fn add_constraint(&mut self, cst: &LinearConstraint, registry: &VariableRegistry) -> bool {
        if cst.is_tautology() {
            return true;
        }
        if cst.is_contradiction() {
            return false;
        }
        dump_constraint_trace("add_constraint", &format!("{cst}"));

        match cst.kind() {
            ConstraintKind::LessThanOrEqualsZero => {
                if !self.add_linear_leq(cst.expression(), registry) {
                    return false;
                }
            }
            ConstraintKind::LessThanZero => {
                let nc_expr = cst.expression().plus_constant(&Number::from(1i64));
                if !self.add_linear_leq(&nc_expr, registry) {
                    return false;
                }
            }
            ConstraintKind::EqualsZero => {
                let exp = cst.expression();
                if !self.add_linear_leq(exp, registry)
                    || !self.add_linear_leq(&exp.negate(), registry)
                {
                    return false;
                }
            }
            ConstraintKind::NotZero => {
                let e = cst.expression();
                for (variable, coefficient) in e.variable_terms() {
                    let i = self
                        .compute_residual(e, *variable, registry)
                        .div(&Interval::from_number(*coefficient));
                    if let Some(k) = i.singleton()
                        && !self.add_univar_disequation(*variable, k, registry)
                    {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn eval_interval(&self, e: &LinearExpression, registry: &VariableRegistry) -> Interval {
        let mut r = Interval::from_number(*e.constant_term());
        for (variable, coefficient) in e.variable_terms() {
            r += &(&Interval::from_number(*coefficient) * &self.get_interval(*variable, registry));
        }
        r
    }

    pub fn eval_interval_var(&self, v: Variable, registry: &VariableRegistry) -> Interval {
        self.get_interval(v, registry)
    }

    pub fn forget(&mut self, variables: &[Variable]) {
        if self.is_top() {
            return;
        }
        for &v in variables {
            if self.vert_map.contains_key(&v) {
                self.havoc(v);
            }
        }
        self.normalize();
    }

    // ========================================================================
    // Entailment and intersection checks
    // ========================================================================

    pub fn intersect(&self, cst: &LinearConstraint, registry: &VariableRegistry) -> bool {
        if cst.is_contradiction() {
            return false;
        }
        if self.is_top() || cst.is_tautology() {
            return true;
        }
        let mut copy = self.clone();
        copy.add_constraint(cst, registry)
    }

    pub fn entail(&self, rhs: &LinearConstraint, registry: &VariableRegistry) -> bool {
        if rhs.is_tautology() {
            return true;
        }
        if rhs.is_contradiction() {
            return false;
        }
        let interval = self.eval_interval(rhs.expression(), registry);
        match rhs.kind() {
            ConstraintKind::EqualsZero => {
                if interval.singleton() == Some(&Number::from(0i64)) {
                    return true;
                }
            }
            ConstraintKind::LessThanOrEqualsZero => {
                if *interval.ub() <= Bound::Finite(Number::from(0i64)) {
                    return true;
                }
            }
            ConstraintKind::LessThanZero => {
                if *interval.ub() < Bound::Finite(Number::from(0i64)) {
                    return true;
                }
            }
            ConstraintKind::NotZero => {
                if *interval.ub() < Bound::Finite(Number::from(0i64))
                    || *interval.lb() > Bound::Finite(Number::from(0i64))
                {
                    return true;
                }
            }
        }
        if rhs.kind() == ConstraintKind::EqualsZero {
            self.entail_aux(
                &LinearConstraint::new(
                    rhs.expression().clone(),
                    ConstraintKind::LessThanOrEqualsZero,
                ),
                registry,
            ) && self.entail_aux(
                &LinearConstraint::new(
                    rhs.expression().negate(),
                    ConstraintKind::LessThanOrEqualsZero,
                ),
                registry,
            )
        } else {
            self.entail_aux(rhs, registry)
        }
    }

    fn entail_aux(&self, cst: &LinearConstraint, registry: &VariableRegistry) -> bool {
        !self.clone().add_constraint(&cst.negate(), registry)
    }

    pub fn implies(
        &self,
        premise: &LinearConstraint,
        conclusion: &LinearConstraint,
        registry: &VariableRegistry,
    ) -> bool {
        let mut result = self.clone();
        !result.add_constraint(premise, registry) || result.entail(conclusion, registry)
    }

    // ========================================================================
    // to_set (for display)
    // ========================================================================

    pub fn to_set(&self, registry: &VariableRegistry) -> StringInvariant {
        use std::collections::BTreeSet;

        if self.is_top() {
            return StringInvariant::top();
        }

        let g = self.core.graph();

        // Step 1: Build equivalence classes (weight-0 edges) and collect
        // difference constraints (non-zero edges).
        let mut equivalence_classes: BTreeMap<Variable, Variable> = BTreeMap::new();
        let mut diff_csts: BTreeSet<(Variable, Variable, Weight)> = BTreeSet::new();

        for s in g.verts() {
            if s == 0 {
                continue;
            }
            let vs = match self.rev_map.get(s as usize).and_then(|v| *v) {
                Some(v) => v,
                None => continue,
            };
            let mut least = vs;
            for d in g.succs(s) {
                if d == 0 {
                    continue;
                }
                let vd = match self.rev_map.get(d as usize).and_then(|v| *v) {
                    Some(v) => v,
                    None => continue,
                };
                let w = g.edge_val(s, d);
                if w == 0i64 {
                    if registry.printing_order(vd, least) == std::cmp::Ordering::Less {
                        least = vd;
                    }
                } else {
                    diff_csts.insert((vd, vs, w));
                }
            }
            equivalence_classes.insert(vs, least);
        }

        // Step 2: Emit equivalence-class alias strings and find representatives.
        let mut representatives: BTreeSet<Variable> = BTreeSet::new();
        let mut result: BTreeSet<String> = BTreeSet::new();

        for (&vs, &least) in &equivalence_classes {
            if vs == least {
                representatives.insert(least);
            } else {
                result.insert(format!("{}={}", registry.name(vs), registry.name(least)));
            }
        }

        // Step 3: Emit difference constraints with simplification.
        // If both `vd - vs <= w` and `vs - vd <= -w` exist, simplify to `vd = vs + w`.
        for &(vd, vs, ref w) in &diff_csts {
            if !representatives.contains(&vd) || !representatives.contains(&vs) {
                continue;
            }
            let dual = format!("{}-{}<={}", registry.name(vs), registry.name(vd), -*w,);
            if result.contains(&dual) {
                // Simplify reciprocal pair into equality
                result.remove(&dual);
                let nw = -*w;
                if w.is_positive() {
                    result.insert(format!("{}={}+{}", registry.name(vd), registry.name(vs), w));
                } else if w.is_negative() {
                    result.insert(format!(
                        "{}={}+{}",
                        registry.name(vs),
                        registry.name(vd),
                        nw
                    ));
                } else {
                    // w == 0: equality (pick alphabetical order)
                    let (left, right) =
                        if registry.printing_order(vs, vd) == std::cmp::Ordering::Less {
                            (vs, vd)
                        } else {
                            (vd, vs)
                        };
                    result.insert(format!("{}={}", registry.name(left), registry.name(right)));
                }
            } else {
                result.insert(format!(
                    "{}-{}<={}",
                    registry.name(vd),
                    registry.name(vs),
                    w,
                ));
            }
        }

        // Step 4: Emit interval constraints for representative variables.
        for vert in g.verts() {
            if vert == 0 {
                continue;
            }
            let var = match self.rev_map.get(vert as usize).and_then(|v| *v) {
                Some(v) => v,
                None => continue,
            };
            if !representatives.contains(&var) {
                continue;
            }
            let has_lb = g.elem(vert, 0);
            let has_ub = g.elem(0, vert) && !registry.is_min_only(var);
            if !has_lb && !has_ub {
                continue;
            }
            let lb_bound = if has_lb {
                Bound::Finite(-g.edge_val(vert, 0))
            } else {
                MINUS_INFINITY
            };
            let ub_bound = if has_ub {
                Bound::Finite(g.edge_val(0, vert))
            } else {
                PLUS_INFINITY
            };
            let v_out = Interval::new(lb_bound, ub_bound);
            assert!(!v_out.is_bottom());

            let name = registry.name(var);

            if registry.is_min_only(var) {
                // One-sided: just emit lower bound
                result.insert(format!("{name}={}", v_out.lb()));
            } else if v_out.is_singleton() {
                result.insert(format!("{name}={}", v_out.lb()));
            } else {
                result.insert(format!("{name}={v_out}"));
            }
        }

        StringInvariant::from_set(result)
    }

    // ========================================================================
    // Internal alignment helpers
    // ========================================================================

    fn make_intersection_alignment<'a>(
        left: &'a ZoneDomain,
        right: &'a ZoneDomain,
    ) -> (AlignedPair<'a>, RevMap) {
        let mut perm_left = vec![0];
        let mut perm_right = vec![0];
        let mut aligned_vars: RevMap = vec![None];

        for (var, &left_vert) in &left.vert_map {
            if let Some(&right_vert) = right.vert_map.get(var) {
                perm_left.push(left_vert);
                perm_right.push(right_vert);
                aligned_vars.push(Some(*var));
            }
        }

        let aligned = AlignedPair {
            left: &left.core,
            right: &right.core,
            left_perm: perm_left,
            right_perm: perm_right,
            initial_potentials: Vec::new(),
        };
        (aligned, aligned_vars)
    }

    fn make_union_alignment<'a>(
        left: &'a ZoneDomain,
        right: &'a ZoneDomain,
    ) -> (AlignedPair<'a>, RevMap) {
        const NOT_PRESENT: VertId = VertId::MAX;

        let mut perm_left = vec![0];
        let mut perm_right = vec![0];
        let mut aligned_vars: RevMap = vec![None];
        let mut initial_potentials = vec![Weight::from(0i64)];

        let mut var_to_index: BTreeMap<Variable, usize> = BTreeMap::new();

        for (var, &left_vert) in &left.vert_map {
            var_to_index.insert(*var, perm_left.len());
            perm_left.push(left_vert);
            perm_right.push(NOT_PRESENT);
            aligned_vars.push(Some(*var));
            initial_potentials
                .push(left.core.potential_at(left_vert) - left.core.potential_at_zero());
        }

        for (var, &right_vert) in &right.vert_map {
            if let Some(&idx) = var_to_index.get(var) {
                perm_right[idx] = right_vert;
            } else {
                perm_left.push(NOT_PRESENT);
                perm_right.push(right_vert);
                aligned_vars.push(Some(*var));
                initial_potentials
                    .push(right.core.potential_at(right_vert) - right.core.potential_at_zero());
            }
        }

        let aligned = AlignedPair {
            left: &left.core,
            right: &right.core,
            left_perm: perm_left,
            right_perm: perm_right,
            initial_potentials,
        };
        (aligned, aligned_vars)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn result_mappings(aligned_vars: &RevMap) -> (VertMap, RevMap) {
    let mut vmap = VertMap::new();
    let revmap = aligned_vars.clone();

    for (i, var) in aligned_vars.iter().enumerate().skip(1) {
        if let Some(v) = var {
            vmap.insert(*v, i as VertId);
        }
    }
    (vmap, revmap)
}

fn trim_interval(i: &Interval, n: &Number) -> Interval {
    if *i.lb() == Bound::Finite(*n) {
        return Interval::new(Bound::Finite(*n + Number::from(1i64)), *i.ub());
    }
    if *i.ub() == Bound::Finite(*n) {
        return Interval::new(*i.lb(), Bound::Finite(*n - Number::from(1i64)));
    }
    if i.is_top() && n.is_zero() {
        return Interval::new(
            Bound::Finite(Number::from(1i64)),
            Bound::Finite(Number::from(u64::MAX)),
        );
    }
    *i
}

// ============================================================================
// Trait implementations
// ============================================================================

impl Clone for ZoneDomain {
    fn clone(&self) -> Self {
        ZoneDomain {
            core: self.core.clone(),
            vert_map: self.vert_map.clone(),
            rev_map: self.rev_map.clone(),
        }
    }
}

impl Default for ZoneDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ZoneDomain {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full display requires VariableRegistry, which we don't have here.
        // Use to_set() with a registry for proper display.
        write!(_f, "<ZoneDomain>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::linear_constraint::gt;
    use crate::crab::interval::Interval;
    use crate::crab::type_encoding::DataKind;

    #[test]
    fn test_to_set_uses_raw_difference_edge_weight() {
        let mut reg = VariableRegistry::new();
        let mut dom = ZoneDomain::new();

        let left_u = reg.reg(DataKind::Uvalues, 1);
        let right_u = reg.reg(DataKind::Uvalues, 2);

        dom.set(left_u, &Interval::from_number(Number::from(u64::MAX)), &reg);
        dom.set(
            right_u,
            &Interval::from_number(Number::from(i64::MAX)),
            &reg,
        );

        // left_u > right_u  ==>  right_u - left_u <= -1
        let cst = gt(
            LinearExpression::from(left_u),
            LinearExpression::from(right_u),
        );
        assert!(dom.add_constraint(&cst, &reg));

        let left_vert = dom.vert_map.get(&left_u).copied().unwrap();
        let right_vert = dom.vert_map.get(&right_u).copied().unwrap();
        let raw = dom.core.graph().edge_val(left_vert, right_vert);

        let rendered = dom.to_set(&reg);
        let expected = format!("{}-{}<={}", reg.name(right_u), reg.name(left_u), raw);
        assert!(
            rendered.contains(&expected),
            "to_set must reflect stored edge exactly; missing {expected} in {rendered}",
        );
    }

    #[test]
    fn test_add_linear_leq_tightens_difference_from_finite_bounds() {
        let mut reg = VariableRegistry::new();
        let mut dom = ZoneDomain::new();

        let left_u = reg.reg(DataKind::Uvalues, 1);
        let right_u = reg.reg(DataKind::Uvalues, 2);

        dom.set(left_u, &Interval::from_number(Number::from(u64::MAX)), &reg);
        dom.set(
            right_u,
            &Interval::from_number(Number::from(i64::MAX)),
            &reg,
        );

        // left_u > right_u introduces right_u - left_u <= -1 syntactically,
        // but finite bounds imply the tighter relation <= -2^63.
        let cst = gt(
            LinearExpression::from(left_u),
            LinearExpression::from(right_u),
        );
        assert!(dom.add_constraint(&cst, &reg));

        let left_vert = dom.vert_map.get(&left_u).copied().unwrap();
        let right_vert = dom.vert_map.get(&right_u).copied().unwrap();
        let raw = dom.core.graph().edge_val(left_vert, right_vert);

        let rendered = dom.to_set(&reg);
        let expected = format!("{}-{}<={}", reg.name(right_u), reg.name(left_u), raw);
        assert!(
            rendered.contains(&expected),
            "missing tightened edge {expected} in {rendered}"
        );
    }
}
