//! Constant aware degree metadata for the fixed AIR, without expression graphs.
//! This diagnostic does not test witness satisfaction or admit a proof class.
use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
};
use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_baby_bear::BabyBear as F;
use p3_field::{Algebra, PrimeCharacteristicRing};

const ASSERTIONS: usize = 80_000;
const CHARGES: usize = 20_000_000;
const DEGREE: usize = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Error {
    Shape = 1,
    Allocation,
    Charges,
    Degree,
    Overflow,
    Owner,
    Assertions,
    Control,
}

struct Budget {
    charges: AtomicUsize,
    cause: AtomicU8,
    limit: usize,
    max_degree: usize,
}
impl Budget {
    fn new(limit: usize, max_degree: usize) -> Self {
        Self {
            charges: AtomicUsize::new(0),
            cause: AtomicU8::new(0),
            limit,
            max_degree,
        }
    }
    fn fail(&self, cause: Error) {
        let _ = self
            .cause
            .compare_exchange(0, cause as u8, Ordering::Relaxed, Ordering::Relaxed);
    }
    fn error(&self) -> Option<Error> {
        match self.cause.load(Ordering::Relaxed) {
            0 => None,
            1 => Some(Error::Shape),
            2 => Some(Error::Allocation),
            3 => Some(Error::Charges),
            4 => Some(Error::Degree),
            5 => Some(Error::Overflow),
            6 => Some(Error::Owner),
            7 => Some(Error::Assertions),
            _ => Some(Error::Control),
        }
    }
    fn charge(&self, count: usize) {
        if self.error().is_some() {
            return;
        }
        let result = self
            .charges
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(count).filter(|new| *new <= self.limit)
            });
        if result.is_err() {
            self.fail(Error::Charges);
        }
    }
}

/// An unknown public variable has degree zero and is not a known literal.
#[derive(Clone, Copy, Debug)]
struct Expr<'a> {
    owner: Option<&'a Budget>,
    constant: Option<F>,
    degree: usize,
    pending: usize,
    fault: Option<Error>,
}
impl<'a> Expr<'a> {
    const fn literal(value: F) -> Self {
        Self {
            owner: None,
            constant: Some(value),
            degree: 0,
            pending: 0,
            fault: None,
        }
    }
    fn unknown(owner: &'a Budget, degree: usize) -> Self {
        Self {
            owner: Some(owner),
            constant: None,
            degree,
            pending: 0,
            fault: None,
        }
    }
    fn attach(mut self, owner: &'a Budget) -> Self {
        if let Some(previous) = self.owner {
            if !core::ptr::eq(previous, owner) {
                previous.fail(Error::Owner);
                owner.fail(Error::Owner);
            }
        } else {
            self.owner = Some(owner);
            owner.charge(self.pending);
            self.pending = 0;
        }
        if let Some(cause) = self.fault {
            owner.fail(cause);
        }
        if self.degree > owner.max_degree {
            owner.fail(Error::Degree);
        }
        self
    }
    fn combined(self, other: Self, op: u8) -> Self {
        let owner = self.owner.or(other.owner);
        let (left, right) = match owner {
            Some(budget) => (self.attach(budget), other.attach(budget)),
            None => (self, other),
        };
        let work = left
            .pending
            .checked_add(right.pending)
            .and_then(|n| n.checked_add(1));
        let mut out = Self {
            owner,
            constant: None,
            degree: 0,
            pending: 0,
            fault: left.fault.or(right.fault),
        };
        if let Some(budget) = owner {
            budget.charge(1);
        } else if let Some(work) = work {
            out.pending = work;
        } else {
            out.fault = out.fault.or(Some(Error::Overflow));
        }
        out.constant = match (left.constant, right.constant) {
            (Some(x), Some(y)) => Some(match op {
                0 => x + y,
                1 => x - y,
                _ => x * y,
            }),
            _ if op == 2 && (left.constant == Some(F::ZERO) || right.constant == Some(F::ZERO)) => {
                Some(F::ZERO)
            }
            _ => None,
        };
        out.degree = if out.constant.is_some() {
            0
        } else if op != 2 {
            left.degree.max(right.degree)
        } else {
            match left.degree.checked_add(right.degree) {
                Some(degree) => degree,
                None => {
                    out.fault = out.fault.or(Some(Error::Overflow));
                    0
                }
            }
        };
        if let Some(budget) = owner {
            out = out.attach(budget);
        }
        out
    }
}
impl core::fmt::Debug for Budget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Budget").finish_non_exhaustive()
    }
}
impl Default for Expr<'_> {
    fn default() -> Self {
        Self::ZERO
    }
}
impl From<F> for Expr<'_> {
    fn from(value: F) -> Self {
        Self::literal(value)
    }
}
impl PrimeCharacteristicRing for Expr<'_> {
    type PrimeSubfield = F;
    const ZERO: Self = Self::literal(F::ZERO);
    const ONE: Self = Self::literal(F::ONE);
    const TWO: Self = Self::literal(F::TWO);
    const NEG_ONE: Self = Self::literal(F::NEG_ONE);
    fn from_prime_subfield(value: F) -> Self {
        Self::literal(value)
    }
}
impl Algebra<F> for Expr<'_> {}
macro_rules! binary {
    ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $op:expr) => {
        impl<'a> $trait for Expr<'a> {
            type Output = Self;
            fn $method(self, rhs: Self) -> Self {
                self.combined(rhs, $op)
            }
        }
        impl $trait<F> for Expr<'_> {
            type Output = Self;
            fn $method(self, rhs: F) -> Self {
                self.combined(rhs.into(), $op)
            }
        }
        impl<'a> $trait<Expr<'a>> for F {
            type Output = Expr<'a>;
            fn $method(self, rhs: Expr<'a>) -> Expr<'a> {
                Expr::from(self).combined(rhs, $op)
            }
        }
        impl $assign for Expr<'_> {
            fn $assign_method(&mut self, rhs: Self) {
                *self = self.$method(rhs);
            }
        }
        impl $assign<F> for Expr<'_> {
            fn $assign_method(&mut self, rhs: F) {
                *self = self.$method(rhs);
            }
        }
    };
}
binary!(Add, add, AddAssign, add_assign, 0);
binary!(Sub, sub, SubAssign, sub_assign, 1);
binary!(Mul, mul, MulAssign, mul_assign, 2);
impl Neg for Expr<'_> {
    type Output = Self;
    fn neg(mut self) -> Self {
        if let Some(owner) = self.owner {
            owner.charge(1);
        } else {
            match self.pending.checked_add(1) {
                Some(n) => self.pending = n,
                None => self.fault = self.fault.or(Some(Error::Overflow)),
            }
        }
        self.constant = self.constant.map(|value| -value);
        self
    }
}
impl Sum for Expr<'_> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}
impl Product for Expr<'_> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |a, b| a * b)
    }
}

struct Builder<'a> {
    owner: &'a Budget,
    main: RowWindow<'a, Expr<'a>>,
    empty: RowWindow<'a, Expr<'a>>,
    public: &'a [Expr<'a>],
    degrees: Vec<usize>,
    limit: usize,
}
impl<'a> AirBuilder for Builder<'a> {
    type F = F;
    type Expr = Expr<'a>;
    type Var = Expr<'a>;
    type PreprocessedWindow = RowWindow<'a, Expr<'a>>;
    type MainWindow = RowWindow<'a, Expr<'a>>;
    type PublicVar = Expr<'a>;
    type PeriodicVar = Expr<'a>;
    fn main(&self) -> Self::MainWindow {
        self.main
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.empty
    }
    fn is_first_row(&self) -> Self::Expr {
        Expr::unknown(self.owner, 1)
    }
    fn is_last_row(&self) -> Self::Expr {
        Expr::unknown(self.owner, 1)
    }
    fn is_transition(&self) -> Self::Expr {
        Expr::unknown(self.owner, 0)
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.public
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        let value = value.into().attach(self.owner);
        if self.owner.error().is_some() {
            return;
        }
        if self.degrees.len() >= self.limit {
            self.owner.fail(Error::Assertions);
            return;
        }
        self.degrees.push(value.degree);
    }
}

#[derive(Debug)]
pub struct Observation {
    pub assertions: usize,
    pub degree_histogram: [usize; 8],
    pub attached_metadata_charges: usize,
    pub requested_variable_bytes: usize,
    pub variable_capacity: usize,
    pub assertion_capacity: usize,
    pub expression_bytes: usize,
    pub independent_controls: usize,
}

fn check_shape(width: usize, public: usize, prep: usize, periodic: usize) -> Result<(), Error> {
    if width != crate::layout::WIDTH
        || public != crate::layout::PUBLIC_VALUES
        || prep != 0
        || periodic != 0
    {
        return Err(Error::Shape);
    }
    Ok(())
}

/// One actual fixed AIR metadata evaluation. No public shape or witness override.
pub fn inspect_overlay() -> Result<Observation, Error> {
    const { assert!(crate::layout::HEIGHT == 8192) };
    let controls = controls()?;
    let air = crate::PackedSignatureOwnerAir;
    let width = <crate::PackedSignatureOwnerAir as BaseAir<F>>::width(&air);
    let public = <crate::PackedSignatureOwnerAir as BaseAir<F>>::num_public_values(&air);
    check_shape(
        width,
        public,
        <crate::PackedSignatureOwnerAir as BaseAir<F>>::preprocessed_width(&air),
        <crate::PackedSignatureOwnerAir as BaseAir<F>>::num_periodic_columns(&air),
    )?;
    let owner = Budget::new(CHARGES, DEGREE);
    let count = width
        .checked_mul(2)
        .and_then(|n| n.checked_add(public))
        .ok_or(Error::Overflow)?;
    let mut variables = Vec::new();
    variables
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    variables.extend((0..2 * width).map(|_| Expr::unknown(&owner, 1)));
    variables.extend((0..public).map(|_| Expr::unknown(&owner, 0)));
    let variable_capacity = variables.capacity();
    let mut degrees = Vec::new();
    degrees
        .try_reserve_exact(ASSERTIONS)
        .map_err(|_| Error::Allocation)?;
    let mut builder = Builder {
        owner: &owner,
        main: RowWindow::from_two_rows(&variables[..width], &variables[width..2 * width]),
        empty: RowWindow::from_two_rows(&[], &[]),
        public: &variables[2 * width..],
        degrees,
        limit: ASSERTIONS,
    };
    air.eval(&mut builder);
    if let Some(cause) = owner.error() {
        return Err(cause);
    }
    let mut histogram = [0usize; 8];
    for &degree in &builder.degrees {
        let slot = histogram.get_mut(degree).ok_or(Error::Degree)?;
        *slot = slot.checked_add(1).ok_or(Error::Overflow)?;
    }
    Ok(Observation {
        assertions: builder.degrees.len(),
        degree_histogram: histogram,
        attached_metadata_charges: owner.charges.load(Ordering::Relaxed),
        requested_variable_bytes: count
            .checked_mul(core::mem::size_of::<Expr<'_>>())
            .ok_or(Error::Overflow)?,
        variable_capacity,
        assertion_capacity: builder.degrees.capacity(),
        expression_bytes: core::mem::size_of::<Expr<'_>>(),
        independent_controls: controls,
    })
}

#[allow(
    clippy::eq_op,
    reason = "Unknown x-x must retain its original symbolic degree"
)]
fn controls() -> Result<usize, Error> {
    let owner = Budget::new(1000, 8);
    let x = Expr::unknown(&owner, 1);
    let public = Expr::unknown(&owner, 0);
    let cases = [
        (x * F::ZERO, 0, Some(F::ZERO)),
        (x * F::ONE, 1, None),
        (x - x, 1, None),
        ((Expr::from(F::ONE) - F::ONE) * x, 0, Some(F::ZERO)),
        (public * x, 1, None),
        (x * x, 2, None),
        ((x * x) * x, 3, None),
        (-x, 1, None),
        (public - public, 0, None),
        (Expr::unknown(&owner, 1) * x, 2, None),
        (Expr::unknown(&owner, 0) * x, 1, None),
    ];
    for (value, degree, constant) in cases {
        if value.degree != degree || value.constant != constant {
            return Err(Error::Control);
        }
    }
    if owner.error().is_some() {
        return Err(Error::Control);
    }
    let pending = Expr::from(F::TWO) + F::ONE;
    if pending.pending != 1 || pending.owner.is_some() {
        return Err(Error::Control);
    }
    let a = Budget::new(1, 8);
    let _ = pending.attach(&a);
    if a.charges.load(Ordering::Relaxed) != 1 || a.error().is_some() {
        return Err(Error::Control);
    }
    let _ = Expr::unknown(&a, 1) + F::ONE;
    a.fail(Error::Owner);
    if a.error() != Some(Error::Charges) {
        return Err(Error::Control);
    }
    let b = Budget::new(1000, 8);
    let c = Budget::new(1000, 8);
    let _ = Expr::unknown(&b, 1) + Expr::unknown(&c, 1);
    if b.error() != Some(Error::Owner) || c.error() != Some(Error::Owner) {
        return Err(Error::Control);
    }
    let d = Budget::new(1000, usize::MAX);
    let _ = Expr::unknown(&d, usize::MAX) * Expr::unknown(&d, 1);
    if d.error() != Some(Error::Overflow) {
        return Err(Error::Control);
    }
    let e = Budget::new(1000, 2);
    let _ = Expr::unknown(&e, 2) * Expr::unknown(&e, 1);
    if e.error() != Some(Error::Degree) {
        return Err(Error::Control);
    }
    let f = Budget::new(1000, 8);
    let mut builder = Builder {
        owner: &f,
        main: RowWindow::from_two_rows(&[], &[]),
        empty: RowWindow::from_two_rows(&[], &[]),
        public: &[],
        degrees: Vec::with_capacity(1),
        limit: 1,
    };
    builder.assert_zero(F::ZERO);
    builder.assert_zero(F::ZERO);
    builder.assert_zero(F::ZERO);
    if builder.degrees != [0] || f.error() != Some(Error::Assertions) {
        return Err(Error::Control);
    }
    for shape in [
        (0, 196, 0, 0),
        (42178, 0, 0, 0),
        (42178, 196, 1, 0),
        (42178, 196, 0, 1),
    ] {
        if check_shape(shape.0, shape.1, shape.2, shape.3) != Err(Error::Shape) {
            return Err(Error::Control);
        }
    }
    let g = Budget::new(usize::MAX, 8);
    g.charge(usize::MAX);
    g.charge(1);
    if g.error() != Some(Error::Charges) || g.charges.load(Ordering::Relaxed) != usize::MAX {
        return Err(Error::Control);
    }
    let h = Budget::new(1000, 8);
    let detached = Expr {
        pending: usize::MAX,
        ..Expr::from(F::ONE)
    } + F::ONE;
    if detached.fault != Some(Error::Overflow) || detached.owner.is_some() {
        return Err(Error::Control);
    }
    let _ = detached.attach(&h);
    if h.error() != Some(Error::Overflow) {
        return Err(Error::Control);
    }
    let j = Budget::new(1000, 8);
    let x = Expr::unknown(&j, 1);
    let mut order = Builder {
        owner: &j,
        main: RowWindow::from_two_rows(&[], &[]),
        empty: RowWindow::from_two_rows(&[], &[]),
        public: &[],
        degrees: Vec::with_capacity(4),
        limit: 4,
    };
    for value in [Expr::ZERO, x * x, x, x.square().square()] {
        order.assert_zero(value);
    }
    if order.degrees != [0, 2, 1, 4]
        || [
            order.is_first_row().degree,
            order.is_last_row().degree,
            order.is_transition().degree,
        ] != [1, 1, 0]
        || j.error().is_some()
    {
        return Err(Error::Control);
    }
    Ok(cases.len() + 1 + 1 + 1 + 1 + 1 + 1 + 4 + 1 + 1 + 1)
}
