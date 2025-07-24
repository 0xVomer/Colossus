//! Port of <https://docs.rs/amcl_wrapper/latest/amcl_wrapper/univar_poly/struct.UnivarPolynomial.html>
//! We only need to coeffients from roots, much of this code is not used or needed.
//!
#![allow(clippy::vec_init_then_push)] // because macro usage
use super::Scalar;
use bls12_381_plus::ff::Field;
use rand::rngs::ThreadRng;
use rayon::prelude::*;
use std::{
    ops::{Index, IndexMut, Mul},
    slice::Iter,
};

#[derive(Clone, Copy)]
pub enum ValueError {
    UnequalSizeVectors(usize, usize),
    IncorrectSize(usize),
    NonPowerOf2(usize),
    OutOfRange(usize),
}

#[macro_export]
macro_rules! check_vector_size_for_equality {
    ( $a:expr, $b:expr ) => {{
        if $a.len() != $b.len() {
            Err(ValueError::UnequalSizeVectors($a.len(), $b.len()))
        } else {
            Ok(())
        }
    }};
}

/// Univariate polynomial represented with coefficients in a vector. The ith element of the vector is the coefficient of the ith degree term.
#[derive(Clone, Debug, PartialEq)]
pub struct UnivarPolynomial(pub ScalarVector);

impl UnivarPolynomial {
    /// Return a zero polynomial of degree `degree`
    pub fn new(degree: usize) -> Self {
        let coeffs = ScalarVector::new(degree + 1);
        UnivarPolynomial(coeffs)
    }

    /// Return a constant polynomial
    pub fn new_constant(constant: Scalar) -> Self {
        let mut coeffs = ScalarVector::new(1);
        coeffs[0] = constant;
        UnivarPolynomial(coeffs)
    }

    /// Return a randomly chosen polynomial (each coefficient is randomly chosen) of degree `degree`.
    pub fn random(degree: usize) -> Self {
        Self(ScalarVector::random(degree + 1)) // +1 for constant term
    }

    /// Create a polynomial with given roots in `roots`
    /// i.e. (x-roots[0])*(x-roots[1])*(x-roots[2])...(x-roots[last]) given `roots`
    pub fn new_with_roots(roots: &[Scalar]) -> Self {
        // vector of [(x-roots[0]), (x-roots[1]), (x-roots[2]), ...]
        let x_i = roots
            .iter()
            .map(|i| {
                let mut v = ScalarVector::with_capacity(2);
                v.push(-i);
                v.push(Scalar::ONE);
                UnivarPolynomial(v)
            })
            .collect::<Vec<UnivarPolynomial>>();

        // Polynomial (x-roots[0])*(x-roots[1])*(x-roots[2])...(x-roots[last])
        x_i.par_iter()
            .cloned()
            .reduce(|| Self::new_constant(Scalar::ONE), |a, b| UnivarPolynomial::multiply(&a, &b))
    }

    pub fn coefficients(&self) -> &ScalarVector {
        &self.0
    }

    pub fn degree(&self) -> usize {
        // TODO: This makes fetching the coefficient ambiguous as a 0 degree polynomial might
        // have a coefficient for the 0th degree or it might not. Should probably adapt Index and IndexMut trait.
        let l = self.0.len();
        if l == 0 { l } else { l - 1 }
    }

    /// Polynomial is zero if all coefficients are 0
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|coeff| coeff.is_zero().into())
    }

    /// Return product of 2 polynomials. `left` * `right`
    pub fn multiply(left: &Self, right: &Self) -> Self {
        let mut product = Self::new(left.degree() + right.degree());
        for i in 0..=left.degree() {
            for j in 0..=right.degree() {
                product[i + j] += left[i] * right[j];
            }
        }
        product
    }

    pub fn multiply_by_constant(&self, constant: &Scalar) -> UnivarPolynomial {
        let mut new_poly = self.clone();
        for i in 0..=self.degree() {
            new_poly[i] = constant * self[i];
        }
        new_poly
    }
}

impl Index<usize> for UnivarPolynomial {
    type Output = Scalar;

    fn index(&self, idx: usize) -> &Scalar {
        &self.0[idx]
    }
}

impl IndexMut<usize> for UnivarPolynomial {
    fn index_mut(&mut self, idx: usize) -> &mut Scalar {
        &mut self.0[idx]
    }
}

impl Eq for UnivarPolynomial {}

impl<'a> Mul<&'a UnivarPolynomial> for &UnivarPolynomial {
    type Output = UnivarPolynomial;

    fn mul(self, other: &'a UnivarPolynomial) -> UnivarPolynomial {
        UnivarPolynomial::multiply(self, other)
    }
}

#[derive(Clone, Debug)]
pub struct ScalarVector {
    elems: Vec<Scalar>,
}

impl ScalarVector {
    /// Creates a new field element vector with each element being 0
    // FIXME: size should have a type like u64 since usize can be small on older/smaller machines. This code
    // is less likely to be used on older/smaller machines though
    pub fn new(size: usize) -> Self {
        Self {
            elems: (0..size).into_par_iter().map(|_| Scalar::default()).collect(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elems: Vec::<Scalar>::with_capacity(capacity),
        }
    }

    /// Get a vector of random field elements
    pub fn random(size: usize) -> Self {
        (0..size)
            .into_par_iter()
            .map(|_| Scalar::random(ThreadRng::default()))
            .collect::<Vec<Scalar>>()
            .into()
    }

    pub fn as_slice(&self) -> &[Scalar] {
        self.elems.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [Scalar] {
        self.elems.as_mut_slice()
    }

    pub fn len(&self) -> usize {
        self.elems.len()
    }

    pub fn push(&mut self, value: Scalar) {
        self.elems.push(value)
    }

    pub fn append(&mut self, other: &mut Self) {
        self.elems.append(&mut other.elems)
    }

    pub fn pop(&mut self) -> Option<Scalar> {
        self.elems.pop()
    }

    pub fn insert(&mut self, index: usize, element: Scalar) {
        self.elems.insert(index, element)
    }

    pub fn remove(&mut self, index: usize) -> Scalar {
        self.elems.remove(index)
    }

    /// Multiply each element of the vector with a given field
    /// element `n` (scale the vector). Modifies the vector.
    pub fn scale(&mut self, n: &Scalar) {
        self.elems.as_mut_slice().par_iter_mut().for_each(|e| {
            *e *= n;
        })
    }

    /// Multiply each element of the vector with a given field
    /// element `n` to create a new vector
    pub fn scaled_by(&self, n: &Scalar) -> Self {
        let mut scaled = self.clone();
        scaled.scale(n);
        scaled
    }

    /// Add 2 vectors of field elements
    pub fn plus(&self, b: &ScalarVector) -> Result<ScalarVector, ValueError> {
        check_vector_size_for_equality!(self, b)?;
        let mut sum_vector = Self::new(self.len());
        sum_vector
            .as_mut_slice()
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, e)| *e = self[i] + b[i]);
        Ok(sum_vector)
    }

    /// Subtract 2 vectors of field elements
    pub fn minus(&self, b: &ScalarVector) -> Result<ScalarVector, ValueError> {
        check_vector_size_for_equality!(self, b)?;
        let mut diff_vector = Self::new(self.len());
        diff_vector
            .as_mut_slice()
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, e)| *e = self[i] - b[i]);
        Ok(diff_vector)
    }

    /// Compute sum of all elements of a vector
    pub fn sum(&self) -> Scalar {
        self.as_slice().par_iter().cloned().reduce(Scalar::default, |a, b| a + b)
    }

    /// Computes inner product of 2 vectors of field elements
    /// [a1, a2, a3, ...field elements].[b1, b2, b3, ...field elements] = (a1*b1 + a2*b2 + a3*b3) % curve_order
    pub fn inner_product(&self, b: &ScalarVector) -> Result<Scalar, ValueError> {
        check_vector_size_for_equality!(self, b)?;
        let r = (0..b.len())
            .into_par_iter()
            .map(|i| (self[i] * b[i]))
            .reduce(Scalar::default, |a, b| a + b);
        Ok(r)
    }

    /// Calculates Hadamard product of 2 field element vectors.
    /// Hadamard product of `a` and `b` = `a` o `b` = (a0 o b0, a1 o b1, ...).
    /// Here `o` denotes multiply operation
    pub fn hadamard_product(&self, b: &ScalarVector) -> Result<ScalarVector, ValueError> {
        check_vector_size_for_equality!(self, b)?;
        let mut hadamard_product = Self::new(self.len());
        hadamard_product
            .as_mut_slice()
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, e)| *e = self[i] * b[i]);
        Ok(hadamard_product)
    }

    pub fn split_at(&self, mid: usize) -> (Self, Self) {
        let (l, r) = self.as_slice().split_at(mid);
        (Self::from(l), Self::from(r))
    }

    // /// Replace a range `R` of the vector with `I`. Same as Vector's splice except it does not return
    // /// anything. Only available to this crate for now for some manipulations in Polynomial
    // pub(crate) fn splice<R, I>(&mut self, range: R, replace_with: I)
    // where
    //     R: RangeBounds<usize>,
    //     I: IntoIterator<Item = Scalar>,
    // {
    //     self.elems.splice(range, replace_with);
    // }

    pub fn iter(&self) -> Iter<Scalar> {
        self.as_slice().iter()
    }
}

impl From<Vec<Scalar>> for ScalarVector {
    fn from(x: Vec<Scalar>) -> Self {
        Self { elems: x }
    }
}

impl From<&[Scalar]> for ScalarVector {
    fn from(x: &[Scalar]) -> Self {
        Self { elems: x.to_vec() }
    }
}

impl From<ScalarVector> for Vec<Scalar> {
    fn from(val: ScalarVector) -> Self {
        val.elems
    }
}

impl<'a> From<&'a ScalarVector> for &'a [Scalar] {
    fn from(val: &'a ScalarVector) -> Self {
        &val.elems
    }
}

impl Index<usize> for ScalarVector {
    type Output = Scalar;

    fn index(&self, idx: usize) -> &Scalar {
        &self.elems[idx]
    }
}

impl IndexMut<usize> for ScalarVector {
    fn index_mut(&mut self, idx: usize) -> &mut Scalar {
        &mut self.elems[idx]
    }
}

impl PartialEq for ScalarVector {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        for i in 0..self.len() {
            if self[i] != other[i] {
                return false;
            }
        }
        true
    }
}

impl IntoIterator for ScalarVector {
    type Item = Scalar;
    type IntoIter = ::std::vec::IntoIter<Scalar>;

    fn into_iter(self) -> Self::IntoIter {
        self.elems.into_iter()
    }
}

impl AsRef<[Scalar]> for ScalarVector {
    fn as_ref(&self) -> &[Scalar] {
        self.elems.as_slice()
    }
}

/// Creates a new univariate polynomial from given coefficients from lower to higher degree terms
#[macro_export]
macro_rules! univar_polynomial {
    ( $( $elem:expr ),* ) => {
        {
            let mut coeffs = vec![];
            $(
                coeffs.push($elem);
            )*
            UnivarPolynomial(coeffs.into())
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly() {
        let degree = 10;
        let poly1 = UnivarPolynomial(ScalarVector::random(degree + 1));
        assert!(!poly1.is_zero());

        let poly2 = UnivarPolynomial(ScalarVector::new(degree + 1));
        assert!(poly2.is_zero());

        let poly3 = UnivarPolynomial::new(degree);
        assert!(poly3.is_zero());

        let poly4 = UnivarPolynomial::new_constant(Scalar::from(100u64));
        assert!(!poly4.is_zero());
        assert_eq!(poly4.degree(), 0);
        assert_eq!(poly4[0], Scalar::from(100u64));
    }

    #[test]
    fn test_create_poly_from_macro() {
        let poly = univar_polynomial!(
            Scalar::ONE,
            Scalar::ZERO,
            Scalar::from(87u64),
            -Scalar::ONE,
            Scalar::from(300u64)
        );
        assert_eq!(poly.degree(), 4);
        assert_eq!(poly[0], Scalar::ONE);
        assert_eq!(poly[1], Scalar::ZERO);
        assert_eq!(poly[2], Scalar::from(87u64));
        assert_eq!(poly[3], -Scalar::ONE);
        assert_eq!(poly[4], Scalar::from(300u64));
    }
}
