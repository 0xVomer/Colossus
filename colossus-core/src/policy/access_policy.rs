//! Access Policy for specifying encryption requirements.
//!
//! An `AccessPolicy` defines which attribute combinations are required to decrypt data.
//! It supports boolean expressions with AND (`&&`) and OR (`||`) operators.
//!
//! # Example
//!
//! ```ignore
//! use colossus_core::policy::AccessPolicy;
//!
//! // Parse a policy from a string
//! let policy = AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY")?;
//!
//! // Broadcast policy (anyone can decrypt)
//! let broadcast = AccessPolicy::Broadcast;
//!
//! // Combine policies with operators
//! let p1 = AccessPolicy::term("AGE", "ADULT");
//! let p2 = AccessPolicy::term("LOC", "INNER_CITY");
//! let combined = p1 & p2; // Conjunction
//! ```

use super::Error;
use std::{
    collections::LinkedList,
    fmt::Debug,
    ops::{BitAnd, BitOr},
};

/// An attribute term in an access policy, represented as dimension::name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyTerm {
    /// The dimension name (e.g., "AGE", "LOC", "DEVICE")
    pub dimension: String,
    /// The attribute name within the dimension (e.g., "ADULT", "INNER_CITY")
    pub name: String,
}

impl PolicyTerm {
    /// Create a new policy term.
    pub fn new(dimension: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            dimension: dimension.into(),
            name: name.into(),
        }
    }

    /// Parse a term from "DIMENSION::NAME" format.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let (dimension, name) = s.split_once("::").ok_or_else(|| {
            Error::InvalidBooleanExpression(format!("expected 'DIMENSION::NAME' format, got '{s}'"))
        })?;

        if dimension.is_empty() || name.is_empty() {
            return Err(Error::InvalidBooleanExpression(format!(
                "empty dimension or name in '{s}'"
            )));
        }

        Ok(Self::new(dimension.trim(), name.trim()))
    }
}

impl std::fmt::Display for PolicyTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.dimension, self.name)
    }
}

/// A boolean expression defining access requirements.
///
/// Policies can be:
/// - `Broadcast`: Anyone can access (no restrictions)
/// - `Term(PolicyTerm)`: Requires a specific attribute
/// - `Conjunction`: Requires both sub-policies (AND)
/// - `Disjunction`: Requires either sub-policy (OR)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessPolicy {
    /// No restrictions - anyone can decrypt
    Broadcast,
    /// Requires a specific attribute (dimension::name)
    Term(PolicyTerm),
    /// Requires both policies to be satisfied (AND)
    Conjunction(Box<AccessPolicy>, Box<AccessPolicy>),
    /// Requires either policy to be satisfied (OR)
    Disjunction(Box<AccessPolicy>, Box<AccessPolicy>),
}

impl BitAnd for AccessPolicy {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        if self == Self::Broadcast {
            rhs
        } else if rhs == Self::Broadcast {
            self
        } else {
            Self::Conjunction(Box::new(self), Box::new(rhs))
        }
    }
}

impl BitOr for AccessPolicy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Broadcast {
            self
        } else if rhs == Self::Broadcast {
            rhs
        } else {
            Self::Disjunction(Box::new(self), Box::new(rhs))
        }
    }
}

impl AccessPolicy {
    /// Create a term policy for a specific attribute.
    pub fn term(dimension: impl Into<String>, name: impl Into<String>) -> Self {
        Self::Term(PolicyTerm::new(dimension, name))
    }

    /// Parse an access policy from a boolean expression string.
    ///
    /// # Syntax
    ///
    /// - `*` - Broadcast (anyone can decrypt)
    /// - `DIM::ATTR` - Requires specific attribute
    /// - `A && B` - Requires both A and B
    /// - `A || B` - Requires either A or B
    /// - `(A)` - Grouping
    ///
    /// # Example
    ///
    /// ```ignore
    /// let policy = AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY")?;
    /// ```
    pub fn parse(mut e: &str) -> Result<Self, Error> {
        let seeker = |c: &char| !"()|&".contains(*c);
        let mut q = LinkedList::<Self>::new();
        loop {
            e = e.trim();

            if e.is_empty() {
                if let Some(first) = q.pop_front() {
                    return Ok(Self::conjugate(first, q.into_iter()));
                } else {
                    return Err(Error::InvalidBooleanExpression(
                        "empty string is not a valid access policy".to_string(),
                    ));
                }
            } else if e == "*" {
                return Ok(Self::conjugate(Self::Broadcast, q.into_iter()));
            } else {
                match &e[..1] {
                    "(" => {
                        let offset = Self::find_matching_closing_parenthesis(&e[1..])?;
                        q.push_back(Self::parse(&e[1..1 + offset]).map_err(|err| {
                            Error::InvalidBooleanExpression(format!(
                                "error while parsing '{e}': {err}"
                            ))
                        })?);
                        e = &e[2 + offset..];
                    },
                    "|" => {
                        if e[1..].is_empty() || &e[1..2] != "|" {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "invalid separator in: '{e}'"
                            )));
                        }
                        let base = q.pop_front().ok_or_else(|| {
                            Error::InvalidBooleanExpression(format!("leading OR operand in '{e}'"))
                        })?;
                        let lhs = Self::conjugate(base, q.into_iter());
                        return Ok(lhs | Self::parse(&e[2..])?);
                    },
                    "&" => {
                        if e[1..].is_empty() || &e[1..2] != "&" {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "invalid leading separator in: '{e}'"
                            )));
                        }
                        if q.is_empty() {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "leading AND operand in '{e}'"
                            )));
                        }
                        e = &e[2..];
                    },
                    ")" => {
                        return Err(Error::InvalidBooleanExpression(format!(
                            "unmatched closing parenthesis in '{e}'"
                        )));
                    },
                    _ => {
                        let attr: String = e.chars().take_while(seeker).collect();
                        q.push_back(Self::Term(PolicyTerm::parse(attr.as_str())?));
                        e = &e[attr.len()..];
                    },
                }
            }
        }
    }

    fn find_matching_closing_parenthesis(boolean_expression: &str) -> Result<usize, Error> {
        let mut count = 0;
        for (index, c) in boolean_expression.chars().enumerate() {
            match c {
                '(' => count += 1,
                ')' => count -= 1,
                _ => {},
            };
            if count < 0 {
                return Ok(index);
            }
        }
        Err(Error::InvalidBooleanExpression(format!(
            "Missing closing parenthesis in boolean expression {boolean_expression}"
        )))
    }

    fn conjugate(first: Self, policies: impl Iterator<Item = Self>) -> Self {
        policies.fold(first, |mut res, operand| {
            res = res & operand;
            res
        })
    }

    /// Convert the policy to Disjunctive Normal Form (DNF).
    ///
    /// Returns a list of conjunctions (AND clauses), where any conjunction
    /// being satisfied means the policy is satisfied.
    ///
    /// Example: `(A && B) || C` becomes `[[A, B], [C]]`
    #[must_use]
    pub fn to_dnf(&self) -> Vec<Vec<PolicyTerm>> {
        match self {
            Self::Term(term) => vec![vec![term.clone()]],
            Self::Conjunction(lhs, rhs) => {
                let combinations_left = lhs.to_dnf();
                let combinations_right = rhs.to_dnf();
                let mut res =
                    Vec::with_capacity(combinations_left.len() * combinations_right.len());
                for value_left in combinations_left {
                    for value_right in &combinations_right {
                        res.push([value_left.as_slice(), value_right.as_slice()].concat());
                    }
                }
                res
            },
            Self::Disjunction(lhs, rhs) => [lhs.to_dnf(), rhs.to_dnf()].concat(),
            Self::Broadcast => vec![vec![]],
        }
    }

    /// Get all unique terms in the policy.
    pub fn terms(&self) -> Vec<&PolicyTerm> {
        match self {
            Self::Broadcast => vec![],
            Self::Term(term) => vec![term],
            Self::Conjunction(lhs, rhs) | Self::Disjunction(lhs, rhs) => {
                let mut terms = lhs.terms();
                terms.extend(rhs.terms());
                terms
            },
        }
    }

    /// Check if this is a broadcast policy.
    pub fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast)
    }
}

impl<T> TryFrom<&[T]> for AccessPolicy
where
    T: std::fmt::Display + Clone + PartialEq + Eq + std::hash::Hash + std::fmt::Debug,
{
    type Error = Error;

    fn try_from(attributes: &[T]) -> Result<Self, Self::Error> {
        let ap_string = format!(
            "({})",
            attributes
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" && ")
        );
        AccessPolicy::parse(ap_string.as_str())
    }
}

impl std::fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broadcast => write!(f, "*"),
            Self::Term(term) => write!(f, "{}", term),
            Self::Conjunction(lhs, rhs) => write!(f, "({} && {})", lhs, rhs),
            Self::Disjunction(lhs, rhs) => write!(f, "({} || {})", lhs, rhs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_policy_parsing() {
        let ap = AccessPolicy::parse("(D1::A && (D2::A) || D2::B)").unwrap();
        println!("{ap:#?}");
        let ap = AccessPolicy::parse("D1::A && D2::A || D2::B").unwrap();
        println!("{ap:#?}");
        let ap = AccessPolicy::parse("D1::A && (D2::A || D2::B)").unwrap();
        println!("{ap:#?}");
        let ap = AccessPolicy::parse("D1::A (D2::A || D2::B)").unwrap();
        println!("{ap:#?}");
        assert_eq!(AccessPolicy::parse("*").unwrap(), AccessPolicy::Broadcast);
        assert!(AccessPolicy::parse("").is_err());

        assert!(AccessPolicy::parse("D1").is_err());
        assert!(AccessPolicy::parse("D1::A (&& D2::A || D2::B)").is_err());
        assert!(AccessPolicy::parse("|| D2::B").is_err());
    }

    #[test]
    fn test_policy_term_parsing() {
        let term = PolicyTerm::parse("AGE::ADULT").unwrap();
        assert_eq!(term.dimension, "AGE");
        assert_eq!(term.name, "ADULT");

        assert!(PolicyTerm::parse("INVALID").is_err());
        assert!(PolicyTerm::parse("::NAME").is_err());
        assert!(PolicyTerm::parse("DIM::").is_err());
    }

    #[test]
    fn test_to_dnf() {
        // Simple term
        let p = AccessPolicy::parse("A::B").unwrap();
        let dnf = p.to_dnf();
        assert_eq!(dnf.len(), 1);
        assert_eq!(dnf[0].len(), 1);

        // Conjunction
        let p = AccessPolicy::parse("A::B && C::D").unwrap();
        let dnf = p.to_dnf();
        assert_eq!(dnf.len(), 1);
        assert_eq!(dnf[0].len(), 2);

        // Disjunction
        let p = AccessPolicy::parse("A::B || C::D").unwrap();
        let dnf = p.to_dnf();
        assert_eq!(dnf.len(), 2);

        // Complex
        let p = AccessPolicy::parse("(A::B || C::D) && E::F").unwrap();
        let dnf = p.to_dnf();
        assert_eq!(dnf.len(), 2); // (A::B && E::F) || (C::D && E::F)
    }

    #[test]
    fn test_policy_display() {
        let p = AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY").unwrap();
        let s = p.to_string();
        assert!(s.contains("AGE::ADULT"));
        assert!(s.contains("LOC::INNER_CITY"));
    }

    #[test]
    fn test_term_constructor() {
        let p = AccessPolicy::term("AGE", "ADULT") & AccessPolicy::term("LOC", "INNER_CITY");
        let terms = p.terms();
        assert_eq!(terms.len(), 2);
    }
}
