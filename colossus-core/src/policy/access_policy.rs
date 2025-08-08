use super::{Error, QualifiedAttribute};
use std::{
    collections::LinkedList,
    fmt::Debug,
    ops::{BitAnd, BitOr},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessPolicy {
    Broadcast,
    Term(QualifiedAttribute),
    Conjunction(Box<AccessPolicy>, Box<AccessPolicy>),
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

impl super::AccessPolicy {
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
                        q.push_back(Self::Term(QualifiedAttribute::try_from(attr.as_str())?));
                        e = &e[attr.len()..];
                    },
                }
            }
        }
    }

    fn conjugate(first: Self, policies: impl Iterator<Item = Self>) -> Self {
        policies.fold(first, |mut res, operand| {
            res = res & operand;
            res
        })
    }

    #[must_use]
    pub fn to_dnf(&self) -> Vec<Vec<QualifiedAttribute>> {
        match self {
            Self::Term(attr) => vec![vec![attr.clone()]],
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
}

impl<T> TryFrom<&[T]> for AccessPolicy
where
    T: std::fmt::Display + Clone + PartialEq + Eq + std::hash::Hash + std::fmt::Debug,
{
    type Error = crate::policy::Error;

    fn try_from(attributes: &[T]) -> Result<Self, Self::Error> {
        let ap_string = format!(
            "({})",
            attributes
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" && ")
        );
        // create an Access Policy String that joins all unique perms, e.g. "PERM::READ && PERM::WRITE"
        let ap = AccessPolicy::parse(ap_string.as_str())?;
        Ok(ap)
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::AccessPolicy;

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
}
