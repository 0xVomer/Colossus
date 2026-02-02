use super::{ATTRIBUTE, Dict, Error};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, hash_map::Entry},
    fmt::Debug,
    ops::BitOr,
};

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttributeStatus {
    EncryptDecrypt,
    DecryptOnly,
}

impl BitOr for AttributeStatus {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::DecryptOnly || rhs == Self::DecryptOnly {
            Self::DecryptOnly
        } else {
            Self::EncryptDecrypt
        }
    }
}

impl From<AttributeStatus> for bool {
    fn from(val: AttributeStatus) -> Self {
        val == AttributeStatus::EncryptDecrypt
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Attribute {
    pub(crate) id: usize,
    pub(crate) write_status: AttributeStatus,
}

impl Attribute {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_status(&self) -> AttributeStatus {
        self.write_status
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum Dimension {
    Anarchy(HashMap<ATTRIBUTE, Attribute>),
    Hierarchy(Dict<ATTRIBUTE, Attribute>),
}

impl Default for Dimension {
    fn default() -> Self {
        Self::Anarchy(Default::default())
    }
}

impl Dimension {
    pub fn nb_attributes(&self) -> usize {
        match self {
            Self::Anarchy(attributes) => attributes.len(),
            Self::Hierarchy(attributes) => attributes.len(),
        }
    }

    pub fn is_ordered(&self) -> bool {
        match self {
            Self::Anarchy(_) => false,
            Self::Hierarchy(_) => true,
        }
    }

    pub fn get_attribute_ids(&self) -> Box<dyn '_ + Iterator<Item = &ATTRIBUTE>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.keys()),
            Self::Hierarchy(attributes) => Box::new(attributes.keys()),
        }
    }

    pub fn get_attribute_id(&self, index: usize) -> Option<&ATTRIBUTE> {
        match self {
            Self::Anarchy(attributes) => attributes.keys().nth(index),
            Self::Hierarchy(attributes) => attributes.keys().nth(index),
        }
    }

    pub fn get_attribute_pairs(&self) -> Box<dyn '_ + Iterator<Item = (&ATTRIBUTE, &ATTRIBUTE)>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.keys().zip(attributes.keys().skip(1))),
            Self::Hierarchy(attributes) => {
                Box::new(attributes.keys().zip(attributes.keys().skip(1)))
            },
        }
    }

    pub fn has_attribute(&self, attr: &ATTRIBUTE) -> bool {
        match self {
            Self::Anarchy(attributes) => attributes.contains_key(attr),
            Self::Hierarchy(attributes) => attributes.contains_key(attr),
        }
    }

    pub fn get_attribute(&self, attr: &ATTRIBUTE) -> Option<&Attribute> {
        match self {
            Self::Anarchy(attributes) => attributes.get(attr),
            Self::Hierarchy(attributes) => attributes.get(attr),
        }
    }
}

impl Dimension {
    pub fn restrict(&self, attr: &ATTRIBUTE) -> Result<Self, Error> {
        let params = self
            .get_attribute(attr)
            .ok_or_else(|| Error::AttributeNotFound(attr.to_string()))?
            .clone();

        match self {
            Self::Hierarchy(attributes) => {
                let mut attributes = attributes
                    .iter()
                    .take_while(|(h, _)| *h != attr)
                    .map(|(ref_attr, ref_params)| (ref_attr.clone(), ref_params.clone()))
                    .collect::<Dict<ATTRIBUTE, Attribute>>();
                attributes.insert(attr.clone(), params);
                Ok(Self::Hierarchy(attributes))
            },
            Self::Anarchy(_) => Ok(Self::Anarchy(HashMap::from_iter([(attr.clone(), params)]))),
        }
    }

    pub fn add_attribute(
        &mut self,
        attribute: ATTRIBUTE,
        after: Option<ATTRIBUTE>,
        id: usize,
    ) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => {
                if let Entry::Vacant(entry) = attributes.entry(attribute) {
                    entry.insert(Attribute::new(id));
                    Ok(())
                } else {
                    Err(Error::OperationNotPermitted("Attribute already in dimension".to_string()))
                }
            },
            Self::Hierarchy(attributes) => {
                if attributes.contains_key(&attribute) {
                    return Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ));
                }
                let after = if let Some(after) = after {
                    if !attributes.contains_key(&after) {
                        return Err(Error::AttributeNotFound(
                            "the specified `after` attribute {after} does not exist".to_string(),
                        ));
                    }
                    after
                } else {
                    ATTRIBUTE::default()
                };
                let higher_attributes = attributes
                    .clone()
                    .into_iter()
                    .rev()
                    .take_while(|(attr, _)| *attr != after)
                    .collect::<Vec<_>>();

                let mut new_attributes = attributes
                    .clone()
                    .into_iter()
                    .take_while(|a| Some(a) != higher_attributes.last())
                    .collect::<Dict<_, _>>();

                new_attributes.insert(attribute, Attribute::new(id));
                higher_attributes.into_iter().rev().for_each(|(name, dim)| {
                    new_attributes.insert(name, dim);
                });
                *attributes = new_attributes;
                Ok(())
            },
        }
    }

    pub fn remove_attribute(&mut self, attr: &ATTRIBUTE) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => attributes
                .remove(attr)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(attr.to_string())),
            Self::Hierarchy(attributes) => attributes
                .remove(attr)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(attr.to_string())),
        }
    }

    pub fn disable_attribute(&mut self, attr: &ATTRIBUTE) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => attributes
                .get_mut(attr)
                .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(attr.to_string())),
            Self::Hierarchy(attributes) => attributes
                .get_mut(attr)
                .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(attr.to_string())),
        }
    }

    pub fn update_attribute(
        &mut self,
        old_digest: &ATTRIBUTE,
        new_attributes: ATTRIBUTE,
    ) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => {
                if attributes.contains_key(&new_attributes) {
                    return Err(Error::OperationNotPermitted(
                        "New attribute name is already used in the same dimension".to_string(),
                    ));
                }
                match attributes.remove(old_digest) {
                    Some(attr_params) => {
                        attributes.insert(new_attributes, attr_params);
                        Ok(())
                    },
                    None => Err(Error::AttributeNotFound(old_digest.to_string())),
                }
            },
            Self::Hierarchy(attributes) => attributes
                .update_key(old_digest, new_attributes)
                .map_err(|e| Error::OperationNotPermitted(e.to_string())),
        }
    }

    pub fn attributes(&self) -> Box<dyn '_ + Iterator<Item = &Attribute>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.values()),
            Self::Hierarchy(attributes) => Box::new(attributes.values()),
        }
    }
}

mod serialization {
    use cosmian_crypto_core::bytes_ser_de::{
        Deserializer, Serializable, Serializer, to_leb128_len,
    };

    use super::*;

    impl Serializable for Attribute {
        type Error = Error;

        fn length(&self) -> usize {
            1 + to_leb128_len(self.id)
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = ser.write_leb128_u64(self.id as u64)?;
            n += ser.write_leb128_u64(<bool>::from(self.write_status) as u64)?;
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let id = de.read_leb128_u64()?.try_into()?;
            let status = de.read_leb128_u64()?;
            let write_status = if 0 == status {
                AttributeStatus::DecryptOnly
            } else if 1 == status {
                AttributeStatus::EncryptDecrypt
            } else {
                return Err(Error::ConversionFailed(format!("erroneous status value")));
            };
            Ok(Self { id, write_status })
        }
    }

    #[test]
    fn test_attribute_serialization() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let attribute = Attribute::new(13);
        test_serialization(&attribute).unwrap();

        let attribute = Attribute::new(usize::MAX);
        test_serialization(&attribute).unwrap();
    }

    impl Serializable for Dimension {
        type Error = Error;

        fn length(&self) -> usize {
            let f = |attributes: Box<dyn Iterator<Item = (&ATTRIBUTE, &Attribute)>>| {
                attributes
                    .map(|(name, attribute)| {
                        let l = name.len();
                        to_leb128_len(l) + l + attribute.length()
                    })
                    .sum::<usize>()
            };
            1 + match self {
                Dimension::Anarchy(attributes) => {
                    to_leb128_len(attributes.len()) + f(Box::new(attributes.iter()))
                },
                Dimension::Hierarchy(attributes) => {
                    to_leb128_len(attributes.len()) + f(Box::new(attributes.iter()))
                },
            }
        }

        fn write(
            &self,
            ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
        ) -> Result<usize, Self::Error> {
            let write_attributes =
                |mut attributes: Box<dyn Iterator<Item = (&ATTRIBUTE, &Attribute)>>,
                 ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer|
                 -> Result<usize, Error> {
                    attributes.try_fold(0, |mut n, (attr, attribute)| {
                        n += ser.write_vec(attr)?;
                        n += ser.write(attribute)?;
                        Ok(n)
                    })
                };

            let mut n = ser.write_leb128_u64(self.is_ordered() as u64)?;
            match self {
                Dimension::Anarchy(attributes) => {
                    n += ser.write_leb128_u64(attributes.len() as u64)?;
                    n += write_attributes(Box::new(attributes.iter()), ser)?;
                },
                Dimension::Hierarchy(attributes) => {
                    n += ser.write_leb128_u64(attributes.len() as u64)?;
                    n += write_attributes(Box::new(attributes.iter()), ser)?;
                },
            };

            Ok(n)
        }

        fn read(
            de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer,
        ) -> Result<Self, Self::Error> {
            let is_ordered = de.read_leb128_u64()?;
            let l = de.read_leb128_u64()?;
            let attributes = (0..l).map(|_| {
                let attr = ATTRIBUTE::from(de.read_vec()?);
                let attribute = de.read::<Attribute>()?;
                Ok::<_, Error>((attr, attribute))
            });

            if 0 == is_ordered {
                attributes.collect::<Result<_, _>>().map(Self::Anarchy)
            } else if 1 == is_ordered {
                attributes.collect::<Result<_, _>>().map(Self::Hierarchy)
            } else {
                Err(Error::ConversionFailed(format!("invalid boolean value {is_ordered}")))
            }
        }
    }

    #[test]
    fn test_dimension_serialization() {
        use crate::policy::ATTRIBUTE;
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        // Create test attribute identifiers
        let attr_a = ATTRIBUTE::from(b"test_attr_a".to_vec());
        let attr_b = ATTRIBUTE::from(b"test_attr_b".to_vec());
        let attr_c = ATTRIBUTE::from(b"test_attr_c".to_vec());

        let mut d = Dimension::Hierarchy(Dict::new());

        d.add_attribute(attr_a.clone(), None, 0).unwrap();
        d.add_attribute(attr_b.clone(), Some(attr_a.clone()), 1).unwrap();
        d.add_attribute(attr_c.clone(), Some(attr_b.clone()), 2).unwrap();
        test_serialization(&d).unwrap();

        let mut d = Dimension::Anarchy(HashMap::new());
        d.add_attribute(attr_a.clone(), None, 0).unwrap();
        d.add_attribute(attr_b.clone(), None, 1).unwrap();
        d.add_attribute(attr_c.clone(), None, 2).unwrap();

        test_serialization(&d).unwrap();
    }
}
