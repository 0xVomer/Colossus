use super::{
    ATTRIBUTE, AccessPolicy, Attribute, AttributeStatus, Dict, Dimension, Error,
    QualifiedAttribute, Right,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt::Debug,
};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AccessStructure {
    dimensions: HashMap<String, super::Dimension>,
}

impl Default for AccessStructure {
    fn default() -> Self {
        Self { dimensions: HashMap::new() }
    }
}

impl AccessStructure {
    pub fn new() -> Self {
        Self { dimensions: HashMap::new() }
    }
}

impl AccessStructure {
    pub fn ap_to_usk_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        self.generate_complementary_rights(ap)
    }

    pub fn ap_to_enc_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        self.generate_associated_rights(ap)
    }

    pub fn add_anarchy(&mut self, dimension: String) -> Result<(), Error> {
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::Anarchy(HashMap::new()));
                Ok(())
            },
        }
    }

    pub fn add_hierarchy(&mut self, dimension: String) -> Result<(), Error> {
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::Hierarchy(Dict::new()));
                Ok(())
            },
        }
    }

    pub fn del_dimension(&mut self, dimension: &str) -> Result<(), Error> {
        self.dimensions
            .remove(dimension)
            .map(|_| ())
            .ok_or(Error::DimensionNotFound(dimension.to_string()))
    }

    pub fn add_attribute(
        &mut self,
        attribute: QualifiedAttribute,
        after: Option<&str>,
    ) -> Result<(), Error> {
        let cnt = self.dimensions.values().map(Dimension::nb_attributes).sum::<usize>();

        let after = after
            .map(|after| QualifiedAttribute::from((attribute.dimension.as_str(), after)).bytes());

        self.dimensions
            .get_mut(&attribute.dimension)
            .ok_or_else(|| Error::DimensionNotFound(attribute.dimension.clone()))?
            .add_attribute(attribute.bytes(), after, cnt)?;

        Ok(())
    }

    pub fn del_attribute(&mut self, attr: &QualifiedAttribute) -> Result<(), Error> {
        if let Some(dim) = self.dimensions.get_mut(&attr.dimension) {
            dim.remove_attribute(&attr.bytes())
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    pub fn update_attribute(
        &mut self,
        attribute: &QualifiedAttribute,
        new_digest: ATTRIBUTE,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&attribute.dimension) {
            Some(d) => d.update_attribute(&attribute.bytes(), new_digest),
            None => Err(Error::DimensionNotFound(attribute.dimension.to_string())),
        }
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &str> {
        self.dimensions.keys().map(|d| d.as_str())
    }

    pub fn no_attributes(&'_ self) -> usize {
        self.dimensions.values().map(|d| d.nb_attributes()).sum()
    }

    pub fn attributes(&'_ self) -> impl '_ + Iterator<Item = QualifiedAttribute> {
        self.dimensions.iter().flat_map(|(dimension, d)| {
            d.get_attributes_name()
                .map(move |attr| QualifiedAttribute::from((dimension.as_str(), attr)))
        })
    }

    pub fn disable_attribute(&mut self, attr: &QualifiedAttribute) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(d) => d.disable_attribute(&attr.bytes()),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    pub(crate) fn omega(&self) -> Result<HashMap<Right, AttributeStatus>, Error> {
        let universe = self.dimensions.iter().collect::<Vec<_>>();
        combine(universe.as_slice())
            .into_iter()
            .map(|(ids, is_readonly)| Right::from_point(ids).map(|r| (r, (is_readonly))))
            .collect()
    }

    fn get_attribute(&self, attr: &QualifiedAttribute) -> Result<&Attribute, Error> {
        if let Some(dim) = self.dimensions.get(&attr.dimension) {
            dim.get_attribute(&attr.bytes())
                .ok_or(Error::AttributeNotFound(attr.to_string()))
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    #[cfg(test)]
    fn get_attribute_id(&self, attribute: &QualifiedAttribute) -> Result<usize, Error> {
        self.get_attribute(attribute).map(Attribute::get_id)
    }

    fn generate_semantic_space(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<HashMap<String, Dimension>, Error> {
        clause
            .iter()
            .map(|qa| {
                self.dimensions
                    .get(&qa.dimension)
                    .ok_or_else(|| Error::DimensionNotFound(qa.dimension.clone()))
                    .and_then(|d| d.restrict(&qa.bytes()))
                    .map(|d| (qa.dimension.clone(), d))
            })
            .collect()
    }

    fn generate_complementary_points(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<Vec<Vec<usize>>, Error> {
        let semantic_space = self.generate_semantic_space(clause)?;

        let semantic_points = combine(semantic_space.iter().collect::<Vec<_>>().as_slice())
            .into_iter()
            .map(|(ids, _)| ids)
            .collect::<Vec<_>>();

        let restricted_space = self
            .dimensions
            .iter()
            .filter(|(name, _)| !semantic_space.contains_key(*name))
            .collect::<Vec<_>>();

        let complementary_points = combine(&restricted_space)
            .into_iter()
            .flat_map(|(prefix, _)| {
                semantic_points.iter().map(move |suffix| {
                    let mut prefix = prefix.clone();
                    prefix.append(&mut suffix.clone());
                    prefix
                })
            })
            .collect::<Vec<_>>();

        Ok(complementary_points)
    }

    fn generate_complementary_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        let points = ap
            .to_dnf()
            .iter()
            .map(|qas| self.generate_complementary_points(qas))
            .try_fold(HashSet::new(), |mut acc, ids| {
                ids?.into_iter().for_each(|ids| {
                    acc.insert(ids);
                });
                Ok::<HashSet<Vec<usize>>, Error>(acc)
            })?;

        points.into_iter().map(Right::from_point).collect()
    }

    fn generate_associated_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        let dnf = ap.to_dnf();
        let len = dnf.len();
        dnf.into_iter()
            .try_fold(HashSet::with_capacity(len), |mut rights, conjunction| {
                let r = Right::from_point(
                    conjunction
                        .into_iter()
                        .map(|attr| self.get_attribute(&attr).map(|params| params.id))
                        .collect::<Result<_, _>>()?,
                )?;
                rights.insert(r);
                Ok(rights)
            })
    }
}

fn combine(dimensions: &[(&String, &Dimension)]) -> Vec<(Vec<usize>, AttributeStatus)> {
    if dimensions.is_empty() {
        vec![(vec![], AttributeStatus::EncryptDecrypt)]
    } else {
        let (_, current_dimension) = &dimensions[0];
        let partial_combinations = combine(&dimensions[1..]);
        let mut res = vec![];
        for component in current_dimension.attributes() {
            for (ids, is_activated) in &partial_combinations {
                res.push((
                    [vec![component.get_id()], ids.clone()].concat(),
                    *is_activated | component.get_status(),
                ));
            }
        }
        [partial_combinations.clone(), res].concat()
    }
}

mod serialization {
    use crate::policy::*;
    use cosmian_crypto_core::bytes_ser_de::{
        Deserializer, Serializable, Serializer, to_leb128_len,
    };

    impl Serializable for AccessStructure {
        type Error = Error;

        fn length(&self) -> usize {
            to_leb128_len(self.dimensions.len())
                + self
                    .dimensions
                    .iter()
                    .map(|(name, dimension)| {
                        let l = name.len();
                        to_leb128_len(l) + l + dimension.length()
                    })
                    .sum::<usize>()
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = ser.write_leb128_u64(self.dimensions.len() as u64)?;
            self.dimensions.iter().try_for_each(|(name, dimension)| {
                n += ser.write_vec(name.as_bytes())?;
                n += ser.write(dimension)?;
                Ok::<_, Self::Error>(())
            })?;
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let dimensions = {
                (0..de.read_leb128_u64()?)
                    .map(|_| {
                        let name = String::from_utf8(de.read_vec()?)
                            .map_err(|e| Error::ConversionFailed(e.to_string()))?;
                        let dimension = de.read::<Dimension>()?;
                        Ok((name, dimension))
                    })
                    .collect::<Result<std::collections::HashMap<_, _>, Error>>()
            }?;
            Ok(Self { dimensions })
        }
    }

    #[test]
    fn test_access_structure_serialization() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let mut structure = AccessStructure::new();
        gen_test_structure(&mut structure, false).unwrap();
        test_serialization(&structure).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::*;

    #[test]
    fn test_combine() {
        let mut structure = AccessStructure::new();
        gen_test_structure(&mut structure, false).unwrap();

        assert_eq!(
            combine(&structure.dimensions.iter().collect::<Vec<_>>()).len(),
            structure
                .dimensions
                .values()
                .map(|d| d.attributes().count() + 1)
                .product::<usize>()
        );

        structure.add_anarchy("Country".to_string()).unwrap();
        [("France"), ("Germany"), ("Spain")]
            .into_iter()
            .try_for_each(|attribute| {
                structure.add_attribute(QualifiedAttribute::new("Country", attribute), None)
            })
            .unwrap();

        assert_eq!(
            combine(&structure.dimensions.iter().collect::<Vec<_>>()).len(),
            structure
                .dimensions
                .values()
                .map(|dim| dim.attributes().count() + 1)
                .product::<usize>()
        );
    }

    #[test]
    fn test_generate_complementary_rights() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_test_structure(&mut structure, false).unwrap();

        {
            let ap = "(DPT::HR || DPT::FIN) && SEC::TOP";
            let comp_points = structure.generate_complementary_rights(&AccessPolicy::parse(ap)?)?;

            let mut rights = HashSet::new();

            rights.insert(Right::from_point(vec![])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("DPT", "FIN")))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("DPT", "HR")))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("SEC", "LOW")))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("SEC", "TOP")))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("DPT", "FIN")))?,
                structure.get_attribute_id(&QualifiedAttribute::from(("SEC", "LOW")))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("DPT", "HR")))?,
                structure.get_attribute_id(&QualifiedAttribute::from(("SEC", "LOW")))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("DPT", "HR")))?,
                structure.get_attribute_id(&QualifiedAttribute::from(("SEC", "TOP")))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::from(("DPT", "FIN")))?,
                structure.get_attribute_id(&QualifiedAttribute::from(("SEC", "TOP")))?,
            ])?);

            assert_eq!(comp_points, rights);
        }

        {
            let ap = "DPT::HR";
            assert_eq!(
                structure.generate_complementary_rights(&AccessPolicy::parse(ap)?)?.len(),
                2 * (1 + 2)
            );

            let ap = "SEC::LOW";
            assert_eq!(
                structure.generate_complementary_rights(&AccessPolicy::parse(ap)?)?.len(),
                2 * (1 + 5)
            );
        }
        Ok(())
    }
}
