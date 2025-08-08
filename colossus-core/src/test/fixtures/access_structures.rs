use std::fmt;

use super::*;

pub struct Age(u8);

impl Age {
    pub fn claim(age: u8) -> Self {
        Self(age)
    }
    fn dimension_label() -> &'static str {
        "AGE"
    }
    fn attribute_label(&self) -> &'static str {
        match self.0 {
            0..=20 => "YOUTH",
            21..=60 => "ADULT",
            61..=100 => "SENIOR",
            _ => "UNKNOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), self.attribute_label())
    }

    fn young_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "YOUTH")
    }

    fn adult_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "ADULT")
    }

    fn senior_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "SENIOR")
    }

    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_hierarchy(Age::dimension_label().to_string())?;
        ac.add_attribute(Age::young_attribute(), None)?;
        ac.add_attribute(Age::adult_attribute(), Some("YOUTH"))?;
        ac.add_attribute(Age::senior_attribute(), Some("ADULT"))?;
        ac.add_attribute(Age::unknown_attribute(), Some("SENIOR"))?;

        Ok(ac)
    }
}

pub struct Location(String);

impl Location {
    pub fn claim(address: String) -> Self {
        Self(address)
    }
    fn dimension_label() -> &'static str {
        "LOC"
    }
    fn attribute_label(&self) -> &'static str {
        match self.0.as_str() {
            "innercity" => "INNER_CITY",
            "eastsydney" => "EAST_SYDNEY",
            "westsydney" => "WEST_SYDNEY",
            _ => "UNKOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), self.attribute_label())
    }

    fn inner_city_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "INNER_CITY")
    }

    fn east_sydney_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "EAST_SYDNEY")
    }

    fn west_sydney_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "WEST_SYDNEY")
    }

    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_anarchy(Location::dimension_label().to_string())?;
        ac.add_attribute(Location::inner_city_attribute(), None)?;
        ac.add_attribute(Location::east_sydney_attribute(), None)?;
        ac.add_attribute(Location::west_sydney_attribute(), None)?;
        ac.add_attribute(Location::unknown_attribute(), None)?;

        Ok(ac)
    }
}

pub enum Sex {
    MALE,
    FEMALE,
    UNKNOWN,
}

impl Sex {
    fn dimension_label() -> &'static str {
        "SEX"
    }
    fn attribute_label(&self) -> &'static str {
        match self {
            Sex::MALE => "MALE",
            Sex::FEMALE => "FEMALE",
            Sex::UNKNOWN => "UNKNOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), self.attribute_label())
    }

    fn male_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), "MALE")
    }

    fn female_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), "FEMALE")
    }
    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_anarchy(Sex::dimension_label().to_string())?;
        ac.add_attribute(Sex::male_attribute(), None)?;
        ac.add_attribute(Sex::female_attribute(), None)?;
        ac.add_attribute(Sex::unknown_attribute(), None)?;

        Ok(ac)
    }
}

pub struct Device(u8);

impl Device {
    pub fn claim(udi: u8) -> Self {
        Self(udi)
    }
    fn dimension_label() -> &'static str {
        "DEVICE"
    }
    fn attribute_label(&self) -> &'static str {
        match self.0 {
            0..=10 => "MOBILE",
            11..=40 => "LAPTOP",
            _ => "UNKOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), self.attribute_label())
    }

    fn mobile_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), "MOBILE")
    }

    fn laptop_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), "LAPTOP")
    }

    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), "UNKOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_hierarchy(Device::dimension_label().to_string())?;
        ac.add_attribute(Device::mobile_attribute(), None)?;
        ac.add_attribute(Device::laptop_attribute(), None)?;
        ac.add_attribute(Device::unknown_attribute(), None)?;

        Ok(ac)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Permission {
    READ,
    WRITE,
    EXECUTE,
    SEARCH,
    UNKNOWN,
}

impl Permission {
    fn dimension_label() -> &'static str {
        "PERM"
    }
    fn attribute_label(&self) -> &'static str {
        match self {
            Permission::READ => "READ",
            Permission::WRITE => "WRITE",
            Permission::EXECUTE => "EXECUTE",
            Permission::SEARCH => "SEARCH",
            Permission::UNKNOWN => "UNKNOWN",
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}::{}", Permission::dimension_label(), self.attribute_label())
    }

    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Permission::dimension_label(), self.attribute_label())
    }

    fn read_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Permission::dimension_label(), Permission::READ.attribute_label())
    }

    fn write_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Permission::dimension_label(), Permission::WRITE.attribute_label())
    }

    fn execute_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(
            Permission::dimension_label(),
            Permission::EXECUTE.attribute_label(),
        )
    }

    fn search_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Permission::dimension_label(), Permission::SEARCH.attribute_label())
    }

    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(
            Permission::dimension_label(),
            Permission::UNKNOWN.attribute_label(),
        )
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_anarchy(Permission::dimension_label().to_string())?;
        ac.add_attribute(Permission::read_attribute(), None)?;
        ac.add_attribute(Permission::write_attribute(), None)?;
        ac.add_attribute(Permission::search_attribute(), None)?;
        ac.add_attribute(Permission::execute_attribute(), None)?;
        ac.add_attribute(Permission::unknown_attribute(), None)?;

        Ok(ac)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Challenge {
    HasUserID,
    HasGroupID,
}

impl Challenge {
    fn dimension(&self) -> &'static str {
        match self {
            Challenge::HasUserID => UserID::dimension_label(),
            Challenge::HasGroupID => GroupID::dimension_label(),
        }
    }
    fn attribute(&self) -> &'static str {
        "KNOWN"
    }

    pub fn to_string(&self) -> String {
        format!("{}::{}", self.dimension(), self.attribute())
    }
}

pub struct UserID(u8);

impl UserID {
    pub fn claim(uid: u8) -> Self {
        Self(uid)
    }
    fn dimension_label() -> &'static str {
        "USERID"
    }
    fn attribute_label(&self) -> &'static str {
        if self.0 > 1 { "KNOWN" } else { "UNKNOWN" }
    }

    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(UserID::dimension_label(), self.attribute_label())
    }

    fn known_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(UserID::dimension_label(), "KNOWN")
    }

    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(UserID::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_hierarchy(UserID::dimension_label().to_string())?;
        ac.add_attribute(UserID::unknown_attribute(), None)?;
        ac.add_attribute(UserID::known_attribute(), Some("UNKNOWN"))?;
        Ok(ac)
    }

    pub fn to_string(&self) -> String {
        format!("{}::{}", UserID::dimension_label(), self.attribute_label())
    }
}

pub struct GroupID(u8);
impl GroupID {
    pub fn claim(uid: u8) -> Self {
        Self(uid)
    }
    fn dimension_label() -> &'static str {
        "GROUPID"
    }
    fn attribute_label(&self) -> &'static str {
        if self.0 > 1 { "KNOWN" } else { "UNKNOWN" }
    }

    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(GroupID::dimension_label(), self.attribute_label())
    }

    fn known_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(GroupID::dimension_label(), "KNOWN")
    }

    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(GroupID::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_hierarchy(GroupID::dimension_label().to_string())?;
        ac.add_attribute(GroupID::unknown_attribute(), None)?;
        ac.add_attribute(GroupID::known_attribute(), Some("UNKNOWN"))?;

        Ok(ac)
    }

    pub fn to_string(&self) -> String {
        format!("{}::{}", GroupID::dimension_label(), self.attribute_label())
    }
}
