use crate::types::ProviderAttributes;
use colossus_core::policy::{AccessPolicy, AccessStructure, QualifiedAttribute};

pub fn provider_access_policy(attributes: &ProviderAttributes) -> AccessPolicy {
    // Create access policy from attributes
    let access_policy_str = format!(
        "Role::{} && Department::{} && Clearance::{} && Hospital::{}",
        attributes.role, attributes.department, attributes.clearance_level, attributes.hospital
    );
    let ap = AccessPolicy::parse(access_policy_str.to_string().as_str()).unwrap();
    ap
}

// Example access policies for different scenarios
pub enum HealthcareAccess {
    EmergencyAccess,
    CardiologySensitive,
    PharmacyPrescription,
    MultiDepartment,
}

impl ToString for HealthcareAccess {
    fn to_string(&self) -> String {
        match self {
            HealthcareAccess::EmergencyAccess => format!(
                "{} && {} && {}",
                Role::Doctor.policy_label(),
                Department::Emergency.policy_label(),
                Clearance::Advanced.policy_label()
            ),
            HealthcareAccess::CardiologySensitive => format!(
                "{} && {} && {}",
                Role::Doctor.policy_label(),
                Department::Cardiology.policy_label(),
                SecurityLevel::Sensitive.policy_label()
            ),
            HealthcareAccess::PharmacyPrescription => format!(
                "{} && {} && {}",
                Role::Pharmacist.policy_label(),
                Department::Pharmacy.policy_label(),
                Clearance::Standard.policy_label()
            ),
            HealthcareAccess::MultiDepartment => format!(
                "({} || {}) && ({} || {}) && {}",
                Role::Doctor.policy_label(),
                Role::Nurse.policy_label(),
                Department::Emergency.policy_label(),
                Department::Cardiology.policy_label(),
                Clearance::Advanced.policy_label()
            ),
        }
        .into()
    }
}

impl HealthcareAccess {
    pub fn create_policy(&self) -> AccessPolicy {
        let ap = AccessPolicy::parse(self.to_string().as_str()).unwrap();
        ap
    }
}

pub enum Department {
    Emergency,
    Cardiology,
    Radiology,
    Pharmacy,
    Lab,
    Surgery,
}

impl ToString for Department {
    fn to_string(&self) -> String {
        match self {
            Department::Emergency => "EMERGENCY",
            Department::Cardiology => "CARDIOLOGY",
            Department::Radiology => "RADIOLOGY",
            Department::Pharmacy => "PHARMACY",
            Department::Lab => "LAB",
            Department::Surgery => "SURGERY",
        }
        .into()
    }
}

impl Department {
    pub fn dimension() -> String {
        "DPT".to_string()
    }
    pub fn policy_label(&self) -> String {
        format!("{}::{}", Department::dimension(), self.to_string())
    }
    pub fn attributes() -> Vec<QualifiedAttribute> {
        [
            Department::Emergency,
            Department::Cardiology,
            Department::Pharmacy,
            Department::Lab,
            Department::Surgery,
        ]
        .into_iter()
        .map(|attribute| QualifiedAttribute {
            dimension: Department::dimension(),
            name: attribute.to_string(),
        })
        .collect::<Vec<QualifiedAttribute>>()
    }

    pub fn add_to_access_structure(access_structure: &mut AccessStructure) {
        access_structure.add_anarchy(Department::dimension()).unwrap();
        Department::attributes()
            .into_iter()
            .try_for_each(|attribute| access_structure.add_attribute(attribute, None))
            .unwrap();
    }
}

pub enum Hospital {
    GeneralHopsital,
    ChildrenHopsital,
    HeartCenter,
    CancerCenter,
}

impl ToString for Hospital {
    fn to_string(&self) -> String {
        match self {
            Hospital::GeneralHopsital => "GEN",
            Hospital::ChildrenHopsital => "CHILD",
            Hospital::HeartCenter => "HEART",
            Hospital::CancerCenter => "CANCER",
        }
        .into()
    }
}

impl Hospital {
    pub fn dimension() -> String {
        "HOSP".to_string()
    }
    pub fn policy_label(&self) -> String {
        format!("{}::{}", Hospital::dimension(), self.to_string())
    }
    pub fn attributes() -> Vec<QualifiedAttribute> {
        [
            Hospital::GeneralHopsital,
            Hospital::ChildrenHopsital,
            Hospital::HeartCenter,
            Hospital::CancerCenter,
        ]
        .into_iter()
        .map(|attribute| QualifiedAttribute {
            dimension: Hospital::dimension(),
            name: attribute.to_string(),
        })
        .collect::<Vec<QualifiedAttribute>>()
    }

    pub fn add_to_access_structure(access_structure: &mut AccessStructure) {
        access_structure.add_anarchy(Hospital::dimension()).unwrap();
        Hospital::attributes()
            .into_iter()
            .try_for_each(|attribute| access_structure.add_attribute(attribute, None))
            .unwrap();
    }
}

// Hierarchical - higher levels can access lower levels
pub enum SecurityLevel {
    Public,
    Sensitive,
    HighlySensitive,
}

impl ToString for SecurityLevel {
    fn to_string(&self) -> String {
        match self {
            SecurityLevel::Public => "PUB",
            SecurityLevel::Sensitive => "SENS",
            SecurityLevel::HighlySensitive => "HSENS",
        }
        .into()
    }
}

impl SecurityLevel {
    pub fn dimension() -> String {
        "SEC".to_string()
    }
    pub fn policy_label(&self) -> String {
        format!("{}::{}", SecurityLevel::dimension(), self.to_string())
    }
    pub fn attributes() -> Vec<QualifiedAttribute> {
        [SecurityLevel::Public, SecurityLevel::Sensitive, SecurityLevel::HighlySensitive]
            .into_iter()
            .map(|attribute| QualifiedAttribute {
                dimension: SecurityLevel::dimension(),
                name: attribute.to_string(),
            })
            .collect::<Vec<QualifiedAttribute>>()
    }
    pub fn add_to_access_structure(access_structure: &mut AccessStructure) {
        access_structure.add_hierarchy(SecurityLevel::dimension()).unwrap();
        access_structure
            .add_attribute(
                QualifiedAttribute {
                    dimension: SecurityLevel::dimension(),
                    name: SecurityLevel::Public.to_string(),
                },
                None,
            )
            .unwrap();
        access_structure
            .add_attribute(
                QualifiedAttribute {
                    dimension: SecurityLevel::dimension(),
                    name: SecurityLevel::Sensitive.to_string(),
                },
                Some(SecurityLevel::Public.to_string().as_str()),
            )
            .unwrap();
        access_structure
            .add_attribute(
                QualifiedAttribute {
                    dimension: SecurityLevel::dimension(),
                    name: SecurityLevel::HighlySensitive.to_string(),
                },
                Some(SecurityLevel::Sensitive.to_string().as_str()),
            )
            .unwrap();
    }
}

// Not hierarchical - specific roles only
pub enum Role {
    Patient,
    Pharmacist,
    Doctor,
    Nurse,
    Admin,
}

impl ToString for Role {
    fn to_string(&self) -> String {
        match self {
            Role::Patient => "PATIENT",
            Role::Pharmacist => "PHARMACIST",
            Role::Doctor => "DOCTOR",
            Role::Nurse => "NURSE",
            Role::Admin => "ADMIN",
        }
        .into()
    }
}

impl Role {
    pub fn dimension() -> String {
        "ROLE".to_string()
    }
    pub fn policy_label(&self) -> String {
        format!("{}::{}", Role::dimension(), self.to_string())
    }
    pub fn attributes() -> Vec<QualifiedAttribute> {
        [Role::Patient, Role::Pharmacist, Role::Doctor, Role::Nurse, Role::Admin]
            .into_iter()
            .map(|attribute| QualifiedAttribute {
                dimension: Role::dimension(),
                name: attribute.to_string(),
            })
            .collect::<Vec<QualifiedAttribute>>()
    }

    pub fn add_to_access_structure(access_structure: &mut AccessStructure) {
        access_structure.add_anarchy(Role::dimension()).unwrap();
        Role::attributes()
            .into_iter()
            .try_for_each(|attribute| access_structure.add_attribute(attribute, None))
            .unwrap();
    }
}

// Hierarchical clearance levels
pub enum Clearance {
    Basic,
    Standard,
    Advanced,
    Critical,
}

impl ToString for Clearance {
    fn to_string(&self) -> String {
        match self {
            Clearance::Basic => "BASIC",
            Clearance::Standard => "STD",
            Clearance::Advanced => "ADV",
            Clearance::Critical => "CRIT",
        }
        .into()
    }
}

impl Clearance {
    pub fn dimension() -> String {
        "CLR".to_string()
    }
    pub fn policy_label(&self) -> String {
        format!("{}::{}", Clearance::dimension(), self.to_string())
    }
    pub fn attributes() -> Vec<QualifiedAttribute> {
        [SecurityLevel::Public, SecurityLevel::Sensitive, SecurityLevel::HighlySensitive]
            .into_iter()
            .map(|attribute| QualifiedAttribute {
                dimension: Clearance::dimension(),
                name: attribute.to_string(),
            })
            .collect::<Vec<QualifiedAttribute>>()
    }
    pub fn add_to_access_structure(access_structure: &mut AccessStructure) {
        access_structure.add_hierarchy(Clearance::dimension()).unwrap();
        access_structure
            .add_attribute(
                QualifiedAttribute {
                    dimension: Clearance::dimension(),
                    name: Clearance::Basic.to_string(),
                },
                None,
            )
            .unwrap();
        access_structure
            .add_attribute(
                QualifiedAttribute {
                    dimension: Clearance::dimension(),
                    name: Clearance::Standard.to_string(),
                },
                Some(Clearance::Basic.to_string().as_str()),
            )
            .unwrap();
        access_structure
            .add_attribute(
                QualifiedAttribute {
                    dimension: Clearance::dimension(),
                    name: Clearance::Advanced.to_string(),
                },
                Some(Clearance::Standard.to_string().as_str()),
            )
            .unwrap();
        access_structure
            .add_attribute(
                QualifiedAttribute {
                    dimension: Clearance::dimension(),
                    name: Clearance::Critical.to_string(),
                },
                Some(Clearance::Advanced.to_string().as_str()),
            )
            .unwrap();
    }
}
