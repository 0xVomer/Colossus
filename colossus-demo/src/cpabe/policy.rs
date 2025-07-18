use colossus_core::policy::{AccessStructure, Dimension};

/// Trading access policy for institutional finance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub trading_level: TradingLevel,
    pub institution_type: InstitutionType,
    pub geographical_region: Region,
    pub compliance_level: ComplianceLevel,
}

impl Policy {
    /// Convert to Covercrypt policy format
    fn to_access_structure(&self) -> Result<AccessStructure, Error> {
        let mut policy = AccessStructure::new();
        TradingLevel::update_policy(&policy)?;
        InstitutionType::update_policy(&policy)?;
        Region::update_policy(&policy)?;
        ComplianceLevel::update_policy(&policy)?;
        Ok(policy)
    }
}

// Policy Dimensions & Attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TradingLevel {
    Basic,
    Intermediate,
    Advanced,
    Institutional,
}

impl TradingLevel {
    pub fn label() -> String {
        "TradingLevel".to_string()
    }
    pub fn update_policy(policy: &AccessStructure) -> Result<(), Error> {
        policy.add_hierarchy(self.label());
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Basic".to_string(),
            },
            None,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Intermediate".to_string(),
            },
            "Basic".to_string(),
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Advanced".to_string(),
            },
            "Intermediate".to_string(),
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Institutional".to_string(),
            },
            "Advanced".to_string(),
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstitutionType {
    Bank,
    HedgeFund,
    Insurance,
    Pension,
    FamilyOffice,
}

impl InstitutionType {
    pub fn label() -> String {
        "InstitutionType".to_string()
    }
    pub fn update_policy(policy: &AccessStructure) -> Result<(), Error> {
        policy.add_anarchy(self.label());
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Bank".to_string(),
            },
            None,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "HedgeFund".to_string(),
            },
            none,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Insurance".to_string(),
            },
            none,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Pension".to_string(),
            },
            none,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "FamilyOffice".to_string(),
            },
            none,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Region {
    NorthAmerica,
    Europe,
    Asia,
    Global,
}

impl Region {
    pub fn label() -> String {
        "Region".to_string()
    }
    pub fn update_policy(policy: &AccessStructure) -> Result<(), Error> {
        policy.add_anarchy(self.label());
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "NorthAmerica".to_string(),
            },
            None,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Europe".to_string(),
            },
            none,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Asia".to_string(),
            },
            none,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Global".to_string(),
            },
            none,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceLevel {
    Basic,
    Enhanced,
    Institutional,
    Regulatory,
}
impl ComplianceLevel {
    pub fn label() -> String {
        "ComplianceLevel".to_string()
    }
    pub fn update_policy(policy: &AccessStructure) -> Result<(), Error> {
        policy.add_hierarchy(self.label());
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Basic".to_string(),
            },
            None,
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Enhanced".to_string(),
            },
            "Basic".to_string(),
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Institutional".to_string(),
            },
            "Enhanced".to_string(),
        )?;
        policy.add_attribute(
            QualifiedAttribute {
                dimension: self.label(),
                name: "Regulatory".to_string(),
            },
            "Institutional".to_string(),
        )?;
        Ok(())
    }
}
