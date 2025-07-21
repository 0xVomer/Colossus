use anyhow::{Result, anyhow};
use ucan::capability::{Ability, CapabilitySemantics, Scope};
use url::Url;

#[derive(Ord, Eq, PartialOrd, PartialEq, Clone)]
pub enum HealthCareAction {
    Read,
    Write,
    Prescribe,
    UpdateVitals,
    AddConsultant,
    EmergencyOverride,
}

impl Ability for HealthCareAction {}

impl TryFrom<String> for HealthCareAction {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Ok(match value.as_str() {
            "healthcare/read" => HealthCareAction::Read,
            "healthcare/write" => HealthCareAction::Write,
            "healthcare/prescribe" => HealthCareAction::Prescribe,
            "healthcare/update_vitals" => HealthCareAction::UpdateVitals,
            "healthcare/add_consultant" => HealthCareAction::AddConsultant,
            "healthcare/emergency_override" => HealthCareAction::EmergencyOverride,
            _ => return Err(anyhow!("No such WNFS capability level: {}", value)),
        })
    }
}

impl ToString for HealthCareAction {
    fn to_string(&self) -> String {
        match self {
            HealthCareAction::Read => "healthcare/read",
            HealthCareAction::Write => "healthcare/write",
            HealthCareAction::Prescribe => "healthcare/prescribe",
            HealthCareAction::UpdateVitals => "healthcare/update_vitals",
            HealthCareAction::AddConsultant => "healthcare/add_consultant",
            HealthCareAction::EmergencyOverride => "healthcare/emergency_override",
        }
        .into()
    }
}

#[derive(Clone, PartialEq)]
pub struct HealhtCareScope {
    origin: String,
    path: String,
}

impl Scope for HealhtCareScope {
    fn contains(&self, other: &Self) -> bool {
        if self.origin != other.origin {
            return false;
        }

        let self_path_parts = self.path.split('/');
        let mut other_path_parts = other.path.split('/');

        for part in self_path_parts {
            match other_path_parts.nth(0) {
                Some(other_part) => {
                    if part != other_part {
                        return false;
                    }
                },
                None => return false,
            }
        }

        true
    }
}

impl TryFrom<Url> for HealhtCareScope {
    type Error = anyhow::Error;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        match (value.scheme(), value.host_str(), value.path()) {
            ("wnfs", Some(host), path) => Ok(HealhtCareScope {
                origin: String::from(host),
                path: String::from(path),
            }),
            _ => Err(anyhow!("Cannot interpret URI as WNFS scope: {}", value)),
        }
    }
}

impl ToString for HealhtCareScope {
    fn to_string(&self) -> String {
        format!("wnfs://{}{}", self.origin, self.path)
    }
}

pub struct HealhtCareSemantics {}

impl CapabilitySemantics<HealhtCareScope, HealthCareAction> for HealhtCareSemantics {}
