///! Implementation for Capability-Based Authorization using UCAN
use crate::types::{Capability, HealthcareProvider, SystemError, SystemResult, UCANToken};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ucan::{
    builder::UcanBuilder,
    capability::{Ability, CapabilitySemantics, Scope},
    chain::ProofChain,
    crypto::KeyMaterial,
};
use uuid::Uuid;

// Healthcare-specific capability semantics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthcareCapability {
    pub resource: String,
    pub action: String,
    pub constraints: HashMap<String, String>,
}

impl Scope for HealthcareCapability {
    fn contains(&self, other: &Self) -> bool {
        self.resource == other.resource && self.action == other.action
    }
}

impl Ability for HealthcareCapability {
    fn can(&self, _action: &Self) -> bool {
        true // Simplified for demo
    }
}

// UCAN Manager for healthcare capabilities
pub struct UCANManager {
    key_material: Box<dyn KeyMaterial>,
    did: String,
}

impl UCANManager {
    pub fn new(key_material: Box<dyn KeyMaterial>, did: String) -> Self {
        UCANManager { key_material, did }
    }

    /// Create a UCAN token for healthcare provider
    pub async fn create_healthcare_ucan(
        &self,
        audience_did: &str,
        capabilities: Vec<HealthcareCapability>,
        expiration_hours: i64,
    ) -> SystemResult<String> {
        let mut builder = UcanBuilder::default();

        // Set issuer and audience
        builder = builder.issued_by(&*self.key_material).for_audience(audience_did);

        // Set expiration
        let expiration = Utc::now() + Duration::hours(expiration_hours);
        builder = builder.with_expiration(expiration.timestamp() as u64);

        // Add capabilities
        for cap in capabilities {
            builder = builder.with_capability(cap.resource, cap.action);
        }

        // Build and sign UCAN
        let ucan = builder
            .build()
            .map_err(|e| SystemError::SystemError(format!("UCAN build failed: {}", e)))?;

        let token = ucan
            .sign()
            .await
            .map_err(|e| SystemError::SystemError(format!("UCAN signing failed: {}", e)))?;

        Ok(token.encode())
    }

    /// Create patient consent UCAN
    pub async fn create_patient_consent_ucan(
        &self,
        provider_did: &str,
        patient_id: &str,
        allowed_actions: Vec<String>,
        expiration_hours: i64,
    ) -> SystemResult<String> {
        let mut capabilities = Vec::new();

        for action in allowed_actions {
            capabilities.push(HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action,
                constraints: HashMap::new(),
            });
        }

        self.create_healthcare_ucan(provider_did, capabilities, expiration_hours).await
    }

    /// Create emergency access UCAN
    pub async fn create_emergency_access_ucan(
        &self,
        provider_did: &str,
        patient_id: &str,
        emergency_level: &str,
    ) -> SystemResult<String> {
        let mut constraints = HashMap::new();
        constraints.insert("emergency_level".to_string(), emergency_level.to_string());
        constraints.insert("duration".to_string(), "24h".to_string());

        let capabilities = vec![
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "read".to_string(),
                constraints: constraints.clone(),
            },
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "write".to_string(),
                constraints,
            },
        ];

        self.create_healthcare_ucan(provider_did, capabilities, 24).await
    }

    /// Create delegation UCAN (doctor delegating to nurse)
    pub async fn create_delegation_ucan(
        &self,
        delegate_did: &str,
        original_capabilities: Vec<HealthcareCapability>,
        restrictions: HashMap<String, String>,
    ) -> SystemResult<String> {
        let mut restricted_capabilities = Vec::new();

        for mut cap in original_capabilities {
            // Apply restrictions
            for (key, value) in &restrictions {
                cap.constraints.insert(key.clone(), value.clone());
            }
            restricted_capabilities.push(cap);
        }

        self.create_healthcare_ucan(delegate_did, restricted_capabilities, 8).await
    }

    /// Validate UCAN token
    pub async fn validate_ucan(&self, token: &str) -> SystemResult<bool> {
        // This is a simplified validation - in real implementation,
        // you'd use ProofChain for full validation
        match self.decode_ucan(token) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Decode UCAN token
    pub fn decode_ucan(&self, token: &str) -> SystemResult<UCANToken> {
        // Simplified decoding - in real implementation, use proper UCAN parsing
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(SystemError::InvalidUCANToken("Invalid token format".to_string()));
        }

        // For demo purposes, return a mock UCANToken
        // In real implementation, parse the JWT payload
        Ok(UCANToken {
            token: token.to_string(),
            issuer: self.did.clone(),
            audience: "did:example:audience".to_string(),
            capabilities: vec![],
            expiration: Utc::now() + Duration::hours(24),
            proof_chain: vec![],
        })
    }

    /// Check if UCAN authorizes specific action
    pub fn authorize_action(
        &self,
        token: &UCANToken,
        resource: &str,
        action: &str,
    ) -> SystemResult<bool> {
        // Check expiration
        if token.expiration < Utc::now() {
            return Ok(false);
        }

        // Check capabilities
        for capability in &token.capabilities {
            if capability.resource == resource && capability.action == action {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Create research access UCAN (anonymized data)
    pub async fn create_research_access_ucan(
        &self,
        researcher_did: &str,
        research_project: &str,
        data_types: Vec<String>,
    ) -> SystemResult<String> {
        let mut capabilities = Vec::new();

        for data_type in data_types {
            let mut constraints = HashMap::new();
            constraints.insert("anonymized".to_string(), "true".to_string());
            constraints.insert("project".to_string(), research_project.to_string());

            capabilities.push(HealthcareCapability {
                resource: format!("research_data:{}", data_type),
                action: "read".to_string(),
                constraints,
            });
        }

        self.create_healthcare_ucan(researcher_did, capabilities, 24 * 30) // 30 days
            .await
    }

    /// Create audit access UCAN
    pub async fn create_audit_access_ucan(
        &self,
        auditor_did: &str,
        audit_scope: &str,
    ) -> SystemResult<String> {
        let mut constraints = HashMap::new();
        constraints.insert("audit_scope".to_string(), audit_scope.to_string());
        constraints.insert("read_only".to_string(), "true".to_string());

        let capabilities = vec![
            HealthcareCapability {
                resource: "audit_log:*".to_string(),
                action: "read".to_string(),
                constraints: constraints.clone(),
            },
            HealthcareCapability {
                resource: "access_log:*".to_string(),
                action: "read".to_string(),
                constraints,
            },
        ];

        self.create_healthcare_ucan(auditor_did, capabilities, 24 * 7) // 7 days
            .await
    }
}

// Helper functions for common healthcare UCAN patterns
pub fn create_patient_read_capability(patient_id: &str) -> HealthcareCapability {
    HealthcareCapability {
        resource: format!("medical_record:patient:{}", patient_id),
        action: "read".to_string(),
        constraints: HashMap::new(),
    }
}

pub fn create_patient_write_capability(patient_id: &str) -> HealthcareCapability {
    HealthcareCapability {
        resource: format!("medical_record:patient:{}", patient_id),
        action: "write".to_string(),
        constraints: HashMap::new(),
    }
}

pub fn create_prescription_capability(patient_id: &str) -> HealthcareCapability {
    let mut constraints = HashMap::new();
    constraints.insert("type".to_string(), "prescription".to_string());

    HealthcareCapability {
        resource: format!("medical_record:patient:{}", patient_id),
        action: "prescribe".to_string(),
        constraints,
    }
}

pub fn create_lab_result_capability(patient_id: &str) -> HealthcareCapability {
    let mut constraints = HashMap::new();
    constraints.insert("type".to_string(), "lab_result".to_string());

    HealthcareCapability {
        resource: format!("medical_record:patient:{}", patient_id),
        action: "update".to_string(),
        constraints,
    }
}

// UCAN delegation patterns for healthcare
pub struct HealthcareUCANPatterns;

impl HealthcareUCANPatterns {
    /// Doctor delegates read access to nurse for specific patient
    pub fn doctor_to_nurse_delegation(
        patient_id: &str,
        shift_end: DateTime<Utc>,
    ) -> Vec<HealthcareCapability> {
        let mut constraints = HashMap::new();
        constraints.insert("delegated_by".to_string(), "doctor".to_string());
        constraints.insert("valid_until".to_string(), shift_end.to_rfc3339());

        vec![
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "read".to_string(),
                constraints: constraints.clone(),
            },
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "update_vitals".to_string(),
                constraints,
            },
        ]
    }

    /// Specialist consultation delegation
    pub fn specialist_consultation_delegation(
        patient_id: &str,
        consultation_type: &str,
    ) -> Vec<HealthcareCapability> {
        let mut constraints = HashMap::new();
        constraints.insert("consultation_type".to_string(), consultation_type.to_string());
        constraints.insert("scope".to_string(), "consultation_only".to_string());

        vec![
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "read".to_string(),
                constraints: constraints.clone(),
            },
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "add_consultation".to_string(),
                constraints,
            },
        ]
    }

    /// Emergency team access
    pub fn emergency_team_access(patient_id: &str) -> Vec<HealthcareCapability> {
        let mut constraints = HashMap::new();
        constraints.insert("emergency".to_string(), "true".to_string());
        constraints.insert("duration".to_string(), "24h".to_string());

        vec![
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "read".to_string(),
                constraints: constraints.clone(),
            },
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "write".to_string(),
                constraints: constraints.clone(),
            },
            HealthcareCapability {
                resource: format!("medical_record:patient:{}", patient_id),
                action: "emergency_override".to_string(),
                constraints,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthcare_capability_creation() {
        let cap = create_patient_read_capability("patient123");
        assert_eq!(cap.resource, "medical_record:patient:patient123");
        assert_eq!(cap.action, "read");
    }

    #[test]
    fn test_emergency_team_access() {
        let capabilities = HealthcareUCANPatterns::emergency_team_access("patient456");
        assert_eq!(capabilities.len(), 3);
        assert!(capabilities.iter().any(|c| c.action == "emergency_override"));
    }

    #[test]
    fn test_delegation_patterns() {
        let delegation = HealthcareUCANPatterns::doctor_to_nurse_delegation(
            "patient789",
            Utc::now() + Duration::hours(8),
        );
        assert_eq!(delegation.len(), 2);
        assert!(delegation.iter().any(|c| c.action == "read"));
        assert!(delegation.iter().any(|c| c.action == "update_vitals"));
    }
}
