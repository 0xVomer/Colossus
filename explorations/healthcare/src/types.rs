use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// =============================================================================
// SYSTEM ACTORS DEFINITIONS
// =============================================================================

/// Patient - End user who owns their health data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patient {
    pub id: Uuid,
    pub did: String, // DID identifier
    pub name: String,
    pub medical_record_number: String,
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// Healthcare Provider - Doctors, nurses, specialists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcareProvider {
    pub id: Uuid,
    pub did: String, // DID identifier
    pub name: String,
    pub license_number: String,
    pub specialization: String,
    pub hospital_id: Uuid,
    pub attributes: ProviderAttributes,
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// Healthcare Provider Attributes for CP-ABE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderAttributes {
    pub role: String,                // "Doctor", "Nurse", "Specialist", "Pharmacist"
    pub department: String,          // "Cardiology", "Emergency", "Radiology", etc.
    pub clearance_level: String,     // "Basic", "Sensitive", "Highly_Sensitive"
    pub hospital: String,            // Hospital identifier
    pub certifications: Vec<String>, // Additional certifications
}

/// Hospital/Healthcare Institution - Manages infrastructure and policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcareInstitution {
    pub id: Uuid,
    pub did: String, // DID identifier
    pub name: String,
    pub type_: String, // "Hospital", "Clinic", "Lab", "Pharmacy"
    pub location: String,
    pub public_key: Vec<u8>,
    pub policy_authority: bool, // Can create/modify access policies
    pub created_at: DateTime<Utc>,
}

/// Attribute Authority - Manages CP-ABE attributes and policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeAuthority {
    pub id: Uuid,
    pub did: String, // DID identifier
    pub name: String,
    pub domain: String, // "regional", "national", "international"
    pub master_public_key: Vec<u8>,
    pub master_secret_key: Vec<u8>, // Securely stored
    pub managed_attributes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// DID Registry - Manages decentralized identifiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDRegistry {
    pub id: Uuid,
    pub name: String,
    pub network: String, // "IOTA", "Ethereum", "Hyperledger"
    pub endpoint: String,
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

// =============================================================================
// SYSTEM COMPONENTS
// =============================================================================

/// Medical Record with CP-ABE encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MedicalRecord {
    pub id: Uuid,
    pub patient_id: Uuid,
    pub record_type: String, // "Diagnosis", "Lab_Result", "Prescription", etc.
    pub encrypted_data: Vec<u8>, // CP-ABE encrypted data
    pub access_policy: String, // Boolean expression of attributes
    pub created_by: Uuid,    // Healthcare provider ID
    pub created_at: DateTime<Utc>,
    pub metadata: RecordMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordMetadata {
    pub sensitivity_level: String, // "Public", "Sensitive", "Highly_Sensitive"
    pub retention_period: i64,     // Days
    pub audit_trail: Vec<AccessLog>,
}

/// UCAN Token for capability-based authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UCANToken {
    pub token: String,    // JWT-encoded UCAN
    pub issuer: String,   // DID of issuer
    pub audience: String, // DID of audience
    pub capabilities: Vec<Capability>,
    pub expiration: DateTime<Utc>,
    pub proof_chain: Vec<String>, // Chain of delegation proofs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub resource: String, // "medical_record", "patient_data", etc.
    pub action: String,   // "read", "write", "delete", "share"
    pub constraints: HashMap<String, String>, // Additional constraints
}

/// Access Log for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLog {
    pub timestamp: DateTime<Utc>,
    pub actor_did: String,
    pub action: String,
    pub resource_id: Uuid,
    pub success: bool,
    pub ip_address: String,
    pub user_agent: String,
    pub zero_trust_score: f64, // Trust score at access time
}

/// Zero Trust Policy Decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustDecision {
    pub decision: String, // "Allow", "Deny", "Challenge"
    pub confidence: f64,  // 0.0 to 1.0
    pub factors: Vec<TrustFactor>,
    pub required_actions: Vec<String>, // Additional verification steps
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    pub factor_type: String, // "Location", "Device", "Behavior", "Time"
    pub value: String,
    pub weight: f64,
    pub score: f64,
}

// =============================================================================
// SYSTEM ERRORS
// =============================================================================

#[derive(Debug, thiserror::Error)]
pub enum SystemError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("CP-ABE encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("CP-ABE decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("DID operation failed: {0}")]
    DIDOperationFailed(String),

    #[error("UCAN token invalid: {0}")]
    InvalidUCANToken(String),

    #[error("Zero Trust policy violation: {0}")]
    PolicyViolation(String),

    #[error("System error: {0}")]
    SystemError(String),
}

pub type SystemResult<T> = Result<T, SystemError>;
