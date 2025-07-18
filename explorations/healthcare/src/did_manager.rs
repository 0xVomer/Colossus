///! DID Implementation using IOTA Identity
use crate::types::{HealthcareInstitution, HealthcareProvider, Patient, SystemError, SystemResult};
use anyhow::Result;
use chrono::{DateTime, Utc};
use identity_iota::{
    core::ToJson,
    iota::{IotaDocument, IotaIdentityClientExt, NetworkName},
    storage::{JwkDocumentExt, JwkMemStore, KeyIdMemstore, Storage},
    verification::{MethodScope, jws::JwsAlgorithm},
};
use iota_sdk::{
    client::{Client, api::GetAddressesOptions, secret::SecretManager},
    crypto::keys::bip39,
    types::block::address::Bech32Address,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// DID Document with healthcare-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcareDIDDocument {
    pub did: String,
    pub document: IotaDocument,
    pub entity_type: String, // "patient", "provider", "institution"
    pub metadata: DIDMetadata,
    pub verification_methods: Vec<VerificationMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
    pub license_info: Option<LicenseInfo>,
    pub institution_affiliation: Option<String>,
    pub specializations: Vec<String>,
    pub certifications: Vec<Certification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub license_number: String,
    pub license_type: String,
    pub issuing_authority: String,
    pub expiration_date: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certification {
    pub name: String,
    pub issuer: String,
    pub issued_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub credential_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: String,
    pub controller: String,
    pub public_key: Vec<u8>,
    pub purpose: Vec<String>,
}

/// DID Manager for healthcare entities
pub struct DIDManager {
    client: Client,
    storage: Storage<JwkMemStore, KeyIdMemstore>,
    network_name: NetworkName,
}

impl DIDManager {
    pub async fn new(node_url: &str) -> SystemResult<Self> {
        let client = Client::builder()
            .with_primary_node(node_url, None)
            .map_err(|e| SystemError::DIDOperationFailed(format!("Client creation failed: {}", e)))?
            .finish()
            .await
            .map_err(|e| SystemError::DIDOperationFailed(format!("Client finish failed: {}", e)))?;

        let storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
        let network_name = client.network_name().await.map_err(|e| {
            SystemError::DIDOperationFailed(format!("Network name retrieval failed: {}", e))
        })?;

        Ok(DIDManager { client, storage, network_name })
    }

    /// Create DID for patient
    pub async fn create_patient_did(
        &self,
        patient: &Patient,
    ) -> SystemResult<HealthcareDIDDocument> {
        let mut document = IotaDocument::new(&self.network_name);

        // Generate verification method
        document
            .generate_method(
                &self.storage,
                JwkMemStore::ED25519_KEY_TYPE,
                JwsAlgorithm::EdDSA,
                None,
                MethodScope::VerificationMethod,
            )
            .await
            .map_err(|e| {
                SystemError::DIDOperationFailed(format!("Method generation failed: {}", e))
            })?;

        // Create metadata
        let metadata = DIDMetadata {
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            license_info: None,
            institution_affiliation: None,
            specializations: vec![],
            certifications: vec![],
        };

        let healthcare_did = HealthcareDIDDocument {
            did: document.id().to_string(),
            document,
            entity_type: "patient".to_string(),
            metadata,
            verification_methods: vec![],
        };

        Ok(healthcare_did)
    }

    /// Create DID for healthcare provider
    pub async fn create_provider_did(
        &self,
        provider: &HealthcareProvider,
    ) -> SystemResult<HealthcareDIDDocument> {
        let mut document = IotaDocument::new(&self.network_name);

        // Generate verification method
        document
            .generate_method(
                &self.storage,
                JwkMemStore::ED25519_KEY_TYPE,
                JwsAlgorithm::EdDSA,
                None,
                MethodScope::VerificationMethod,
            )
            .await
            .map_err(|e| {
                SystemError::DIDOperationFailed(format!("Method generation failed: {}", e))
            })?;

        // Create license info
        let license_info = LicenseInfo {
            license_number: provider.license_number.clone(),
            license_type: provider.specialization.clone(),
            issuing_authority: "Medical Board".to_string(),
            expiration_date: Utc::now() + chrono::Duration::days(365),
            status: "active".to_string(),
        };

        // Create metadata
        let metadata = DIDMetadata {
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            license_info: Some(license_info),
            institution_affiliation: Some(provider.hospital_id.to_string()),
            specializations: vec![provider.specialization.clone()],
            certifications: vec![],
        };

        let healthcare_did = HealthcareDIDDocument {
            did: document.id().to_string(),
            document,
            entity_type: "provider".to_string(),
            metadata,
            verification_methods: vec![],
        };

        Ok(healthcare_did)
    }

    /// Create DID for healthcare institution
    pub async fn create_institution_did(
        &self,
        institution: &HealthcareInstitution,
    ) -> SystemResult<HealthcareDIDDocument> {
        let mut document = IotaDocument::new(&self.network_name);

        // Generate verification method
        document
            .generate_method(
                &self.storage,
                JwkMemStore::ED25519_KEY_TYPE,
                JwsAlgorithm::EdDSA,
                None,
                MethodScope::VerificationMethod,
            )
            .await
            .map_err(|e| {
                SystemError::DIDOperationFailed(format!("Method generation failed: {}", e))
            })?;

        // Create metadata
        let metadata = DIDMetadata {
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            license_info: None,
            institution_affiliation: None,
            specializations: vec![],
            certifications: vec![],
        };

        let healthcare_did = HealthcareDIDDocument {
            did: document.id().to_string(),
            document,
            entity_type: "institution".to_string(),
            metadata,
            verification_methods: vec![],
        };

        Ok(healthcare_did)
    }

    /// Resolve DID document
    pub async fn resolve_did(&self, did: &str) -> SystemResult<HealthcareDIDDocument> {
        // This is a simplified implementation
        // In real implementation, you'd resolve from the IOTA network
        Err(SystemError::DIDOperationFailed(
            "DID resolution not implemented in demo".to_string(),
        ))
    }

    /// Update DID document
    pub async fn update_did_document(
        &self,
        did_doc: &mut HealthcareDIDDocument,
        updates: DIDUpdateRequest,
    ) -> SystemResult<()> {
        // Update metadata
        did_doc.metadata.updated_at = Utc::now();
        did_doc.metadata.version += 1;

        // Apply updates
        if let Some(certifications) = updates.add_certifications {
            did_doc.metadata.certifications.extend(certifications);
        }

        if let Some(specializations) = updates.add_specializations {
            did_doc.metadata.specializations.extend(specializations);
        }

        Ok(())
    }

    /// Verify DID document authenticity
    pub async fn verify_did_document(&self, did_doc: &HealthcareDIDDocument) -> SystemResult<bool> {
        // Simplified verification - in real implementation,
        // you'd verify signatures and check the IOTA network
        Ok(true)
    }

    /// Create verifiable credential for healthcare provider
    pub async fn create_provider_credential(
        &self,
        provider_did: &str,
        issuer_did: &str,
        attributes: &HashMap<String, String>,
    ) -> SystemResult<VerifiableCredential> {
        let credential = VerifiableCredential {
            id: Uuid::new_v4(),
            issuer: issuer_did.to_string(),
            subject: provider_did.to_string(),
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            attributes: attributes.clone(),
            proof: vec![], // Simplified for demo
        };

        Ok(credential)
    }

    /// Verify verifiable credential
    pub async fn verify_credential(&self, credential: &VerifiableCredential) -> SystemResult<bool> {
        // Check expiration
        if let Some(expires_at) = credential.expires_at {
            if expires_at < Utc::now() {
                return Ok(false);
            }
        }

        // Verify issuer DID
        // In real implementation, resolve issuer DID and verify signature
        Ok(true)
    }

    /// Create emergency access credential
    pub async fn create_emergency_credential(
        &self,
        provider_did: &str,
        patient_did: &str,
        emergency_type: &str,
    ) -> SystemResult<VerifiableCredential> {
        let mut attributes = HashMap::new();
        attributes.insert("emergency_type".to_string(), emergency_type.to_string());
        attributes.insert("patient".to_string(), patient_did.to_string());
        attributes.insert("access_level".to_string(), "emergency".to_string());

        let credential = VerifiableCredential {
            id: Uuid::new_v4(),
            issuer: "did:iota:emergency_authority".to_string(),
            subject: provider_did.to_string(),
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            attributes,
            proof: vec![],
        };

        Ok(credential)
    }

    /// Revoke DID document
    pub async fn revoke_did(&self, did: &str, reason: &str) -> SystemResult<()> {
        // In real implementation, you'd publish a revocation to the IOTA network
        log::info!("DID {} revoked. Reason: {}", did, reason);
        Ok(())
    }
}

/// Request structure for DID updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDUpdateRequest {
    pub add_certifications: Option<Vec<Certification>>,
    pub add_specializations: Option<Vec<String>>,
    pub update_license: Option<LicenseInfo>,
}

/// Verifiable Credential structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    pub id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub attributes: HashMap<String, String>,
    pub proof: Vec<String>, // Simplified proof structure
}

/// DID Registry for healthcare entities
pub struct HealthcareDIDRegistry {
    dids: HashMap<String, HealthcareDIDDocument>,
    credentials: HashMap<Uuid, VerifiableCredential>,
}

impl HealthcareDIDRegistry {
    pub fn new() -> Self {
        HealthcareDIDRegistry {
            dids: HashMap::new(),
            credentials: HashMap::new(),
        }
    }

    pub fn register_did(&mut self, did_doc: HealthcareDIDDocument) {
        self.dids.insert(did_doc.did.clone(), did_doc);
    }

    pub fn get_did(&self, did: &str) -> Option<&HealthcareDIDDocument> {
        self.dids.get(did)
    }

    pub fn store_credential(&mut self, credential: VerifiableCredential) {
        self.credentials.insert(credential.id, credential);
    }

    pub fn get_credential(&self, id: &Uuid) -> Option<&VerifiableCredential> {
        self.credentials.get(id)
    }

    pub fn get_credentials_for_subject(&self, subject_did: &str) -> Vec<&VerifiableCredential> {
        self.credentials.values().filter(|c| c.subject == subject_did).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthcare_did_registry() {
        let mut registry = HealthcareDIDRegistry::new();

        let did_doc = HealthcareDIDDocument {
            did: "did:iota:test123".to_string(),
            document: IotaDocument::new(&NetworkName::try_from("test").unwrap()),
            entity_type: "patient".to_string(),
            metadata: DIDMetadata {
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
                license_info: None,
                institution_affiliation: None,
                specializations: vec![],
                certifications: vec![],
            },
            verification_methods: vec![],
        };

        registry.register_did(did_doc);
        assert!(registry.get_did("did:iota:test123").is_some());
    }

    #[test]
    fn test_verifiable_credential_creation() {
        let mut attributes = HashMap::new();
        attributes.insert("role".to_string(), "doctor".to_string());
        attributes.insert("specialization".to_string(), "cardiology".to_string());

        let credential = VerifiableCredential {
            id: Uuid::new_v4(),
            issuer: "did:iota:medical_board".to_string(),
            subject: "did:iota:doctor123".to_string(),
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            attributes,
            proof: vec![],
        };

        assert_eq!(credential.issuer, "did:iota:medical_board");
        assert_eq!(credential.subject, "did:iota:doctor123");
    }
}
