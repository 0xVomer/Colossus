//! DID Identity Manager for decentralized identity verification
mod identity;
mod manager;
use did_key::{Config, DIDCore, Ed25519KeyPair, generate, resolve};
pub use identity::Identity;
pub use manager::DidManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_did_manager_creation() {
        let manager = DidManager::new();
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_identity_creation() {
        let mut manager = DidManager::new().unwrap();
        let user_id = Uuid::new_v4();

        let identity = manager.create_identity(user_id);
        assert!(identity.is_ok());

        let identity = identity.unwrap();
        assert_eq!(identity.id, user_id);
        assert!(!identity.did.is_empty());
        assert!(identity.verified);
    }

    #[tokio::test]
    async fn test_credential_issuance() {
        let mut manager = DidManager::new().unwrap();
        let user_id = Uuid::new_v4();

        manager.create_identity(user_id).unwrap();

        let mut claims = HashMap::new();
        claims.insert("license_type".to_string(), "institutional".to_string());

        let credential = manager.issue_credential(user_id, CredentialType::TradingLicense, claims);

        assert!(credential.is_ok());

        let credential = credential.unwrap();
        assert_eq!(credential.credential_type, CredentialType::TradingLicense);
    }

    #[tokio::test]
    async fn test_identity_verification() {
        let mut manager = DidManager::new().unwrap();
        let user_id = Uuid::new_v4();

        let did_identity = manager.create_identity(user_id).unwrap();

        let identity = Identity {
            id: user_id,
            did: did_identity.did,
            public_key: did_identity.public_key,
            attributes: HashMap::new(),
            created_at: chrono::Utc::now(),
        };

        let verified = manager.verify_identity(&identity).await;
        assert!(verified.is_ok());
        assert!(verified.unwrap());
    }

    #[tokio::test]
    async fn test_institutional_credentials() {
        let mut manager = DidManager::new().unwrap();
        let user_id = Uuid::new_v4();

        manager.create_identity(user_id).unwrap();

        let credentials = manager.create_institutional_credentials(user_id);
        assert!(credentials.is_ok());

        let credentials = credentials.unwrap();
        assert_eq!(credentials.len(), 3);
        assert!(
            credentials
                .iter()
                .any(|c| matches!(c.credential_type, CredentialType::TradingLicense))
        );
        assert!(
            credentials
                .iter()
                .any(|c| matches!(c.credential_type, CredentialType::InstitutionalAccreditation))
        );
        assert!(
            credentials
                .iter()
                .any(|c| matches!(c.credential_type, CredentialType::ComplianceAttestation))
        );
    }
}
