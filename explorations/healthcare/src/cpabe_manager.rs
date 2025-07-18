///! CPABE Implementation using Colossus
use crate::types::{MedicalRecord, ProviderAttributes, SystemError, SystemResult};
//use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use colossus_core::policy::{AccessPolicy, AccessStructure, Attribute};

use anyhow::Result;
use cosmian_cover_crypt::{
    CoverCrypt,
    interfaces::statics::{CoverCryptX25519Aes256, EncryptedHeader},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub struct CPABEManager {
    cover_crypt: CoverCryptX25519Aes256,
    policy: Policy,
    master_secret_key: Vec<u8>,
    master_public_key: Vec<u8>,
}

impl CPABEManager {
    /// Initialize CP-ABE manager with healthcare-specific policy
    pub fn new() -> SystemResult<Self> {
        // Define healthcare-specific attribute axes
        let security_level = PolicyAxis::new(
            "Security_Level",
            &["Public", "Sensitive", "Highly_Sensitive"],
            true, // Hierarchical - higher levels can access lower levels
        );

        let role_axis = PolicyAxis::new(
            "Role",
            &["Patient", "Nurse", "Doctor", "Specialist", "Pharmacist", "Admin"],
            false, // Not hierarchical - specific roles only
        );

        let department_axis = PolicyAxis::new(
            "Department",
            &["Emergency", "Cardiology", "Radiology", "Pharmacy", "Lab", "Surgery"],
            false,
        );

        let hospital_axis = PolicyAxis::new(
            "Hospital",
            &["General_Hospital", "Childrens_Hospital", "Heart_Center", "Cancer_Center"],
            false,
        );

        let clearance_axis = PolicyAxis::new(
            "Clearance",
            &["Basic", "Standard", "Advanced", "Critical"],
            true, // Hierarchical clearance levels
        );

        // Create policy with 100 revocations allowed
        let mut policy = Policy::new(100);
        policy.add_axis(&security_level).map_err(|e| {
            SystemError::SystemError(format!("Failed to add security level axis: {}", e))
        })?;
        policy
            .add_axis(&role_axis)
            .map_err(|e| SystemError::SystemError(format!("Failed to add role axis: {}", e)))?;
        policy.add_axis(&department_axis).map_err(|e| {
            SystemError::SystemError(format!("Failed to add department axis: {}", e))
        })?;
        policy
            .add_axis(&hospital_axis)
            .map_err(|e| SystemError::SystemError(format!("Failed to add hospital axis: {}", e)))?;
        policy.add_axis(&clearance_axis).map_err(|e| {
            SystemError::SystemError(format!("Failed to add clearance axis: {}", e))
        })?;

        // Initialize CoverCrypt
        let cover_crypt = CoverCryptX25519Aes256::default();

        // Generate master keys
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy).map_err(|e| {
            SystemError::SystemError(format!("Failed to generate master keys: {}", e))
        })?;

        Ok(CPABEManager {
            cover_crypt,
            policy,
            master_secret_key: msk,
            master_public_key: mpk,
        })
    }

    /// Encrypt medical record with specified access policy
    pub fn encrypt_medical_record(
        &self,
        data: &[u8],
        access_policy: &str,
    ) -> SystemResult<Vec<u8>> {
        // Parse access policy
        let access_policy = AccessPolicy::from_boolean_expression(access_policy)
            .map_err(|e| SystemError::EncryptionFailed(format!("Invalid access policy: {}", e)))?;

        // Generate encrypted header
        let (_, encrypted_header) = EncryptedHeader::generate(
            &self.cover_crypt,
            &self.policy,
            &self.master_public_key,
            &access_policy.attributes(),
            Some(data),
            None,
        )
        .map_err(|e| SystemError::EncryptionFailed(format!("Encryption failed: {}", e)))?;

        // Serialize encrypted header
        let encrypted_data = encrypted_header
            .serialize()
            .map_err(|e| SystemError::EncryptionFailed(format!("Serialization failed: {}", e)))?;

        Ok(encrypted_data)
    }

    /// Generate user secret key based on provider attributes
    pub fn generate_user_key(&self, attributes: &ProviderAttributes) -> SystemResult<Vec<u8>> {
        // Create access policy from provider attributes
        let access_policy_str = format!(
            "Role::{} && Department::{} && Clearance::{} && Hospital::{}",
            attributes.role, attributes.department, attributes.clearance_level, attributes.hospital
        );

        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| SystemError::SystemError(format!("Invalid attributes: {}", e)))?;

        // Generate user secret key
        let user_key = self
            .cover_crypt
            .generate_user_secret_key(&self.master_secret_key, &access_policy, &self.policy)
            .map_err(|e| SystemError::SystemError(format!("Key generation failed: {}", e)))?;

        // Serialize user key
        let key_bytes = user_key
            .serialize()
            .map_err(|e| SystemError::SystemError(format!("Key serialization failed: {}", e)))?;

        Ok(key_bytes)
    }

    /// Decrypt medical record using user secret key
    pub fn decrypt_medical_record(
        &self,
        encrypted_data: &[u8],
        user_key: &[u8],
    ) -> SystemResult<Vec<u8>> {
        // Deserialize encrypted header
        let encrypted_header = EncryptedHeader::deserialize(encrypted_data)
            .map_err(|e| SystemError::DecryptionFailed(format!("Deserialization failed: {}", e)))?;

        // Deserialize user key
        let user_secret_key =
            self.cover_crypt.deserialize_user_secret_key(user_key).map_err(|e| {
                SystemError::DecryptionFailed(format!("Key deserialization failed: {}", e))
            })?;

        // Decrypt
        let decrypted_data = encrypted_header
            .decrypt(&self.cover_crypt, &user_secret_key, None)
            .map_err(|e| SystemError::DecryptionFailed(format!("Decryption failed: {}", e)))?;

        Ok(decrypted_data)
    }

    /// Revoke attribute (for user revocation)
    pub fn revoke_attribute(&mut self, attribute_name: &str) -> SystemResult<()> {
        let attribute = Attribute::from_str(attribute_name)
            .map_err(|e| SystemError::SystemError(format!("Invalid attribute: {}", e)))?;

        self.policy
            .rotate(&attribute)
            .map_err(|e| SystemError::SystemError(format!("Attribute rotation failed: {}", e)))?;

        // Update master keys
        self.cover_crypt
            .update_master_keys(
                &self.policy,
                &mut self.master_secret_key,
                &mut self.master_public_key,
            )
            .map_err(|e| SystemError::SystemError(format!("Master key update failed: {}", e)))?;

        Ok(())
    }

    /// Refresh user secret key after attribute revocation
    pub fn refresh_user_key(
        &self,
        old_user_key: &[u8],
        attributes: &ProviderAttributes,
        grant_old_access: bool,
    ) -> SystemResult<Vec<u8>> {
        // Deserialize old user key
        let mut user_secret_key = self
            .cover_crypt
            .deserialize_user_secret_key(old_user_key)
            .map_err(|e| SystemError::SystemError(format!("Key deserialization failed: {}", e)))?;

        // Create access policy from attributes
        let access_policy_str = format!(
            "Role::{} && Department::{} && Clearance::{} && Hospital::{}",
            attributes.role, attributes.department, attributes.clearance_level, attributes.hospital
        );

        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| SystemError::SystemError(format!("Invalid attributes: {}", e)))?;

        // Refresh user key
        self.cover_crypt
            .refresh_user_secret_key(
                &mut user_secret_key,
                &access_policy,
                &self.master_secret_key,
                &self.policy,
                grant_old_access,
            )
            .map_err(|e| SystemError::SystemError(format!("Key refresh failed: {}", e)))?;

        // Serialize refreshed key
        let key_bytes = user_secret_key
            .serialize()
            .map_err(|e| SystemError::SystemError(format!("Key serialization failed: {}", e)))?;

        Ok(key_bytes)
    }

    /// Get policy information
    pub fn get_policy_info(&self) -> HashMap<String, Vec<String>> {
        let mut policy_info = HashMap::new();

        // This is a simplified version - in real implementation,
        // you'd iterate over policy axes
        policy_info.insert(
            "Security_Level".to_string(),
            vec!["Public".to_string(), "Sensitive".to_string(), "Highly_Sensitive".to_string()],
        );
        policy_info.insert(
            "Role".to_string(),
            vec![
                "Patient".to_string(),
                "Nurse".to_string(),
                "Doctor".to_string(),
                "Specialist".to_string(),
                "Pharmacist".to_string(),
                "Admin".to_string(),
            ],
        );
        policy_info.insert(
            "Department".to_string(),
            vec![
                "Emergency".to_string(),
                "Cardiology".to_string(),
                "Radiology".to_string(),
                "Pharmacy".to_string(),
                "Lab".to_string(),
                "Surgery".to_string(),
            ],
        );
        policy_info.insert(
            "Hospital".to_string(),
            vec![
                "General_Hospital".to_string(),
                "Childrens_Hospital".to_string(),
                "Heart_Center".to_string(),
                "Cancer_Center".to_string(),
            ],
        );
        policy_info.insert(
            "Clearance".to_string(),
            vec![
                "Basic".to_string(),
                "Standard".to_string(),
                "Advanced".to_string(),
                "Critical".to_string(),
            ],
        );

        policy_info
    }
}

// Helper function to create common healthcare access policies
pub fn create_healthcare_policy(
    role: &str,
    department: &str,
    clearance: &str,
    hospital: &str,
) -> String {
    format!(
        "Role::{} && Department::{} && Clearance::{} && Hospital::{}",
        role, department, clearance, hospital
    )
}

// Example access policies for different scenarios
pub fn emergency_access_policy() -> String {
    "Role::Doctor && Department::Emergency && Clearance::Advanced".to_string()
}

pub fn cardiology_sensitive_policy() -> String {
    "Role::Doctor && Department::Cardiology && Security_Level::Sensitive".to_string()
}

pub fn pharmacy_prescription_policy() -> String {
    "Role::Pharmacist && Department::Pharmacy && Clearance::Standard".to_string()
}

pub fn multi_department_policy() -> String {
    "(Role::Doctor || Role::Nurse) && (Department::Emergency || Department::Cardiology) && Clearance::Advanced".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpabe_manager_creation() {
        let manager = CPABEManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_policy_creation() {
        let policy = create_healthcare_policy("Doctor", "Cardiology", "Advanced", "Heart_Center");
        assert_eq!(
            policy,
            "Role::Doctor && Department::Cardiology && Clearance::Advanced && Hospital::Heart_Center"
        );
    }

    #[test]
    fn test_emergency_policy() {
        let policy = emergency_access_policy();
        assert!(policy.contains("Emergency"));
        assert!(policy.contains("Doctor"));
    }
}
