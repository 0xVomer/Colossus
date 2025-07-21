///! CPABE Implementation using Colossus
use crate::policies::{
    Clearance, Department, HealthcareAccess, Hospital, Role, SecurityLevel, provider_access_policy,
};
use crate::types::{ProviderAttributes, SystemError, SystemResult};
use colossus_core::access_control::{
    EncryptedHeader, Root, RootAuthority, RootPublicKey, UserSecretKey,
};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use zeroize::Zeroizing;

pub struct RootAccessControl {
    api: Root,
    auth: RootAuthority,
    rpk: RootPublicKey,
}

impl RootAccessControl {
    pub fn new() -> SystemResult<Self> {
        let api = Root::default();
        let (mut auth, _) = api.setup().unwrap();

        Department::add_to_access_structure(&mut auth.access_structure);
        Hospital::add_to_access_structure(&mut auth.access_structure);
        Role::add_to_access_structure(&mut auth.access_structure);
        SecurityLevel::add_to_access_structure(&mut auth.access_structure);
        Clearance::add_to_access_structure(&mut auth.access_structure);

        let rpk = api.update_auth(&mut auth).unwrap();

        Ok(Self { api, auth, rpk })
    }

    pub fn seal(
        &self,
        access_control: &HealthcareAccess,
        aad: &[u8],
        data: &[u8],
    ) -> SystemResult<Zeroizing<Vec<u8>>> {
        let (_, encrypted_header) = EncryptedHeader::generate(
            &self.api,
            &self.rpk,
            &access_control.create_policy(),
            Some(data),
            Some(aad),
        )
        .map_err(|e| SystemError::EncryptionFailed(format!("Encryption failed: {}", e)))?;

        let encrypted_data = encrypted_header
            .serialize()
            .map_err(|e| SystemError::EncryptionFailed(format!("Serialization failed: {}", e)))?;

        Ok(encrypted_data)
    }

    pub fn unseal(
        &self,
        access_keys: &[u8],
        aad: &[u8],
        encrypted_data: &[u8],
    ) -> SystemResult<Vec<u8>> {
        let encrypted_header = EncryptedHeader::deserialize(encrypted_data)
            .map_err(|e| SystemError::DecryptionFailed(format!("Deserialization failed: {}", e)))?;

        let access_rights = UserSecretKey::deserialize(access_keys)
            .map_err(|e| SystemError::DecryptionFailed(format!("Deserialization failed: {}", e)))?;

        let decrypted_data = encrypted_header
            .decrypt(&self.api, &access_rights, Some(aad))
            .map_err(|e| SystemError::DecryptionFailed(format!("Decryption failed: {}", e)))?;

        let data = decrypted_data.unwrap().metadata;

        Ok(data.unwrap())
    }

    pub fn create_access_keys(
        &mut self,
        attributes: &ProviderAttributes,
    ) -> SystemResult<Zeroizing<Vec<u8>>> {
        let ap = provider_access_policy(attributes);
        let access_keys = self
            .api
            .generate_user_secret_key(&mut self.auth, &ap)
            .map_err(|e| SystemError::DecryptionFailed(format!("Key generation failed: {}", e)))?;
        let access_keys_serialized = access_keys
            .serialize()
            .map_err(|e| SystemError::DecryptionFailed(format!("Serialization failed: {}", e)))?;
        Ok(access_keys_serialized)
    }

    /// For Access Revocation
    /// we simply generate new access right keys for the given attributes
    /// this means future sealed data cannot be unsealaed by  access keys that has not yet been refreshed
    pub fn revoke(&mut self, attributes: &ProviderAttributes) -> SystemResult<()> {
        let ap = provider_access_policy(attributes);
        self.rpk = self
            .api
            .rekey(&mut self.auth, &ap)
            .map_err(|e| SystemError::DecryptionFailed(format!("Rekeying failed: {}", e)))?;
        Ok(())
    }

    /// Refresh user secret key after attribute revocation
    pub fn refresh_access_keys(
        &mut self,
        serialized_access_keys: &[u8],
        attributes: &ProviderAttributes,
        grant_old_access: bool,
    ) -> SystemResult<Zeroizing<Vec<u8>>> {
        self.revoke(attributes)?;
        let mut access_keys = UserSecretKey::deserialize(serialized_access_keys)
            .map_err(|e| SystemError::DecryptionFailed(format!("Deserialization failed: {}", e)))?;

        self.api
            .refresh_usk(&mut self.auth, &mut access_keys, grant_old_access)
            .map_err(|e| SystemError::SystemError(format!("Key refresh failed: {}", e)))?;

        // Serialize refreshed key
        let access_rights_bytes = access_keys
            .serialize()
            .map_err(|e| SystemError::SystemError(format!("Key serialization failed: {}", e)))?;

        Ok(access_rights_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpabe_manager_creation() {}
}
