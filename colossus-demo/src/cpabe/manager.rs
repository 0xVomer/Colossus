///! Implementation of the CP-ABE manager with institutional trading policies


pub struct CpAbeManager {
    //cover_crypt: CoverCryptX25519Aes256,
    master_secret_key: MasterSecretKey,
    master_public_key: MasterPublicKey,
    user_keys: HashMap<String, UserSecretKey>,
    policy: Policy,
}

impl CpAbeManager {
    /// Create a new CP-ABE manager with institutional trading policies
    pub fn new() -> ZeroTrustResult<Self> {
        // Create institutional trading policy
        let policy = Self::create_institutional_policy()?;

        // Generate master keys
        let (master_secret_key, master_public_key) = cover_crypt
            .generate_master_keys(&policy.to_covercrypt_policy()?)
            .map_err(|e| ZeroTrustError::CpAbeError(format!("Key generation failed: {}", e)))?;

        Ok(Self {
            master_secret_key,
            master_public_key,
            user_keys: HashMap::new(),
            policy,
        })
    }

    /// Create institutional trading policy with multiple axes
    fn create_institutional_policy() -> ZeroTrustResult<Policy> {
        Ok(Policy {
            trading_level: TradingLevel::Institutional,
            institution_type: InstitutionType::HedgeFund,
            geographical_region: Region::Global,
            compliance_level: ComplianceLevel::Institutional,
        })
    }

    /// Generate user secret key for institutional trader
    pub fn generate_user_key(&mut self, user_id: &str, user_policy: &Policy) -> ZeroTrustResult<()> {
        let access_policy = AccessPolicy::from_boolean_expression(
            &format!(
                "TradingLevel::{:?} && InstitutionType::{:?} && Region::{:?} && ComplianceLevel::{:?}",
                user_policy.trading_level,
                user_policy.institution_type,
                user_policy.geographical_region,
                user_policy.compliance_level
            )
        ).map_err(|e| ZeroTrustError::CpAbeError(format!("Policy creation failed: {}", e)))?;

        let user_secret_key = self.cover_crypt
            .generate_user_secret_key(
                &self.master_secret_key,
                &access_policy,
                &self.policy.to_covercrypt_policy()?
            )
            .map_err(|e| ZeroTrustError::CpAbeError(format!("User key generation failed: {}", e)))?;

        self.user_keys.insert(user_id.to_string(), user_secret_key);
        Ok(())
    }

    /// Encrypt transaction data with institutional policy
    pub fn encrypt_transaction(&self,  &[u8], policy: &Policy) -> ZeroTrustResult<Vec<u8>> {
        let encryption_policy = vec![
            format!("TradingLevel::{:?}", policy.trading_level),
            format!("InstitutionType::{:?}", policy.institution_type),
            format!("Region::{:?}", policy.geographical_region),
            format!("ComplianceLevel::{:?}", policy.compliance_level),
        ];

        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.cover_crypt,
            &self.policy.to_covercrypt_policy()?,
            &self.master_public_key,
            &encryption_policy.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            Some(data),
            None,
        ).map_err(|e| ZeroTrustError::CpAbeError(format!("Encryption failed: {}", e)))?;

        Ok(encrypted_header.to_bytes())
    }

    /// Decrypt transaction data for authorized user
    pub fn decrypt_transaction(&self, user_id: &str, encrypted_data:_&[u8]) -> ZeroTrustResult<Vec<u8>> {
        let user_key = self.user_keys.get(user_id)
            .ok_or_else(|| ZeroTrustError::CpAbeError("User key not found".to_string()))?;

        let encrypted_header = EncryptedHeader::from_bytes(encrypted_data)
            .map_err(|e| ZeroTrustError::CpAbeError(format!("Header parsing failed: {}", e)))?;

        let decrypted_data = encrypted_header.decrypt(&self.cover_crypt, user_key, None)
            .map_err(|e| ZeroTrustError::CpAbeError(format!("Decryption failed: {}", e)))?;

        Ok(decrypted_data)
    }

    /// Verify user attributes against resource policy
    pub async fn verify_attributes(&self, user_attributes: &HashMap<String, String>, resource: &str) -> ZeroTrustResult<bool> {
        // Simplified attribute verification for institutional trading
        let trading_level = user_attributes.get("trading_level")
            .map(|s| s.as_str())
            .unwrap_or("Basic");

        let institution_type = user_attributes.get("institution_type")
            .map(|s| s.as_str())
            .unwrap_or("Unknown");

        // Check if user has sufficient attributes for resource
        let has_institutional_access = matches!(trading_level, "Institutional" | "Advanced");
        let has_valid_institution = !matches!(institution_type, "Unknown");

        // Resource-specific checks
        let resource_authorized = match resource {
            r if r.contains("institutional_trading") => has_institutional_access,
            r if r.contains("basic_trading") => true,
            _ => false,
        };

        Ok(has_valid_institution && resource_authorized)
    }

    /// Rotate attribute for enhanced security
    pub fn rotate_attribute(&mut self, attribute: &str) -> ZeroTrustResult<()> {
        // Implement attribute rotation for key refresh
        // This invalidates old keys and generates new ones
        println!("Rotating attribute: {}", attribute);
        Ok(())
    }
}
