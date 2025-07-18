/// DID Manager for identity verification
pub struct DidManager {
    identities: HashMap<Uuid, DidIdentity>,
    key_pairs: HashMap<String, Ed25519KeyPair>,
}

impl DidManager {
    /// Create new DID manager
    pub fn new() -> ZeroTrustResult<Self> {
        Ok(Self {
            identities: HashMap::new(),
            key_pairs: HashMap::new(),
        })
    }

    /// Create a new DID identity for institutional trader
    pub fn create_identity(&mut self, user_id: Uuid) -> Result<DidIdentity, ZeroTrustError> {
        // Generate Ed25519 key pair
        let key_pair = generate::<Ed25519KeyPair>(None);
        let fingerprint = key_pair.fingerprint();

        // Create DID document
        let did_doc = key_pair.get_did_document(Config::default());
        let did_doc_json = serde_json::to_string_pretty(&did_doc).map_err(|e| {
            ZeroTrustError::DidError(format!("DID document serialization failed: {}", e))
        })?;

        // Create DID identity
        let did_identity = DidIdentity {
            id: user_id,
            did: fingerprint.clone(),
            public_key: key_pair.public_key_bytes(),
            document: did_doc_json,
            verified: true,
            created_at: chrono::Utc::now(),
            credentials: Vec::new(),
        };

        // Store key pair and identity
        self.key_pairs.insert(fingerprint.clone(), key_pair);
        self.identities.insert(user_id, did_identity.clone());

        Ok(did_identity)
    }

    /// Issue institutional trading credential
    pub fn issue_credential(
        &mut self,
        user_id: Uuid,
        credential_type: CredentialType,
        claims: HashMap<String, String>,
    ) -> ZeroTrustResult<VerifiableCredential> {
        let identity = self
            .identities
            .get(&user_id)
            .ok_or_else(|| ZeroTrustError::DidError("Identity not found".to_string()))?;

        let credential = VerifiableCredential {
            id: Uuid::new_v4().to_string(),
            issuer: "did:key:institutional_authority".to_string(),
            subject: identity.did.clone(),
            credential_type,
            claims,
            issued_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::days(365)),
        };

        // Add credential to identity
        if let Some(identity) = self.identities.get_mut(&user_id) {
            identity.credentials.push(credential.clone());
        }

        Ok(credential)
    }

    /// Verify identity and credentials
    pub async fn verify_identity(&self, identity: &Identity) -> ZeroTrustResult<bool> {
        // Check if identity exists in our registry
        let stored_identity = self
            .identities
            .get(&identity.id)
            .ok_or_else(|| ZeroTrustError::DidError("Identity not found".to_string()))?;

        // Verify DID matches
        if stored_identity.did != identity.did {
            return Ok(false);
        }

        // Verify credentials are not expired
        let now = chrono::Utc::now();
        for credential in &stored_identity.credentials {
            if let Some(expires_at) = credential.expires_at {
                if now > expires_at {
                    return Ok(false);
                }
            }
        }

        // Additional verification could include:
        // - Cryptographic signature verification
        // - Credential status checks
        // - Revocation list checks

        Ok(stored_identity.verified)
    }

    /// Get identity by DID
    pub fn get_identity_by_did(&self, did: &str) -> ZeroTrustResult<&DidIdentity> {
        self.identities
            .values()
            .find(|identity| identity.did == did)
            .ok_or_else(|| ZeroTrustError::DidError("Identity not found by DID".to_string()))
    }

    /// Revoke credential
    pub fn revoke_credential(&mut self, user_id: Uuid, credential_id: &str) -> ZeroTrustResult<()> {
        if let Some(identity) = self.identities.get_mut(&user_id) {
            identity.credentials.retain(|cred| cred.id != credential_id);
        }
        Ok(())
    }

    /// Create institutional trading credentials
    pub fn create_institutional_credentials(
        &mut self,
        user_id: Uuid,
    ) -> ZeroTrustResult<Vec<VerifiableCredential>> {
        let mut credentials = Vec::new();

        // Trading license credential
        let mut trading_claims = HashMap::new();
        trading_claims.insert("license_type".to_string(), "institutional".to_string());
        trading_claims.insert("trading_level".to_string(), "advanced".to_string());
        trading_claims.insert("max_trade_size".to_string(), "10000000".to_string());

        let trading_credential =
            self.issue_credential(user_id, CredentialType::TradingLicense, trading_claims)?;
        credentials.push(trading_credential);

        // Institutional accreditation
        let mut accreditation_claims = HashMap::new();
        accreditation_claims.insert("institution_type".to_string(), "hedge_fund".to_string());
        accreditation_claims.insert("aum".to_string(), "1000000000".to_string());
        accreditation_claims.insert("regulatory_status".to_string(), "approved".to_string());

        let accreditation_credential = self.issue_credential(
            user_id,
            CredentialType::InstitutionalAccreditation,
            accreditation_claims,
        )?;
        credentials.push(accreditation_credential);

        // Compliance attestation
        let mut compliance_claims = HashMap::new();
        compliance_claims.insert("kyc_status".to_string(), "verified".to_string());
        compliance_claims.insert("aml_check".to_string(), "passed".to_string());
        compliance_claims.insert("sanction_check".to_string(), "clear".to_string());

        let compliance_credential = self.issue_credential(
            user_id,
            CredentialType::ComplianceAttestation,
            compliance_claims,
        )?;
        credentials.push(compliance_credential);

        Ok(credentials)
    }
}
