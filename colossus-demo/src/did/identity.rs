/// DID-based identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidIdentity {
    pub id: Uuid,
    pub did: String,
    pub public_key: Vec<u8>,
    pub document: String,
    pub verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub credentials: Vec<VerifiableCredential>,
}

/// Verifiable credential for institutional trading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub credential_type: CredentialType,
    pub claims: HashMap<String, String>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Types of credentials for institutional trading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    TradingLicense,
    InstitutionalAccreditation,
    ComplianceAttestation,
    GeographicalAuthorization,
}
