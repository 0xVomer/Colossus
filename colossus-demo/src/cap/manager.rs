//! UCAN Capability Manager for delegatable authorization
use crate::errors::ZeroTrustError;
use did_key::{Ed25519KeyPair, Fingerprint, KeyMaterial, PatchedKeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ucan::{
    Ucan,
    builder::UcanBuilder,
    capability::{Capabilities, Capability},
    chain::ProofChain,
    crypto::did::{DidParser, KeyConstructorSlice},
};
use ucan_key_support::ed25519::{Ed25519KeyMaterial, bytes_to_ed25519_key};
use uuid::Uuid;

/// UCAN Capability Manager
pub struct CapabilityManager {
    did_parser: DidParser,
    accounts: HashSet<String>,
    tokens: HashMap<String, Ucan>,
    sk: PatchedKeyPair,
}

fn did_to_issuer_key(did: &PatchedKeyPair) -> Ed25519KeyMaterial {
    let pub_key: VerificationKey =
        VerificationKey::try_from(did.public_key_bytes().as_slice()).unwrap();
    let mut pk_slice: [u8; 32] = [0; 32];
    let pk_bytes = did.private_key_bytes();

    pk_slice[..32].copy_from_slice(&pk_bytes[..32]);

    let private_key: SigningKey = SigningKey::from(pk_slice);
    Ed25519KeyMaterial(pub_key, Some(private_key))
}

fn did_uri(did: &PatchedKeyPair) -> String {
    format!("did:key:{}", did.fingerprint())
}

fn ucan_cid(ucan: &Ucan) -> String {
    let cid = ucan.to_cid(UcanBuilder::<Ed25519KeyMaterial>::default_hasher()).unwrap();
    cid.to_string()
}

impl CapabilityManager {
    /// Create new capability manager
    pub fn new() -> ZeroTrustResult<Self> {
        Ok(Self {
            accounts: HashSet::new(),
            sk: did_key::generate::<Ed25519KeyPair>(None),
            did_parser: DidParser::new(SUPPORTED_UCAN_KEYS),
            tokens: HashMap::new(),
        })
    }

    fn issuer_key(&self) -> Ed25519KeyMaterial {
        did_to_issuer_key(&self.app_did);
    }

    fn new_owner(&mut self) -> PatchedKeyPair {
        let key_pair = did_key::generate::<Ed25519KeyPair>(None);
        self.owners.insert(did_uri(&key_pair));
        key_pair
    }

    fn remove_owner(&mut self, did: &PatchedKeyPair) {
        self.owners.remove(&did_uri(did));
    }

    fn register_token(&mut self, cid: &str, token: Ucan) {
        self.tokens.insert(cid.to_owned(), token);
    }

    // Returns the capabilities for this UCAN if we find it's from a known user.
    pub async fn get_capabilities(&self, ucan: &Ucan) -> Result<Capabilities, String> {
        // Check timestamps and signature.
        if ucan.validate(None, &mut self.did_parser).await.is_err() {
            return Err("Invalid UCAN".into());
        }

        // Check if there is a proof that matches a known valid issuer.
        for proof in ucan.proofs().clone().unwrap_or_default() {
            if let Some(owner_ucan) = self.tokens.get(&proof) {
                if owner_ucan.validate(None, &mut self.did_parser).await.is_err() {
                    return Err("Invalid owner UCAN".into());
                }
                // Check that the issuer DID is still a valid owner.
                if !self.owners.contains(ucan.issuer()) {
                    return Err("Issuer is not a valid owner".into());
                }
                // TODO: more checks?

                return Ok(ucan.capabilities().clone());
            }
        }
        Err("No proof found".into())
    }

    /// Issue capability token for institutional trading
    pub async fn issue_capabilities(
        &mut self,
        account: &str,
        capabilities: Capabilities,
    ) -> Result<Ucan, ZeroTrustError> {
        let signable = UcanBuilder::default()
            .issued_by(&self.issuer_key())
            .for_audience(account)
            .claiming_capabilities(&capabilities)
            .build()
            .unwrap();

        let ucan_from_owner = signable.sign().await.unwrap();
        // Add the cid for this UCAN to the server proofs store.
        self.register_token(ucan_cid(&ucan_from_owner).as_str(), ucan_from_owner.clone());
        Ok(ucan_from_owner)
    }

    // /// Delegate capability to another user
    // pub async fn delegate_capability(
    //     &mut self,
    //     from_user: Uuid,
    //     to_user: Uuid,
    //     capabilities: Vec<Capability>,
    // ) -> ZeroTrustResult<UcanToken> {
    //     // Verify delegator has sufficient capabilities
    //     let delegator_caps = self
    //         .capabilities
    //         .get(&from_user)
    //         .ok_or_else(|| ZeroTrustError::UcanError("Delegator not found".to_string()))?;

    //     // Check if delegator can delegate these capabilities
    //     for capability in &capabilities {
    //         if !delegator_caps.can_perform(&capability.action, &capability.resource) {
    //             return Err(ZeroTrustError::UcanError(format!(
    //                 "Insufficient capability to delegate: {}",
    //                 capability.action
    //             )));
    //         }
    //     }

    //     let token_id = Uuid::new_v4();
    //     let expires_at = chrono::Utc::now() + chrono::Duration::hours(12); // Shorter for delegated

    //     let token = format!("ucan_delegated_{}", token_id);

    //     let ucan_token = UcanToken {
    //         id: token_id,
    //         issuer: format!("did:key:user_{}", from_user),
    //         audience: format!("did:key:user_{}", to_user),
    //         capabilities: capabilities.clone(),
    //         token,
    //         expires_at,
    //     };

    //     // Store delegated capabilities
    //     let user_capabilities = UserCapabilities {
    //         user_id: to_user,
    //         tokens: vec![ucan_token.clone()],
    //         delegated_from: Some(from_user),
    //         expires_at,
    //     };

    //     self.capabilities.insert(to_user, user_capabilities);

    //     Ok(ucan_token)
    // }
}
