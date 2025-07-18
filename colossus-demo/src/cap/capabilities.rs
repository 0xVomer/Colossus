use crate::errors::AppError;
use chrono::{Duration, Utc};
use log::{error, info};
use mysql_async::{Pool, prelude::*};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid;

use ucan::crypto::did::{DidParser, KeyConstructorSlice};

/// Resource types for Bio-DID-Seq capabilities
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstituionalTradingResource {
    // Dataset with resource CID
    DATASET(String),
    // trading engine with resource CID
    ENGINE(String),
    // API with resource CID
    API(String),
}

impl InstituionalTradingResource {
    pub fn new_dataset(cid: &str) -> Self {
        InstituionalTradingResource::DATA(cid.to_string())
    }

    pub fn new_engine(cid: &str) -> Self {
        InstituionalTradingResource::ENGINE(cid.to_string())
    }

    pub fn new_api(cid: &str) -> Self {
        InstituionalTradingResource::API(cid.to_string())
    }
    pub fn resource_label(&self) -> String {
        match self {
            InstituionalTradingResource::DATASET(cid) => format!("institutional:{}", cid),
            InstituionalTradingResource::ENGINE(cid) => format!("institutional:{}", cid),
            InstituionalTradingResource::API(cid) => format!("institutional:{}", cid),
        }
    }
}

/// Actions that can be performed on Bio-DID-Seq resources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstituionalTradingAction {
    Create,
    Execute,
    Read,
    Update,
    Delete,
    Upload,
    Download,
    Process,
    Publish,
}

impl InstituionalTradingAction {
    pub fn action_label(&self) -> String {
        match self {
            InstituionalTradingAction::Create => "create".to_string(),
            InstituionalTradingAction::Execute => "execute".to_string(),
            InstituionalTradingAction::Read => "read".to_string(),
            InstituionalTradingAction::Update => "update".to_string(),
            InstituionalTradingAction::Delete => "delete".to_string(),
            InstituionalTradingAction::Upload => "upload".to_string(),
            InstituionalTradingAction::Download => "download".to_string(),
            InstituionalTradingAction::Process => "process".to_string(),
            InstituionalTradingAction::Publish => "publish".to_string(),
        }
    }
}

/// Simple capability structure for Bio-DID-Seq
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstituionalTradingCapability {
    pub resource: InstituionalTradingResource,
    pub action: InstituionalTradingAction,
}

// /// Service for handling UCAN based authorization
// pub struct UcanService {
//     db_pool: Arc<Pool>,
//     did_parser: DidParser,
//     token_store: MemoryTokenStore,
//     issuer_key: Arc<DummyKeyMaterial>,
// }

// impl UcanService {
//     /// Create a new UCAN service
//     pub async fn new(db_pool: Arc<Pool>) -> Result<Self, AppError> {
//         // For simplicity, we're using a placeholder for a real implementation,
//         // we'll set up proper key constructors
//         const SUPPORTED_KEY_TYPES: &KeyConstructorSlice = &[];

//         let did_parser = DidParser::new(SUPPORTED_KEY_TYPES);
//         let token_store = MemoryTokenStore::new();

//         // Load the issuer key - in a real implementation, we'll use actual key material
//         let issuer_key = Arc::new(DummyKeyMaterial);

//         Ok(Self {
//             db_pool,
//             did_parser,
//             token_store,
//             issuer_key,
//         })
//     }

//     /// Verify a UCAN token and extract its capabilities
//     pub async fn verify_token(&self, token: &str) -> Result<Vec<(String, String)>, AppError> {
//         // Parse token with simple format: ucan:demo:id:issuer:audience:timestamp
//         let parts: Vec<&str> = token.split(':').collect();
//         if parts.len() < 6 || parts[0] != "ucan" || parts[1] != "demo" {
//             return Err(AppError::AuthError("Invalid UCAN token format".to_string()));
//         }

//         // For Production implementation, we need to parse a proper UCAN token
//         // For now, we'll just return some dummy capabilities
//         let capabilities = vec![
//             ("bio://dataset/*".to_string(), "read".to_string()),
//             ("bio://did/*".to_string(), "read".to_string()),
//         ];

//         Ok(capabilities)
//     }

//     /// Check if a token has a specific capability
//     pub async fn has_capability(
//         &self,
//         token: &str,
//         resource: &str,
//         action: &str,
//     ) -> Result<bool, AppError> {
//         let capabilities = self.verify_token(token).await?;

//         // Check if any capability matches the requested resource and action
//         let has_capability = capabilities.iter().any(|(res, act)| res == resource && act == action);

//         Ok(has_capability)
//     }

//     /// Delegate capabilities to another user
//     pub async fn delegate_capability(
//         &self,
//         user_id: i64,
//         from_token: &str,
//         to_did: &str,
//         _capabilities: Vec<BioCapability>,
//     ) -> Result<String, AppError> {
//         let now = Utc::now();
//         let expiry = now + Duration::hours(24);

//         // First verify the original token
//         let _capabilities = self.verify_token(from_token).await?;

//         // Format a simplified JWT like token for demonstration
//         let token_id = uuid::Uuid::new_v4().to_string();
//         let token =
//             format!("ucan:demo:{}:{}:{}:{}", token_id, "delegated", to_did, now.timestamp());

//         // Store the token in the database with delegation info
//         let mut conn = self.db_pool.get_conn().await.map_err(|e| {
//             error!("Failed to get database connection: {}", e);
//             AppError::DatabaseError(e.to_string())
//         })?;

//         let issued_at = now.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string();
//         let expires_at = expiry.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string();

//         // Get the issuer from the original token
//         let issuer = from_token.split(':').nth(3).unwrap_or("unknown");

//         // Generate a UUID for the token ID
//         let token_id = uuid::Uuid::new_v4().to_string();

//         "INSERT INTO ucan_tokens (id, user_id, token, audience_did, issued_at, expires_at, delegated_from) VALUES (:id, :user_id, :token, :audience_did, :issued_at, :expires_at, :delegated_from)"
//             .with(params! {
//                 "id" => &token_id,
//                 "user_id" => user_id,
//                 "token" => &token,
//                 "audience_did" => to_did,
//                 "issued_at" => issued_at,
//                 "expires_at" => expires_at,
//                 "delegated_from" => issuer,
//             })
//             .run(&mut conn)
//             .await
//             .map_err(|e| {
//                 error!("Database error when storing delegated UCAN token: {}", e);
//                 AppError::DatabaseError(e.to_string())
//             })?;

//         info!("Delegated capabilities from user {} to DID {}", user_id, to_did);

//         Ok(token)
//     }

//     /// Revoke a UCAN token
//     pub async fn revoke_token(&self, user_id: i64, token_id: &str) -> Result<(), AppError> {
//         // Check if the user owns the token
//         let mut conn = self.db_pool.get_conn().await.map_err(|e| {
//             error!("Failed to get database connection: {}", e);
//             AppError::DatabaseError(e.to_string())
//         })?;

//         let exists: Option<i32> = "SELECT 1 FROM ucan_tokens WHERE id = :id AND user_id = :user_id"
//             .with(params! {
//                 "id" => token_id,
//                 "user_id" => user_id,
//             })
//             .first(&mut conn)
//             .await
//             .map_err(|e| {
//                 error!("Database error when checking token ownership: {}", e);
//                 AppError::DatabaseError(e.to_string())
//             })?;

//         if exists.is_none() {
//             return Err(AppError::NotFound("Token not found or not owned by user".to_string()));
//         }

//         // Mark the token as revoked in the database
//         let now = Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S").to_string();

//         "UPDATE ucan_tokens SET revoked = TRUE, revoked_at = :revoked_at WHERE id = :id"
//             .with(params! {
//                 "revoked_at" => now,
//                 "id" => token_id,
//             })
//             .run(&mut conn)
//             .await
//             .map_err(|e| {
//                 error!("Database error when revoking token: {}", e);
//                 AppError::DatabaseError(e.to_string())
//             })?;

//         info!("Revoked token {} for user {}", token_id, user_id);

//         Ok(())
//     }

//     /// Check if a token is revoked
//     pub async fn is_token_revoked(&self, token: &str) -> Result<bool, AppError> {
//         // Extract token ID from our simple format
//         let _token_id = token.split(':').nth(2).ok_or_else(|| {
//             error!("Invalid token format");
//             AppError::AuthError("Invalid token format".to_string())
//         })?;

//         // Check the database to see if it's revoked
//         let mut conn = self.db_pool.get_conn().await.map_err(|e| {
//             error!("Failed to get database connection: {}", e);
//             AppError::DatabaseError(e.to_string())
//         })?;

//         // We use the token itself as the identifier, since we might not have stored it by ID
//         let revoked: Option<i32> = "SELECT revoked FROM ucan_tokens WHERE token = :token"
//             .with(params! {
//                 "token" => token,
//             })
//             .first(&mut conn)
//             .await
//             .map_err(|e| {
//                 error!("Database error when checking token revocation: {}", e);
//                 AppError::DatabaseError(e.to_string())
//             })?;

//         Ok(revoked.unwrap_or(0) == 1)
//     }
// }

// // Dummy key material for demonstration purposes
// // For Production implementation, we'll use a proper key from the ucan-key-support crate
// #[derive(Clone)]
// struct DummyKeyMaterial;

// // Since we can't use the real KeyMaterial trait due to lifetime issues,
// // we'll implement a simplified version for our needs
// impl DummyKeyMaterial {
//     fn get_did(&self) -> String {
//         "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()
//     }

//     fn get_jwt_algorithm_name(&self) -> String {
//         "EdDSA".to_string()
//     }
// }
