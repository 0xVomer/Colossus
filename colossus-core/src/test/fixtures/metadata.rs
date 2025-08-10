use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEndpointMeta {
    pub domain: String,
    pub path: String,
    pub query_params: Vec<String>,
}
