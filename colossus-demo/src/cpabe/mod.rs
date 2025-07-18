mod manager;
mod policy;

pub use manager::CpAbeManager;
pub use policy::Policy;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cpabe_manager_creation() {
        let manager = CpAbeManager::new();
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_attribute_verification() {
        let manager = CpAbeManager::new().unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("trading_level".to_string(), "Institutional".to_string());
        attributes.insert("institution_type".to_string(), "HedgeFund".to_string());

        let result = manager.verify_attributes(&attributes, "institutional_trading").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // #[test]
    // fn test_policy_creation() {
    //     let policy = CpAbeManager::create_institutional_policy();
    //     assert!(policy.is_ok());
    // }
}
