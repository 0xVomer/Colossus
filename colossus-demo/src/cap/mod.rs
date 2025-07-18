mod capabilities;
mod manager;
pub use manager::CapabilityManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_manager_creation() {
        let manager = CapabilityManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_capability_issuance() {
        let mut manager = CapabilityManager::new().unwrap();
        let user_id = Uuid::new_v4();

        let capabilities = create_institutional_trading_capabilities();
        let token = manager.issue_capability(user_id, capabilities);

        assert!(token.is_ok());

        let user_caps = manager.get_capabilities(&user_id);
        assert!(user_caps.is_ok());
        assert!(user_caps.unwrap().can_perform("read", "trading_data"));
    }

    #[test]
    fn test_capability_delegation() {
        let mut manager = CapabilityManager::new().unwrap();
        let doctor_id = Uuid::new_v4();
        let nurse_id = Uuid::new_v4();

        // Issue capabilities to doctor
        let doctor_caps = create_institutional_trading_capabilities();
        manager.issue_capability(doctor_id, doctor_caps).unwrap();

        // Delegate limited capabilities to nurse
        let nurse_caps = vec![Capability {
            action: "read".to_string(),
            resource: "trading_data".to_string(),
            constraints: HashMap::new(),
        }];

        let result = manager.delegate_capability(doctor_id, nurse_id, nurse_caps);
        assert!(result.is_ok());

        let nurse_capabilities = manager.get_capabilities(&nurse_id).unwrap();
        assert!(nurse_capabilities.can_perform("read", "trading_data"));
        assert!(!nurse_capabilities.can_perform("execute", "large_trades"));
    }
}
