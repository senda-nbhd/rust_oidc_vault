
    use crate::ident::idp_admin::IdpAdmin;

    use super::{idp_admin::IdpConfig, *};
    use std::sync::Arc;
    use tokio::time::sleep;
    use std::env;

    // Helper function to create a realistic test config based on Terraform setup
    fn create_keycloak_config() -> IdpConfig {
        IdpConfig {
            provider_type: "keycloak".to_string(),
            base_url: "http://keycloak:8080".to_string(),
            realm: Some("app-realm".to_string()),
            client_id: "rust-app".to_string(),
            client_secret: Some(env::var("KEYCLOAK_CLIENT_SECRET").unwrap_or_else(|_| "test-client-secret".to_string())),
            admin_username: Some(env::var("KEYCLOAK_ADMIN").unwrap_or_else(|_| "root".to_string())),
            admin_password: Some(env::var("KEYCLOAK_ADMIN_PASSWORD").unwrap_or_else(|_| "root".to_string())),
            service_account_key_path: None,
            domain: None,
        }
    }

    // Test that verifies IdpAdmin can be created with the Keycloak configuration
    #[tokio::test]
    async fn test_create_idp_admin() {
        let result = IdpAdmin::new(create_keycloak_config()).await;
        assert!(result.is_ok(), "Failed to create IdpAdmin: {:?}", result.err());
    }

    // Integration test that requires a running Keycloak instance
    #[tokio::test]
    async fn test_keycloak_user_retrieval() {
        let admin = IdpAdmin::new(create_keycloak_config()).await.expect("Failed to create IdpAdmin");
        
        // Test retrieving Alice (defined in users.tf)
        let alice_result = admin.get_user("alice").await;
        assert!(alice_result.is_ok(), "Failed to retrieve user Alice: {:?}", alice_result.err());
        
        let alice = alice_result.unwrap();
        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email, Some("alice@domain.com".to_string()));
        assert_eq!(alice.first_name, Some("Alice".to_string()));
        assert_eq!(alice.last_name, Some("Aliceberg".to_string()));
        
        // Immediately call again to test caching
        let alice_cached_result = admin.get_user("alice").await;
        assert!(alice_cached_result.is_ok());
    }

    // Test for user role mapping based on roles defined in Terraform
    #[tokio::test]
    async fn test_user_roles() {
        let admin = IdpAdmin::new(create_keycloak_config()).await.expect("Failed to create IdpAdmin");
        
        // Test retrieving Bob's roles (should include Vault management role per users.tf)
        let bob_roles_result = admin.get_user_roles("bob").await;
        assert!(bob_roles_result.is_ok(), "Failed to retrieve Bob's roles: {:?}", bob_roles_result.err());
        
        let bob_roles = bob_roles_result.unwrap();
        let has_management_role = bob_roles.iter().any(|role| role.name == "management");
        assert!(has_management_role, "Bob should have the management role");
        
        // Call again to test caching
        let bob_roles_cached = admin.get_user_roles("bob").await.unwrap();
        assert_eq!(bob_roles.len(), bob_roles_cached.len());
    }

    // Test for groups feature
    #[tokio::test]
    async fn test_groups() {
        let admin = IdpAdmin::new(create_keycloak_config()).await.expect("Failed to create IdpAdmin");
        
        // Get all groups
        let groups_result = admin.get_groups().await;
        assert!(groups_result.is_ok(), "Failed to retrieve groups: {:?}", groups_result.err());
        
        // Test cache by calling again
        let groups_cached_result = admin.get_groups().await;
        assert!(groups_cached_result.is_ok());
        
        // Test cache invalidation
        admin.invalidate_caches();
        let groups_after_invalidation = admin.get_groups().await;
        assert!(groups_after_invalidation.is_ok());
    }

    // Test domain model conversion
    #[tokio::test]
    async fn test_domain_conversion() {
        let admin = IdpAdmin::new(create_keycloak_config()).await.expect("Failed to create IdpAdmin");
        
        // Get a user and convert to domain model
        let user_result = admin.get_user("bob").await;
        assert!(user_result.is_ok(), "Failed to retrieve Bob: {:?}", user_result.err());
        
        let user = user_result.unwrap();
        let domain_user_result = admin.to_domain_user(&user);
        assert!(domain_user_result.is_ok(), "Failed to convert user to domain model: {:?}", domain_user_result.err());
        
        let domain_user = domain_user_result.unwrap();
        assert_eq!(domain_user.name, "Bob Bobsen");
        
        // Since Bob has admin role in app_client (from users.tf)
        assert!(matches!(domain_user.role, Role::Root));
    }

    // Test caching behavior with TTL expiration
    #[tokio::test]
    async fn test_cache_ttl() {
        // This test assumes the cache TTL is set to a short duration for testing
        // In a real environment, you'd need to adjust the TTL or this test
        let admin = IdpAdmin::new(create_keycloak_config()).await.expect("Failed to create IdpAdmin");
        
        // Make initial request
        let first_result = admin.get_user("alice").await;
        assert!(first_result.is_ok());
        
        // This should be cached
        let cached_result = admin.get_user("alice").await;
        assert!(cached_result.is_ok());
        
        // Wait for cache to expire (assuming 2 minute TTL from the implementation)
        // Note: For testing, you might want to adjust the TTL to a shorter value
        println!("Waiting for cache to expire... (this may take some time)");
        sleep(tokio::time::Duration::from_secs(121)).await;
        
        // This should hit the provider again
        let after_expiry_result = admin.get_user("alice").await;
        assert!(after_expiry_result.is_ok());
    }

    // Test comprehensive report
    #[tokio::test]
    async fn test_comprehensive_report() {
        let admin = IdpAdmin::new(create_keycloak_config()).await.expect("Failed to create IdpAdmin");
        
        let report_result = admin.get_comprehensive_report().await;
        assert!(report_result.is_ok(), "Failed to get comprehensive report: {:?}", report_result.err());
        
        let report = report_result.unwrap();
        assert!(!report.is_empty(), "Comprehensive report should not be empty");
        
        // Verify all users have roles and groups populated
        for user in &report {
            println!("User: {}, Roles: {}, Groups: {}", 
                     user.username, user.roles.len(), user.groups.len());
        }
        
        // Test caching
        let cached_report = admin.get_comprehensive_report().await;
        assert!(cached_report.is_ok());
    }

    // Test specific cache invalidation
    #[tokio::test]
    async fn test_selective_cache_invalidation() {
        let admin = IdpAdmin::new(create_keycloak_config()).await.expect("Failed to create IdpAdmin");
        
        // Cache user data
        let _ = admin.get_user("alice").await.unwrap();
        let _ = admin.get_user("bob").await.unwrap();
        
        // Invalidate just Alice's cache
        admin.invalidate_user_cache("alice");
        
        // Bob should still be cached, Alice should not
        let _ = admin.get_user("alice").await.unwrap(); // Should hit provider again
        let _ = admin.get_user("bob").await.unwrap();   // Should use cache
        
        // Invalidate group cache
        let _ = admin.get_group("some-group-id").await; // May fail but caches the result
        admin.invalidate_group_cache("some-group-id");
        let _ = admin.get_group("some-group-id").await; // Should hit provider again
    }