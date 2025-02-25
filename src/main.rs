use oidc_rust::run;
use serde::Deserialize;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use vaultrs::{client::{VaultClient, VaultClientSettingsBuilder}, kv2};

#[derive(Deserialize, Debug)]
struct OidcConfig {
    app_url: String,
    issuer: String,
    client_id: String,
    client_secret: String,
}

async fn get_oidc_config_from_vault() -> Result<OidcConfig, Box<dyn std::error::Error>> {
    let address = std::env::var("VAULT_ADDR").ok().unwrap();
    let settings = VaultClientSettingsBuilder::default().address(address).build().unwrap();
    let client = VaultClient::new(settings).unwrap();
    let key = "oidc/app-config";
    match kv2::read::<OidcConfig>(&client, "secret", key).await {
        Ok(secret) => {
            tracing::debug!("Got secret {}", key);
            Ok(secret)
        }
        Err(e) => {
            tracing::error!("Failed to get secret {}: {}", key, e);
            Err(e.into())
        }
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    // Default filter if RUST_LOG is not set
                    // Set to info level for everything except hyper
                    "trace,hyper=off".into()
                })
        )
        .init();
    
    // Log application startup
    tracing::info!("Starting OIDC application");
    let config = get_oidc_config_from_vault().await.expect("Unable to get config from vault");
    run(
        config.app_url, 
        config.issuer, 
        config.client_id, 
        Some(config.client_secret)
    ).await;
}
