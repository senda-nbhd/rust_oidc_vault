use std::sync::Arc;

use sqlx::PgPool;

use crate::idp::admin::IdpAdmin;

pub mod users;
pub mod teams;
pub mod institutions;

/// Service for synchronizing IdP data with the database
pub struct IdpSyncService {
    db: PgPool,
    idp_admin: Arc<IdpAdmin>,
}

impl IdpSyncService {
    /// Create a new IdpSyncService
    pub fn new(db: PgPool, idp_admin: Arc<IdpAdmin>) -> Self {
        Self { db, idp_admin }
    }

    /// Synchronize all IdP entities with the database
    pub async fn sync_all(&self) -> anyhow::Result<()> {
        let mut tx = self.db.begin().await?;
        
        // Commit the transaction
        tx.commit().await?;
        
        Ok(())
    }
}