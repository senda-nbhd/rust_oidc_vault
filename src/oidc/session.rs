use tower_sessions::CachingSessionStore;
use tower_sessions_moka_store::MokaStore;
use tower_sessions_sqlx_store::PostgresStore;

pub type AiclSessionStore = CachingSessionStore<MokaStore, PostgresStore>;
