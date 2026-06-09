//! `fineco-helper` binary entry point.
//!
//! Dispatches one of the self-contained binary's roles (plan "Migration
//! target": one binary, subcommands/roles). Config is read from the environment
//! by each role; see [`fineco_helper::serve`].

use std::process::ExitCode;

use fineco_helper::serve::{
    self, BackupConfig, GatewayConfig, PrivateWorkerConfig, RefreshTriggerConfig, ServeError,
    StoreServerConfig,
};

fn main() -> ExitCode {
    let role = std::env::args().nth(1);
    let result = match role.as_deref() {
        Some("gateway") => run_gateway(),
        Some("store-server") => run_store_server(),
        Some("private-worker") => run_private_worker(),
        Some("backup") => run_backup(),
        Some("refresh") => run_refresh(),
        Some("--version" | "-V") => {
            println!("fineco-helper {}", fineco_helper::version());
            return ExitCode::SUCCESS;
        }
        other => {
            if let Some(role) = other {
                eprintln!("unknown role: {role}");
            }
            eprintln!(
                "usage: fineco-helper <gateway|store-server|private-worker|backup|refresh <area>>"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fineco-helper: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Read an environment variable as an owned `String`, if set and valid UTF-8.
fn env_get(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Start the gateway role on a dedicated multi-threaded Tokio runtime.
fn run_gateway() -> Result<(), ServeError> {
    let config = GatewayConfig::from_env(env_get)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServeError::from)?;
    runtime.block_on(serve::run_gateway(config))
}

/// Start the (blocking) store-server role.
fn run_store_server() -> Result<(), ServeError> {
    let config = StoreServerConfig::from_env(env_get)?;
    serve::run_store_server(config)
}

/// Start the (blocking) private-worker role: serve `fineco-live.sock`.
fn run_private_worker() -> Result<(), ServeError> {
    let config = PrivateWorkerConfig::from_env(env_get)?;
    serve::run_private_worker(config)
}

/// Run a one-shot online backup of the store to `FINECO_BACKUP_OUT`.
fn run_backup() -> Result<(), ServeError> {
    let config = BackupConfig::from_env(env_get)?;
    serve::run_backup(config)
}

/// Trigger a one-shot live refresh through the controller (the timer-driven
/// `refresh` subcommand). The data area is the third argument
/// (`fineco-helper refresh portfolio`); a missing/unsupported area is reported by
/// [`serve::parse_refresh_area`].
fn run_refresh() -> Result<(), ServeError> {
    let area = std::env::args().nth(2).unwrap_or_default();
    let request = serve::parse_refresh_area(&area)?;
    let config = RefreshTriggerConfig::from_env(env_get)?;
    serve::run_refresh(config, request)
}
