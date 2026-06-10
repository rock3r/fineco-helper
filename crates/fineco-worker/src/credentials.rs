//! Credential sourcing for the worker.
//!
//! The worker is the sole holder of Fineco credentials; they arrive through
//! [`CredentialSource`] so the live secret source is swappable — environment /
//! config now, the 1Password SDK at M6 — and tests inject synthetic values,
//! never a real credential.

use fineco_core::SafeError;
use zeroize::Zeroizing;

/// A Fineco login credential, held only transiently during a login.
///
/// Deliberately does NOT derive `Debug`/`Clone`-with-logging affordances: the
/// password must never be formatted into a log or error. The password is wrapped
/// in [`Zeroizing`] so its heap buffer is zeroed when the credential drops (after
/// each login), rather than lingering in freed pages.
pub struct FinecoCredential {
    /// Fineco user id.
    pub user_id: String,
    /// Fineco password (zeroed on drop).
    pub password: Zeroizing<String>,
}

impl FinecoCredential {
    /// Build a credential from its parts.
    #[must_use]
    pub fn new(user_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            password: Zeroizing::new(password.into()),
        }
    }
}

/// Supplies the Fineco login credential on demand.
pub trait CredentialSource {
    /// Load the credential.
    ///
    /// # Errors
    /// Returns a [`SafeError`] if the credential is unavailable (e.g. a missing
    /// environment variable). The error never contains the secret value.
    fn load(&self) -> Result<FinecoCredential, SafeError>;
}

/// Credentials held in memory — from config, or synthetic values in tests. The
/// password is zeroed on drop (the source can outlive a process, so its in-memory
/// copy is wrapped too, not just the per-login [`FinecoCredential`]).
pub struct StaticCredentialSource {
    user_id: String,
    password: Zeroizing<String>,
}

impl StaticCredentialSource {
    /// Hold the given credential in memory.
    #[must_use]
    pub fn new(user_id: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            password: Zeroizing::new(password.into()),
        }
    }
}

impl CredentialSource for StaticCredentialSource {
    fn load(&self) -> Result<FinecoCredential, SafeError> {
        Ok(FinecoCredential::new(
            self.user_id.clone(),
            self.password.as_str(),
        ))
    }
}

/// Reads the credential from environment variables (`FINECO_USER_ID` /
/// `FINECO_PASSWORD`). A stand-in until the 1Password-backed source lands at M6.
pub struct EnvCredentialSource;

impl CredentialSource for EnvCredentialSource {
    fn load(&self) -> Result<FinecoCredential, SafeError> {
        credential_from_parts(
            std::env::var("FINECO_USER_ID").ok(),
            std::env::var("FINECO_PASSWORD").ok(),
        )
    }
}

/// Build a credential from optional parts, treating a missing/empty user id or
/// password as an **auth** state (configure credentials/session), not a generic
/// bad request — so `freshness_for` reports `AuthRequired` (the credential
/// remediation state) rather than a generic `RefreshFailed`.
fn credential_from_parts(
    user_id: Option<String>,
    password: Option<String>,
) -> Result<FinecoCredential, SafeError> {
    match (user_id, password) {
        (Some(user_id), Some(password)) if !user_id.is_empty() && !password.is_empty() => {
            Ok(FinecoCredential::new(user_id, password))
        }
        _ => Err(SafeError::auth_required()),
    }
}

#[cfg(test)]
mod tests {
    use super::credential_from_parts;

    #[test]
    fn complete_parts_yield_a_credential() {
        let credential = credential_from_parts(Some("user".into()), Some("pass".into()))
            .expect("complete credential");
        assert_eq!(credential.user_id, "user");
        assert_eq!(credential.password.as_str(), "pass");
    }

    #[test]
    fn missing_or_empty_parts_are_auth_required() {
        for (user, pass) in [
            (None, Some("pass".to_string())),
            (Some("user".to_string()), None),
            (Some(String::new()), Some("pass".to_string())),
            (Some("user".to_string()), Some(String::new())),
            (None, None),
        ] {
            // `FinecoCredential` has no `Debug` (anti-leak), so match rather
            // than `expect_err` (which would format the Ok value).
            let err = match credential_from_parts(user, pass) {
                Ok(_) => panic!("missing/empty credentials must be auth_required"),
                Err(err) => err,
            };
            assert_eq!(err.code(), "auth_required");
        }
    }
}
