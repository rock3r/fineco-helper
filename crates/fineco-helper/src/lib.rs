//! `fineco-helper` library crate.
//!
//! Hosts the self-contained binary's server roles (see [`serve`]). The design
//! rationale lives in the project's private design spec.

pub mod controller;
pub mod serve;

/// The crate's package version, as recorded in `Cargo.toml`.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_is_reported() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
