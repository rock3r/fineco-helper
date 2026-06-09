//! Online backup of the store via `VACUUM INTO`.
//!
//! `VACUUM INTO` writes a single, compacted, consistent copy of the database to a
//! new file under a read lock — the SQLite-native online backup, with no extra
//! `rusqlite` feature and no host `sqlite3` binary (it runs inside the
//! self-contained product binary's `backup` role). It refuses to overwrite an
//! existing target, so a backup can never clobber data. The deploy layer
//! compresses + `age`-encrypts the output and applies retention (see
//! `deploy/backup/` and `docs/DEPLOYMENT.md` → "Backup").

use std::path::Path;

use crate::{Result, Store};

impl Store {
    /// Write a consistent backup copy of the database to `dest`. `dest` must not
    /// already exist (`VACUUM INTO` refuses to overwrite). The `busy_timeout` set
    /// at open waits out a concurrent writer rather than failing immediately.
    ///
    /// # Errors
    /// Returns an error if the copy cannot be written (e.g. `dest` exists, or the
    /// path is not writable).
    pub fn backup_to(&self, dest: &Path) -> Result<()> {
        // The path comes from config/argv (never client input). Reject a non-UTF-8
        // destination rather than silently mangling it via lossy conversion (which
        // could write the backup to a different file than configured).
        let dest_str = dest
            .to_str()
            .ok_or_else(|| rusqlite::Error::InvalidPath(dest.to_path_buf()))?;
        // Single-quote it for the SQL literal `VACUUM INTO` requires, escaping any
        // embedded quote.
        let escaped = dest_str.replace('\'', "''");
        self.conn
            .execute_batch(&format!("VACUUM INTO '{escaped}'"))?;
        Ok(())
    }
}
