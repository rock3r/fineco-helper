//! Online backup of the store via `VACUUM INTO`.
//!
//! `VACUUM INTO` writes a single, compacted, consistent copy of the database to a
//! new file under a read lock — the SQLite-native online backup, with no extra
//! `rusqlite` feature and no host `sqlite3` binary (it runs inside the
//! self-contained product binary's `backup` role). On Unix the copy is staged in a
//! private (0700) directory and written 0600, then published with a `hard_link`
//! that fails if the target exists — so a backup never clobbers data and is never
//! readable by another local user, even briefly during the write, regardless of
//! umask. The deploy layer compresses + `age`-encrypts the output and applies
//! retention (see `deploy/backup/` and `docs/DEPLOYMENT.md` → "Backup").

use std::path::Path;

use crate::{Result, Store};

impl Store {
    /// Write a consistent backup copy of the database to `dest`. `dest` must not
    /// already exist (publishing refuses to overwrite). The `busy_timeout` set at
    /// open waits out a concurrent writer rather than failing immediately.
    ///
    /// # Errors
    /// Returns an error if the copy cannot be written (e.g. `dest` exists, or the
    /// path is not writable).
    pub fn backup_to(&self, dest: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            self.backup_to_unix(dest)
        }
        #[cfg(not(unix))]
        {
            let dest_str = dest
                .to_str()
                .ok_or_else(|| rusqlite::Error::InvalidPath(dest.to_path_buf()))?;
            self.conn.execute("VACUUM INTO ?1", [dest_str])?;
            Ok(())
        }
    }

    /// Unix backup: stage the copy in a freshly-created private (0700) directory so
    /// no other local user can open it mid-`VACUUM` (before the 0600 chmod) and keep
    /// the fd, then publish it. The backup is a full plaintext copy of sensitive
    /// data; this holds independent of the caller's umask, so a manual
    /// `fineco-helper backup` cannot leave the copy exposed even briefly.
    #[cfg(unix)]
    fn backup_to_unix(&self, dest: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let parent = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        // Unique per call: pid keeps it distinct across processes, the counter keeps
        // concurrent backups within one process (e.g. parallel tests, or two backup
        // roles) from colliding on the same staging directory.
        use std::sync::atomic::{AtomicU64, Ordering};
        static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let staging = parent.join(format!(
            ".fineco-backup-staging-{}-{seq}",
            std::process::id()
        ));
        // Clear any stale staging dir from a previously crashed run, then create it
        // empty and tighten it to 0700 BEFORE writing the copy — the brief
        // create→chmod window exposes only an empty directory.
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir(&staging)?;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;

        let result = (|| -> Result<()> {
            let tmp = staging.join("backup.sqlite");
            let tmp_str = tmp
                .to_str()
                .ok_or_else(|| rusqlite::Error::InvalidPath(tmp.clone()))?;
            // Bind the path as a parameter (no built SQL); `tmp` is internal, never
            // client input.
            self.conn.execute("VACUUM INTO ?1", [tmp_str])?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            // Publish atomically and race-free: `hard_link` fails if `dest` already
            // exists, preserving the no-overwrite contract without a TOCTOU. `tmp`
            // and `dest` share `parent`, so they are on one filesystem.
            std::fs::hard_link(&tmp, dest)?;
            Ok(())
        })();
        // Best-effort cleanup; a published `dest` survives via its own hard link.
        let _ = std::fs::remove_dir_all(&staging);
        result
    }
}
