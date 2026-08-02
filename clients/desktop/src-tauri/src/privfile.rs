//! Private-by-default writes for everything Sona keeps at rest (SP-15).
//!
//! Every at-rest file used to go out through a plain `std::fs::write`, which creates
//! with `0666 & ~umask` — typically **0644** — inside an app-data directory created
//! 0755. On a shared Linux desktop that means any other local user can read
//! `vault.bin`, `history.bin`, `prefs.json`, the quick-unlock blobs, and the whole
//! call-control store.
//!
//! With a working keyring the v2 vault is device-bound and this is defence in depth.
//! **Without** one — a headless box, or no Secret Service — the vault falls back to v1
//! (password-only), and any local user can copy it and brute-force it offline: exactly
//! the attack the v2 vault exists to remove. Argon2id at 64 MiB / t=3 is a real cost,
//! not an infinite one, and a weak password falls.
//!
//! This is not the primary control and should not be read as one. The device-bound v2
//! vault is; a shared multi-user host stays outside the endpoint threat model regardless
//! of file modes. What this removes is the free copy.
//!
//! Centralized in one helper on purpose: the mode has to be set at *create* time, and
//! `std::fs::write` takes no mode, so the alternative was ~8 open-coded `OpenOptions`
//! chains — eight chances for a new write site to quietly go back to 0644.
//!
//! Windows and Android need nothing here (per-user and per-app respectively) and
//! `.mode()` does not compile there, so the mode is `#[cfg(unix)]` and the write is
//! otherwise ordinary.

use std::io::Write;
use std::path::Path;

/// Owner-only file mode.
#[cfg(unix)]
const PRIVATE_FILE: u32 = 0o600;
/// Owner-only directory mode.
#[cfg(unix)]
const PRIVATE_DIR: u32 = 0o700;

/// Create (or truncate) `path` owner-readable-only and write `bytes`.
///
/// Note the mode applies at creation. An existing file keeps whatever mode it already
/// has, which is why [`harden_existing`] exists for upgrades from a build that wrote
/// 0644.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PRIVATE_FILE);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    // Re-assert the mode: `mode()` only applies when the file is newly created, so a file
    // left at 0644 by an older build would otherwise keep it forever.
    #[cfg(unix)]
    harden_existing(path);
    Ok(())
}

/// Create `path` as a directory tree, owner-only.
pub(crate) fn create_dir_private(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR));
    }
    Ok(())
}

/// Tighten an existing file to owner-only. Best-effort and silent: a file we do not own
/// (or a filesystem without Unix modes) is not worth failing a write over.
#[cfg(unix)]
pub(crate) fn harden_existing(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE));
}

#[cfg(not(unix))]
pub(crate) fn harden_existing(_path: &Path) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn written_files_and_dirs_are_owner_only() {
        let dir = std::env::temp_dir().join(format!("sona-privfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();
        assert_eq!(mode_of(&dir), PRIVATE_DIR);

        let f = dir.join("vault.bin");
        write_private(&f, b"secret").unwrap();
        assert_eq!(mode_of(&f), PRIVATE_FILE);
        assert_eq!(std::fs::read(&f).unwrap(), b"secret");

        // A file an older build left world-readable is tightened on the next write, not
        // left at 0644 forever — `mode()` alone only applies to a *new* file.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&f, b"again").unwrap();
        assert_eq!(mode_of(&f), PRIVATE_FILE);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
