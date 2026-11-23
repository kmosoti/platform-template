use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use serde::Serialize;

pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path `{}` has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("failed creating `{}`: {e}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    let tmp_path = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));

    let write_res = (|| -> std::io::Result<()> {
        let mut file = File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp_path, path)
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "atomic write to `{}` failed: {err}",
            path.display()
        ));
    }
    Ok(())
}

pub fn write_pretty_json_atomic<T: Serialize>(path: &Path, val: &T) -> Result<(), String> {
    let rendered =
        serde_json::to_string_pretty(val).map_err(|e| format!("JSON serialization failed: {e}"))?;
    write_bytes_atomic(path, format!("{rendered}\n").as_bytes())
}
