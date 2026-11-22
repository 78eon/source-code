// The frontend supplies report bytes and a suggested basename, never a destination path.
use std::{fs::OpenOptions, io::Write, path::Path};

fn validate(filename: &str, bytes: &[u8]) -> Result<(), String> {
    if filename.len() > 160 || !filename.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || !["research-ppo-", "engineering-"].iter().any(|prefix| filename.starts_with(prefix))
        || bytes.is_empty() || bytes.len() > 32 * 1024 * 1024 {
        return Err("Invalid report name or size".into());
    }
    let valid = match filename.rsplit('.').next() {
        Some("pdf") => bytes.starts_with(b"%PDF-"),
        Some("html") => bytes.get(..15).is_some_and(|b| b.eq_ignore_ascii_case(b"<!doctype html>")),
        Some("json") => serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|v| v.is_object()),
        _ => false,
    };
    valid.then_some(()).ok_or_else(|| "Unexpected report format".into())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)
        .map_err(|e| format!("Choose a new writable report filename ({e})"))?;
    file.write_all(bytes).and_then(|_|file.sync_all()).map_err(|e|format!("Save incomplete ({e})"))
}

#[tauri::command]
pub fn save_report(window: tauri::WebviewWindow, filename: String, bytes: Vec<u8>) -> Result<Option<String>, String> {
    use gtk::prelude::*;
    validate(&filename, &bytes)?;
    let parent = window.gtk_window().map_err(|e|e.to_string())?;
    let dialog = gtk::FileChooserDialog::with_buttons(
        Some("Save assessment report"), Some(&parent), gtk::FileChooserAction::Save,
        &[("Cancel", gtk::ResponseType::Cancel), ("Save", gtk::ResponseType::Accept)]);
    dialog.set_current_name(&filename);
    if let Some(folder) = std::env::var_os("SECURITY_RL_EXPORT_DIRECTORY") {
        dialog.set_current_folder(folder);
    }
    let response = dialog.run();
    let path = dialog.filename();
    dialog.close();
    if response != gtk::ResponseType::Accept { return Ok(None); }
    let path = path.ok_or("Choose a local destination")?;
    if path.extension()!=Path::new(&filename).extension() { return Err("Keep the selected report extension".into()); }
    if let Some(root) = std::env::var_os("SECURITY_RL_EXPORT_DIRECTORY") {
        if path.parent().and_then(|p|p.canonicalize().ok()) != Some(std::fs::canonicalize(root).map_err(|_|"Export folder unavailable")?) {
            return Err("Choose the shared Security-RL export folder".into());
        }
    }
    write_new(&path, &bytes)?;
    Ok(Some(path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_paths_and_wrong_formats() {
        assert!(validate("engineering-x.json", b"{}").is_ok());
        assert!(validate("../engineering-x.json", b"{}").is_err());
        assert!(validate("engineering-x.pdf", b"{}").is_err());
    }
    #[test]
    fn saves_exact_bytes_and_preserves_existing_files() {
        let path=std::env::temp_dir().join(format!("report-test-{}",std::process::id()));
        write_new(&path,b"original").unwrap();
        assert!(write_new(&path,b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(),b"original");
        std::fs::remove_file(path).unwrap();
    }
}
