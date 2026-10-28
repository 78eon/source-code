#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod backend;
use std::sync::{Arc, Mutex};
use tauri::Manager;
type BackendState = Arc<Mutex<Option<backend::OwnedBackend>>>;

#[tauri::command]
async fn backend_session(
    app: tauri::AppHandle,
    state: tauri::State<'_, BackendState>,
) -> Result<backend::Session, String> {
    let resources = app
        .path()
        .resource_dir()
        .map_err(|_| "Application resources unavailable")?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut guard = state.lock().map_err(|_| "Backend state unavailable")?;
        if let Some(owned) = guard.as_mut() {
            if !owned.alive() {
                return Err("Owned backend stopped; restart the desktop".into());
            }
            return Ok(owned.session.clone());
        }
        let owned = backend::OwnedBackend::start(&resources)?;
        let session = owned.session.clone();
        *guard = Some(owned);
        Ok(session)
    })
    .await
    .map_err(|_| "Backend startup task failed")?
}

#[tauri::command]
async fn desktop_configuration(
    app: tauri::AppHandle,
    state: tauri::State<'_, BackendState>,
    operation: String,
    payload: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if !["get", "save", "check"].contains(&operation.as_str()) {
        return Err("Unsupported configuration operation".into());
    }
    let resources = app
        .path()
        .resource_dir()
        .map_err(|_| "Application resources unavailable")?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut guard = state.lock().map_err(|_| "Backend state unavailable")?;
        let result = backend::configuration(&resources, &operation, payload)?;
        if operation == "save" {
            guard.take();
        }
        Ok(result)
    })
    .await
    .map_err(|_| "Configuration task failed")?
}

fn main() {
    tauri::Builder::default()
        .manage(BackendState::default())
        .setup(|_app| {
            // Bounded native startup/exit smoke test in development builds only.
            #[cfg(debug_assertions)]
            if let Ok(value) = std::env::var("SECURITY_RL_SMOKE_EXIT_SECONDS") {
                let seconds = value.parse::<u64>().unwrap_or(15).clamp(10, 60);
                let handle = _app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(seconds));
                    handle.exit(0);
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            backend_session,
            desktop_configuration
        ])
        .build(tauri::generate_context!())
        .expect("Desktop runtime failed")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                if let Ok(mut state) = app.state::<BackendState>().lock() {
                    state.take();
                }
            }
        });
}
