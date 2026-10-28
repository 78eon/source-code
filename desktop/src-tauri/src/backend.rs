use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Deserialize, Serialize)]
pub struct Session {
    pub origin: String,
    pub token: String,
    pub instance: String,
}

pub struct OwnedBackend {
    child: Child,
    pub session: Session,
}

impl OwnedBackend {
    pub fn start(resources: &Path) -> Result<Self, String> {
        let child = runtime_command(resources)?
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Do not forward library exceptions containing database credentials.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Cannot launch the configured Python executable")?;
        let mut owned = Self {
            child,
            session: Session {
                origin: String::new(),
                token: String::new(),
                instance: String::new(),
            },
        };
        let output = owned
            .child
            .stdout
            .take()
            .ok_or("Backend handshake pipe unavailable")?;
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(output.take(4096)).read_line(&mut line);
            let _ = send.send(result.map(|_| line));
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        let line = receive
            .recv_timeout(Duration::from_secs(20))
            .map_err(|_| "Backend startup timed out")?
            .map_err(|_| "Backend handshake failed")?;
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|_| "Backend exited before handshake; check runtime dependencies or another desktop instance")?;
        if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
            return Err(error.to_string());
        }
        owned.session = serde_json::from_value(value).map_err(|_| "Invalid backend handshake")?;
        let port = owned
            .session
            .origin
            .strip_prefix("http://127.0.0.1:")
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p != 0)
            .ok_or("Backend did not bind loopback")?;
        if owned.session.token.len() < 32 || owned.session.instance.len() != 32 {
            return Err("Invalid backend session".into());
        }
        while Instant::now() < deadline {
            if owned
                .child
                .try_wait()
                .map_err(|_| "Cannot check backend process")?
                .is_some()
            {
                return Err("Backend exited during startup".into());
            }
            if healthy(port, &owned.session.instance) {
                return Ok(owned);
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err("Backend health check timed out".into())
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

pub fn runtime_command(resources: &Path) -> Result<Command, String> {
    #[cfg(debug_assertions)]
    if let Ok(python) = std::env::var("SECURITY_RL_BACKEND_PYTHON") {
        if !Path::new(&python).is_absolute() {
            return Err("Python executable must be absolute".into());
        }
        let mut command = Command::new(python);
        command.args(["-m", "rlredteam.api.owned_backend"]);
        command.env("SECURITY_RL_USE_LOCAL_CONFIG", "1");
        return Ok(command);
    }
    let executable: PathBuf = resources.join("runtime/security-rl-api/security-rl-api");
    if !executable.is_file() {
        return Err("Bundled Python API runtime is missing. Reinstall the desktop package.".into());
    }
    let mut command = Command::new(executable);
    command.env_remove("PYTHONPATH").env_remove("PYTHONHOME");
    Ok(command)
}

pub fn configuration(
    resources: &Path,
    operation: &str,
    payload: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut child = runtime_command(resources)?
        .args(["--config", operation])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start bundled configuration helper")?;
    if let Some(value) = payload {
        let bytes = serde_json::to_vec(&value).map_err(|_| "Invalid settings")?;
        if bytes.len() > 32768 {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Settings too large".into());
        }
        if child.stdin.take().unwrap().write_all(&bytes).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Settings pipe failed".into());
        }
    } else {
        drop(child.stdin.take());
    }
    let output = child.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut text = String::new();
        let result = output.take(32769).read_to_string(&mut text);
        let _ = send.send(result.map(|_| text));
    });
    let result = receive.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Configuration timed out. Check whether the OS keyring is locked.".into());
    }
    let exit_result = wait_for_configuration_exit(&mut child, deadline);
    let text = result
        .unwrap()
        .map_err(|_| "Configuration response failed")?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "Invalid configuration response")?;
    if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
        return Err(error.to_string());
    }
    exit_result?;
    Ok(value)
}

fn wait_for_configuration_exit(child: &mut Child, deadline: Instant) -> Result<(), String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err("Configuration helper failed".into()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if result.is_err() {
                    "Cannot check configuration helper"
                } else {
                    "Configuration helper exit timed out"
                }.into());
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn configuration_exit_is_bounded_and_reaped() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let start = Instant::now();
        assert!(wait_for_configuration_exit(&mut child, start + Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn configuration_exit_requires_success() {
        for (program, expected) in [("true", true), ("false", false)] {
            let mut child = Command::new(program).spawn().unwrap();
            assert_eq!(wait_for_configuration_exit(&mut child, Instant::now() + Duration::from_secs(2)).is_ok(), expected);
        }
    }
}

fn healthy(port: u16, instance: &str) -> bool {
    let Ok(mut stream) =
        TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(200))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    if stream
        .write_all(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    if stream.take(16384).read_to_string(&mut response).is_err() {
        return false;
    }
    let Some((header, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    header.starts_with("HTTP/1.1 200 ")
        && value["instance"] == instance
        && value["read_only"] == true
}

impl Drop for OwnedBackend {
    fn drop(&mut self) {
        // EOF requests graceful shutdown. Child::kill targets only our owned PID.
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
