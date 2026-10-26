use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::Path,
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
    pub fn start() -> Result<Self, String> {
        let python = std::env::var("SECURITY_RL_BACKEND_PYTHON")
            .map_err(|_| "Set SECURITY_RL_BACKEND_PYTHON to the container Python executable")?;
        if !Path::new(&python).is_absolute() {
            return Err("Backend executable must be an absolute path".into());
        }
        let child = Command::new(python)
            .args(["-m", "rlredteam.api.owned_backend"])
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
        owned.session = serde_json::from_str(&line)
            .map_err(|_| "Backend exited before handshake; check runtime dependencies or another desktop instance")?;
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
