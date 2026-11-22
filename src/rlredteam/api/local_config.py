"""Desktop-only configuration. Public settings on disk; passwords in Secret Service.

No HTTP mutation endpoint. The owning Tauri process uses a private CLI pipe.
"""

import json
import os
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

SERVICE = "org.securityrl.analyst"
LIMIT = 32768


class ConfigurationError(ValueError):
    pass


def directory():
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / SERVICE
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ConfigurationError("Configuration directory must be owned by you with mode 0700")
    return root


def vault():
    # Explicit backend: never permit a plaintext keyring fallback.
    from keyring.backends.SecretService import Keyring

    return Keyring()


def secret(account, value=None, *, write=False):
    try:
        from .development_dbus import host_uid_authentication

        with host_uid_authentication():
            store = vault()
            if write:
                store.set_password(SERVICE, account, value)
                return None
            return store.get_password(SERVICE, account)
    except Exception:
        raise ConfigurationError(
            "OS Secret Service is locked or unavailable. Unlock your desktop keyring; "
            "database passwords will not be stored in plaintext. Offline demo needs no keyring."
        ) from None


def validate(document):
    if not isinstance(document, dict) or set(document) - {
        "version",
        "profile",
        "postgres",
        "neo4j",
        "report_ids",
        "twin_snapshot",
    }:
        raise ConfigurationError("Unsupported configuration fields")
    if document.get("version") != 1 or document.get("profile") not in {"demo", "analyst"}:
        raise ConfigurationError("Choose a supported profile and configuration version")
    if document["profile"] == "analyst" and not any(
        document.get(k) for k in ("postgres", "neo4j", "twin_snapshot")
    ):
        raise ConfigurationError(
            "Configure an analyst data source or choose the offline demo profile"
        )
    for name in ("postgres", "neo4j"):
        value = document.get(name)
        if value is None:
            continue
        expected = (
            {"host", "port", "database", "user", "sslmode"}
            if name == "postgres"
            else {"uri", "database", "user"}
        )
        if not isinstance(value, dict) or set(value) != expected:
            raise ConfigurationError(f"Invalid {name} fields")
        for key, item in value.items():
            if key == "port":
                if type(item) is not int or not 1 <= item <= 65535:
                    raise ConfigurationError("PostgreSQL port must be 1–65535")
            elif (
                not isinstance(item, str)
                or not item.strip()
                or len(item) > 512
                or any(ord(c) < 32 for c in item)
            ):
                raise ConfigurationError(f"Invalid {name} {key}")
        if name == "postgres":
            if value["sslmode"] not in {"verify-full", "require", "disable"}:
                raise ConfigurationError("Unsupported PostgreSQL TLS setting")
            if (
                value["host"] not in {"localhost", "127.0.0.1", "::1"}
                and value["sslmode"] != "verify-full"
            ):
                raise ConfigurationError("Remote PostgreSQL requires verify-full TLS")
        else:
            try:
                uri = urlsplit(value["uri"])
                port = uri.port
            except ValueError:
                raise ConfigurationError("Invalid Neo4j URI") from None
            if (
                uri.scheme not in {"bolt", "neo4j", "bolt+s", "neo4j+s"}
                or not uri.hostname
                or uri.username
                or uri.password
                or uri.query
                or uri.fragment
                or uri.path not in {"", "/"}
            ):
                raise ConfigurationError(
                    "Neo4j URI must contain only a supported scheme, host and port"
                )
            if port is not None and not 1 <= port <= 65535:
                raise ConfigurationError("Invalid Neo4j port")
            if uri.hostname not in {"localhost", "127.0.0.1", "::1"} and not uri.scheme.endswith(
                "+s"
            ):
                raise ConfigurationError("Remote Neo4j requires certificate-verified TLS (+s)")
    ids = document.get("report_ids", [])
    if (
        not isinstance(ids, list)
        or len(ids) > 50
        or any(
            not isinstance(v, str)
            or not v
            or len(v) > 256
            or any(c.isspace() or c == "," for c in v)
            for v in ids
        )
    ):
        raise ConfigurationError("Select at most 50 explicit report IDs")
    snapshot = document.get("twin_snapshot")
    if snapshot:
        if not isinstance(snapshot, str) or not Path(snapshot).is_absolute():
            raise ConfigurationError("Twin snapshot must be an absolute path")
        from rlredteam.application.analyst_readers import SnapshotReader

        try:
            SnapshotReader(snapshot).read()
        except Exception:
            raise ConfigurationError("Twin snapshot is missing, unreadable or invalid") from None
    return document


def read():
    path = directory() / "settings.json"
    if not path.exists() and not path.is_symlink():
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ConfigurationError("Settings file must be owned by you with mode 0600")
        content = stream.read(LIMIT + 1)
    if len(content) > LIMIT:
        raise ConfigurationError("Settings file exceeds the size limit")
    try:
        return validate(json.loads(content))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ConfigurationError(
            "Settings JSON is invalid; open configuration to repair it"
        ) from None


def save(payload):
    if not isinstance(payload, dict) or set(payload) - {"settings", "passwords"}:
        raise ConfigurationError("Invalid settings request")
    settings = validate(payload.get("settings"))
    passwords = payload.get("passwords", {})
    if not isinstance(passwords, dict) or set(passwords) - {"postgres", "neo4j"}:
        raise ConfigurationError("Invalid credential fields")
    if any(
        not isinstance(value, str) or len(value) > 4096 or "\x00" in value
        for value in passwords.values()
    ):
        raise ConfigurationError("Invalid password value")
    # Store per connection identity so a changed host cannot inherit another password.
    for name in ("postgres", "neo4j"):
        if settings.get(name) is not None:
            account = account_id(name, settings[name])
            password = passwords.get(name)
            if password:
                secret(account, password, write=True)
                if secret(account) != password:
                    raise ConfigurationError(
                        f"Saved {name} credential could not be verified. Re-enter it in Settings."
                    )
            elif not secret(account):
                raise ConfigurationError(
                    f"Enter the {name} password for these exact settings; "
                    "no matching saved credential exists."
                )
    root = directory()
    fd, temporary = tempfile.mkstemp(prefix="settings-", dir=root)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(settings, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, root / "settings.json")
        dir_fd = os.open(root, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    persisted = read()
    if persisted != settings:
        raise ConfigurationError("Saved settings could not be verified. Reopen Settings before checking connections.")
    return {"configured": True, "settings": persisted,
            "settings_path": str(root / "settings.json")}


def account_id(name, settings):
    import hashlib

    return name + ":" + hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()


def required_secret(name, settings):
    value = secret(account_id(name, settings))
    if not value:
        raise ConfigurationError(
            f"Saved {name} credential is unavailable. Re-enter it in Settings."
        )
    return value


def activate(*, load_credentials=True):
    settings = read()
    if settings is None:
        raise ConfigurationError("First-run setup required: choose a profile in desktop settings")
    for key in list(os.environ):
        if key.startswith(("POSTGRES_", "NEO4J_", "PG")) or key in {
            "SECURITY_RL_ANALYST_REPORT_IDS",
            "SECURITY_RL_TWIN_SNAPSHOT",
        }:
            del os.environ[key]
    os.environ["SECURITY_RL_PROFILE"] = settings["profile"]
    pg = settings.get("postgres")
    if pg:
        for key, value in {
            "HOST": pg["host"],
            "PORT": str(pg["port"]),
            "DB": pg["database"],
            "USER": pg["user"],
            "SSLMODE": pg["sslmode"],
        }.items():
            os.environ["POSTGRES_" + key] = value
        if load_credentials:
            os.environ["POSTGRES_PASSWORD"] = required_secret("postgres", pg)
    neo = settings.get("neo4j")
    if neo:
        for key, value in {
            "URI": neo["uri"],
            "DATABASE": neo["database"],
            "USER": neo["user"],
        }.items():
            os.environ["NEO4J_" + key] = value
        if load_credentials:
            os.environ["NEO4J_PASSWORD"] = required_secret("neo4j", neo)
    os.environ["SECURITY_RL_ANALYST_REPORT_IDS"] = ",".join(settings.get("report_ids", []))
    if settings.get("twin_snapshot"):
        os.environ["SECURITY_RL_TWIN_SNAPSHOT"] = settings["twin_snapshot"]
    return settings


def connection_failure(error):
    """Classify locally, returning fixed messages only; never expose driver text."""
    if isinstance(error, ConfigurationError):
        if str(error).startswith("Saved "):
            return "UNAVAILABLE [KEYRING_CREDENTIAL_MISSING]: Re-enter this connection's password in Settings."
        return "UNAVAILABLE [KEYRING_UNAVAILABLE]: Unlock the OS Secret Service and retry."
    chain = []
    current = error
    for _ in range(5):
        if current is None or any(current is item for item in chain):
            break
        chain.append(current)
        current = current.__cause__ or current.__context__
    codes = {str(getattr(item, "code", "")) for item in chain}
    states = {getattr(item, "sqlstate", None) for item in chain}
    names = {type(item).__name__ for item in chain}
    text = " ".join(str(item).lower() for item in chain)
    if any(code.endswith("AuthenticationRateLimit") for code in codes):
        return "UNAVAILABLE [AUTHENTICATION_RATE_LIMITED]: Wait before retrying with the correct saved password."
    if (states & {"28P01", "28000"} or "AuthError" in names
            or any(code.endswith(("Unauthorized", "AuthenticationError")) for code in codes)
            or "password authentication failed" in text or "authentication failed" in text):
        return "UNAVAILABLE [AUTHENTICATION_FAILED]: Re-enter the correct database password in Settings."
    if ("3D000" in states or any(code.endswith("DatabaseNotFound") for code in codes)
            or ("database" in text and "does not exist" in text)):
        return "UNAVAILABLE [DATABASE_NOT_FOUND]: Check the saved database name."
    if ("42501" in states or any(code.endswith("Forbidden") for code in codes)
            or "permission denied" in text or "pg_hba.conf" in text):
        return "UNAVAILABLE [PERMISSION_DENIED]: Check database access and read permissions."
    if (names & {"SSLError", "SSLCertVerificationError", "CertificateError", "CertificateConfigurationError"}
            or any(word in text for word in ("certificate", "tls", "ssl connection", "ssl error", "sslmode"))):
        return "UNAVAILABLE [TLS_FAILED]: Check TLS mode and trusted certificates."
    if (names & {"ServiceUnavailable", "SessionExpired", "gaierror", "ConnectionRefusedError", "TimeoutError"}
            or any(word in text for word in ("connection refused", "connection failed", "timed out",
                "timeout", "resolve", "translate host", "name or service not known"))):
        return "UNAVAILABLE [ADDRESS_UNREACHABLE]: Check the saved address, port and service availability."
    return "UNAVAILABLE [CONNECTION_FAILED]: Connection check failed; driver details are withheld."


def connection_checks():
    # Saved settings define addresses/TLS. Read each credential independently so
    # one missing keyring entry cannot hide the other database's actual status.
    settings = activate(load_credentials=False)
    checks = {}
    if settings.get("postgres"):
        try:
            from .services import ReadOnlyRepository

            os.environ["POSTGRES_PASSWORD"] = required_secret("postgres", settings["postgres"])
            with ReadOnlyRepository()._connect() as connection:
                connection.execute("SELECT 1")
            checks["postgres"] = "CONNECTED (read-only session)"
        except Exception as error:
            checks["postgres"] = connection_failure(error)
    if settings.get("neo4j"):
        try:
            from neo4j import GraphDatabase

            os.environ["NEO4J_PASSWORD"] = required_secret("neo4j", settings["neo4j"])
            with GraphDatabase.driver(
                os.environ["NEO4J_URI"],
                auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]),
                connection_timeout=3,
                connection_acquisition_timeout=4,
            ) as driver:
                with driver.session(
                    database=os.environ["NEO4J_DATABASE"], default_access_mode="READ"
                ) as session:
                    session.run("RETURN 1").consume()
            checks["neo4j"] = "CONNECTED (read query)"
        except Exception as error:
            checks["neo4j"] = connection_failure(error)
    return {"checks": checks, "offline": not checks}


def neo4j_diagnostic():
    """Test only the saved desktop connection, without publishing or changing settings."""
    import socket
    from urllib.parse import urlsplit
    from neo4j import GraphDatabase

    stages = dict.fromkeys(("Settings loaded", "Configured", "URI parsed", "Username present",
                            "Credential available", "TCP reachable", "Bolt reachable",
                            "Authenticated", "Database accessible", "Read query",
                            "Projection metadata readable"), "Not tested")
    try:
        settings = read()
        stages["Settings loaded"] = "Passed" if settings else "Missing"
        neo = (settings or {}).get("neo4j")
        if not neo:
            stages["Configured"] = "Missing"
            return {"stages": stages}
        stages["Configured"] = "Passed"
        uri = urlsplit(neo["uri"])
        stages["URI parsed"] = "Passed"
        stages["Username present"] = "Passed" if neo["user"] else "Missing"
        credential = required_secret("neo4j", neo)
        stages["Credential available"] = "Passed"
        with socket.create_connection((uri.hostname, uri.port or 7687), timeout=3):
            stages["TCP reachable"] = "Passed"
        with GraphDatabase.driver(neo["uri"], auth=(neo["user"], credential),
                                  connection_timeout=3, connection_acquisition_timeout=4) as driver:
            driver.get_server_info()
            stages["Bolt reachable"] = stages["Authenticated"] = "Passed"
            with driver.session(database=neo["database"], default_access_mode="READ") as session:
                if session.run("RETURN 1 AS available").single(strict=True)["available"] != 1:
                    raise ValueError("Read query failed")
                stages["Database accessible"] = stages["Read query"] = "Passed"
                row = session.run("MATCH (g:CausalProjection) RETURN count(g) AS n").single(strict=True)
                stages["Projection metadata readable"] = "Passed"
                return {"stages": stages, "projection_count": row["n"]}
    except Exception as exc:
        if type(exc).__name__ == "AuthError":
            stages["Bolt reachable"] = "Passed"
        pending = next((key for key, value in stages.items() if value == "Not tested"), None)
        if pending:
            stages[pending] = "Failed"
        return {"stages": stages, "reason": connection_failure(exc)}


def command(operation, payload=None):
    if operation == "get":
        settings = read()
        return {"configured": settings is not None, "settings": settings,
                "settings_path": str(directory() / "settings.json")}
    if operation == "save":
        return save(payload)
    if operation == "check":
        if payload == {"diagnostic": "neo4j"}:
            return neo4j_diagnostic()
        return connection_checks()
    raise ConfigurationError("Unsupported configuration operation")
