"""Inspect the actual frozen archive and resource tree before bundling."""

import hashlib
import json
from pathlib import Path

from PyInstaller.archive.readers import CArchiveReader

root = Path("src-tauri/runtime/security-rl-api")
archive = CArchiveReader(str(root / "security-rl-api"))
modules = sorted(archive.open_embedded_archive("PYZ.pyz").toc)
for name in modules:
    assert not name.lower().startswith(
        (
            "pyside",
            "pyqt",
            "torch",
            "nasim",
            "stable_baselines3",
            "rlredteam.train",
            "rlredteam.enterprise",
            "rlredteam.application.backend",
        )
    ), name
files = {}
for path in root.rglob("*"):
    if not path.is_file():
        continue
    relative = path.relative_to(root)
    assert not {"docs", "runs", "results", ".git", "checkpoints", "tests"} & set(
        relative.parts
    ), relative
    assert path.suffix not in {".pt", ".pth", ".sqlite", ".sqlite3"}, relative
    assert "pyside" not in str(relative).lower() and "pyqt" not in str(relative).lower(), relative
    if path.suffix in {".yaml", ".yml"}:
        assert str(relative) == "_internal/assets/mitre.yaml", relative
    files[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
assert (root / "_internal/libpython3.11.so.1.0").is_file()
report = {
    "module_count": len(modules),
    "application_modules": [m for m in modules if m.startswith("rlredteam")],
    "files_sha256": files,
    "pyside_present": False,
    "campaign_artifacts_present": False,
}
Path("packaging/build/bundle-audit.json").write_text(json.dumps(report, indent=2))
print(
    f"BUNDLE_AUDIT_PASS: {len(modules)} modules, {len(files)} files; "
    "Python included; no Qt/PySide or campaign artifacts"
)
