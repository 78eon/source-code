import json
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_dynamic_libs, copy_metadata
from PyInstaller.config import CONF

root = Path(SPECPATH).parent
repo = root.parent
a = Analysis(
    [str(root / 'packaging/backend_entry.py')],
    pathex=[str(repo / 'src')],
    binaries=collect_dynamic_libs('psycopg_binary'),
    datas=[(str(repo / 'configs/catalogues/mitre.yaml'), 'assets')] + copy_metadata('keyring'),
    hiddenimports=collect_submodules('uvicorn') + ['psycopg_binary', 'keyring.backends.SecretService'],
    excludes=['PySide6', 'PyQt5', 'PyQt6', 'tkinter', 'torch', 'stable_baselines3', 'nasim',
              'gymnasium', 'numpy', 'matplotlib', 'pandas', 'pytest', 'rlredteam.application.backend',
              'rlredteam.train', 'rlredteam.enterprise', 'rlredteam.attack_path_report'],
    noarchive=False,
)
names = sorted(row[0] for row in a.pure)
allowed = ('rlredteam.api', 'rlredteam.application.data', 'rlredteam.application.analyst_readers',
           'rlredteam.causal_graph', 'rlredteam.storage', 'rlredteam.digital_twin',
           'rlredteam.evidence', 'rlredteam.knowledge', 'rlredteam.catalogues', 'rlredteam.frameworks',
           'rlredteam.research_boundaries')  # Provenance enum only; no campaign behavior/data.
for name in names:
    if name.startswith('rlredteam.') and name not in ('rlredteam.application',) and not name.startswith(allowed):
        raise RuntimeError('Unexpected application module in package: ' + name)
manifest = Path(CONF['workpath']) / 'module-manifest.json'
manifest.write_text(json.dumps(names, indent=2))
a.datas.append(('module-manifest.json', str(manifest), 'DATA'))
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='security-rl-api',
          debug=False, strip=False, upx=False, console=True)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='security-rl-api')
