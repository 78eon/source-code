"""Browser acceptance runner: explicit read-only evidence mount, --network none only."""

import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request


def main():
    root=os.environ.get('SECURITY_RL_REGISTERED_CAMPAIGN')
    if not root or not Path(root).is_dir():
        raise RuntimeError('An explicit read-only registered campaign mount is required')
    # Never forward database, keyring, engineering state or workspace configuration.
    env={k:os.environ[k] for k in ('PATH','HOME','PYTHONPATH','PYTHONDONTWRITEBYTECODE') if k in os.environ}
    env.update(SECURITY_RL_REGISTERED_CAMPAIGN=root,SECURITY_RL_API_TOKEN=secrets.token_hex(32),
               SECURITY_RL_RESEARCH_TRAJECTORY_E2E='1',
               SECURITY_RL_RESEARCH_TRAJECTORY_E2E_OUTPUT=os.environ.get('SECURITY_RL_RESEARCH_TRAJECTORY_E2E_OUTPUT','/tmp/research-trajectory-e2e'))
    server=subprocess.Popen([sys.executable,'-B','-m','uvicorn','rlredteam.api.app:create_app','--factory',
                             '--host','127.0.0.1','--port','8765','--no-access-log'],env=env,
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if server.poll() is not None:raise RuntimeError('Read-only research API exited')
            try:
                with urllib.request.urlopen('http://127.0.0.1:8765/api/health',timeout=1):break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('Read-only research API did not become ready')
        return subprocess.call(['npx','--no-install','playwright','test','e2e/research-trajectories.spec.ts',
                                '--output=/tmp/research-trajectory-playwright-results'],cwd=Path(__file__).parent,env=env)
    finally:
        server.terminate()
        try:server.wait(timeout=10)
        except subprocess.TimeoutExpired:server.kill();server.wait()


if __name__=='__main__':
    raise SystemExit(main())
