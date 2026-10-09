"""Install checksum-pinned upstream AMD64 binaries during the Docker build."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import time
import urllib.request
import zipfile

manifest = json.loads(Path('/tmp/web-tools.json').read_text())
for name, package in manifest.items():
    for attempt in range(3):
        try:
            request = urllib.request.Request(package['url'], headers={'User-Agent': 'kali-mcp-build'})
            with urllib.request.urlopen(request, timeout=120) as response:
                archive = response.read()
            break
        except Exception:
            if attempt == 2:
                raise
            time.sleep(2)
    if hashlib.sha256(archive).hexdigest() != package['sha256']:
        raise RuntimeError(f'{name}: release checksum mismatch')
    if package['url'].endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            members = [item for item in source.namelist() if Path(item).name == name]
            if len(members) != 1:
                raise RuntimeError(f'{name}: expected one binary in release archive')
            binary = source.read(members[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
            members = [item for item in source.getmembers() if item.isfile() and Path(item.name).name == name]
            if len(members) != 1:
                raise RuntimeError(f'{name}: expected one binary in release archive')
            binary = source.extractfile(members[0]).read()
    destination = Path('/usr/local/bin') / name
    destination.write_bytes(binary)
    destination.chmod(0o755)
Path('/opt/kali-versions/web-tools.json').write_text(json.dumps(manifest, indent=2) + '\n')
