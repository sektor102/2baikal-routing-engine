"""Install pinned official binaries; no system installation or PATH changes."""
import gzip
import hashlib
import io
import json
import os
import pathlib
import platform
import sys
import urllib.request
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]


def install():
    data=json.loads((ROOT/'sources/toolchain.json').read_text())
    osname='windows' if os.name=='nt' else 'linux'
    if platform.machine().lower() not in {'amd64','x86_64'}:
        raise RuntimeError('Pinned toolchain currently supports x86_64 Windows/Linux only')
    dest=ROOT/'.cache/tools'
    dest.mkdir(parents=True,exist_ok=True)
    for repo,name in [('MetaCubeX/mihomo','mihomo'),('XTLS/Xray-core','xray')]:
        asset=next(a for a in data[repo]['assets'] if osname in a['name'].lower())
        archive=dest/asset['name']
        if not archive.exists() or 'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()!=asset['digest']:
            request=urllib.request.Request(asset['browser_download_url'],headers={'User-Agent':'2Baikal-Routing/0.1'})
            with urllib.request.urlopen(request,timeout=90) as response:
                raw=response.read(100_000_001)
            if len(raw)>100_000_000 or 'sha256:'+hashlib.sha256(raw).hexdigest()!=asset['digest']:
                raise RuntimeError('Official binary digest mismatch')
            archive.write_bytes(raw)
        raw=archive.read_bytes()
        target=dest/(name+('.exe' if os.name=='nt' else ''))
        if asset['name'].endswith('.gz'):
            target.write_bytes(gzip.decompress(raw))
        else:
            with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
                member=next(n for n in zipped.namelist() if pathlib.PurePosixPath(n).name==target.name or
                            (name=='mihomo' and n.endswith('.exe')))
                target.write_bytes(zipped.read(member))
        if os.name!='nt': target.chmod(0o755)
        print(name,data[repo]['version'],asset['digest'],str(target.relative_to(ROOT)))


if __name__=='__main__': install()
