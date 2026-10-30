"""Prepare/restore/publish immutable Releases. Draft upload, then promote latest."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from engine.io import digest,read_json,write_json
from engine.model import Invalid
from engine.compiler import scan_secrets


def api(path,method='GET',body=None,raw=None):
    token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    headers={'User-Agent':'2Baikal-Routing/0.1','Accept':'application/vnd.github+json',
             'X-GitHub-Api-Version':'2022-11-28'}
    if token: headers['Authorization']='Bearer '+token
    data=json.dumps(body).encode() if body is not None else raw
    if data is not None: headers['Content-Type']='application/json' if raw is None else 'application/octet-stream'
    url=path if path.startswith('https://') else 'https://api.github.com'+path
    if urllib.parse.urlsplit(url).hostname not in {'api.github.com','uploads.github.com'}:
        raise Invalid('Refusing authenticated request outside GitHub API/upload hosts')
    with urllib.request.urlopen(urllib.request.Request(url,data=data,headers=headers,method=method),timeout=90) as response:
        data=response.read(100_000_000)
        return json.loads(data) if 'json' in response.headers.get('Content-Type','') else data


def restore(repository):
    try: latest=api('/repos/'+repository+'/releases/latest')
    except urllib.error.HTTPError as exc:
        if exc.code!=404: raise
        print('No previous published release')
        return
    asset=next((a for a in latest['assets'] if a['name']=='release.json'),None)
    if asset is None:
        raise Invalid('Latest release lacks engine release.json; cannot use as verified baseline')
    # Public repository assets contain no token in the download URL.
    with urllib.request.urlopen(asset['browser_download_url'],timeout=30) as response: raw=response.read(5_000_001)
    if len(raw)>5_000_000: raise Invalid('Previous metadata too large')
    previous=json.loads(raw)
    if previous.get('version')!=latest['tag_name']: raise Invalid('Previous version/tag mismatch')
    write_json(ROOT/'.previous-release/release.json',previous)
    print('Previous release:',previous['version'])


def prepare():
    dist=ROOT/'dist'
    metadata=read_json(dist/'release.json')
    validation=read_json(ROOT/'reports/validation.json')
    if validation.get('artifact_tree_sha256')!=digest(dist/'SHA256SUMS'):
        raise Invalid('Validation does not belong to this artifact tree')
    if validation.get('golden_failures') or validation.get('schema')!='passed':
        raise Invalid('Routing/schema validation missing')
    if not isinstance(validation.get('mihomo'),list) or not isinstance(validation.get('xray'),dict):
        raise Invalid('Both native binary checks required')
    for row in validation['mihomo']:
        if row['returncode']: raise Invalid('Mihomo validation failed')
    if validation['xray']['returncode']: raise Invalid('Xray validation failed')
    declared=set()
    for line in (dist/'SHA256SUMS').read_text().splitlines():
        sha,relative=line.split('  ',1)
        path=dist/relative
        if not path.resolve().is_relative_to(dist.resolve()) or digest(path)!=sha:
            raise Invalid('Artifact modified after validation: '+relative)
        declared.add(relative)
    actual={f.relative_to(dist).as_posix() for f in dist.rglob('*') if f.is_file()}-{'SHA256SUMS'}
    if actual!=declared: raise Invalid('Unexpected or missing artifact files')
    scan_secrets(dist)
    dest=ROOT/'release-assets'
    if dest.exists(): shutil.rmtree(dest)
    dest.mkdir()
    names={'happ/routing.json':'happ-routing.json','happ/import-link.txt':'happ-import-link.txt',
           'mihomo/config.yaml':'mihomo-config.yaml','mihomo/config-doh-optional.yaml':'mihomo-config-doh-optional.yaml'}
    for file in sorted(dist.rglob('*')):
        if not file.is_file() or file.name=='SHA256SUMS': continue
        rel=file.relative_to(dist).as_posix()
        name=names.get(rel,file.name)
        if (dest/name).exists(): raise Invalid('Release asset filename collision: '+name)
        shutil.copyfile(file,dest/name)
    shutil.copyfile(ROOT/'reports/validation.json',dest/'validation.json')
    for name in ['coverage-diff.json','changelog.md','twitter.json','category-overlaps.json','provider-diff.json','personal-route-collisions.json']:
        if (ROOT/'reports'/name).exists(): shutil.copyfile(ROOT/'reports'/name,dest/name)
    for name in ['LICENSE','THIRD_PARTY_NOTICES.md']:
        if (ROOT/name).exists(): shutil.copyfile(ROOT/name,dest/name)
    with zipfile.ZipFile(dest/'2baikal-routing.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(dist.rglob('*')):
            if file.is_file(): archive.write(file,file.relative_to(dist).as_posix())
    sums=''.join(f'{digest(file)}  {file.name}\n' for file in sorted(dest.iterdir()))
    (dest/'SHA256SUMS').write_text(sums,encoding='utf-8',newline='\n')
    print('Prepared',len(list(dest.iterdir())),'validated release assets')
    return metadata,dest


def publish(repository,commit):
    meta,dest=prepare()
    if not meta.get('publishable') or meta.get('repository')!=repository:
        raise Invalid('Unhosted or wrong-repository candidate')
    head=api('/repos/'+repository+'/git/ref/heads/main')['object']['sha']
    if head!=commit: raise Invalid('main moved during build; refusing stale publication')
    result=read_json(ROOT/'reports/build-result.json')
    if not result['changed']:
        print('Payload unchanged; no release, no LastUpdated change')
        return
    tag=meta['version']
    try:
        existing=api('/repos/'+repository+'/releases/tags/'+tag)
    except urllib.error.HTTPError as exc:
        if exc.code!=404: raise
        existing=None
    if existing and not existing['draft']:
        print('Immutable version already published:',existing['html_url'])
        return
    if existing:
        # Do not overwrite partially uploaded drafts automatically. A maintainer
        # can inspect/remove the draft and retry; the previous latest stays valid.
        raise Invalid('Incomplete draft exists; inspect it before retry')
    body=('Verified DEFAULT DIRECT routing for HAPP iOS and Mihomo Windows.\n\n'
          f"{meta['counts']['personal']} personal input rules; binaries and golden routing validated.\n\n"
          'See validation.json, baseline.json, conflicts.json, review.json and SHA256SUMS.\n'
          'HAPP changes require import and reconnect; native iOS device test remains manual.')
    release=api('/repos/'+repository+'/releases','POST',
                {'tag_name':tag,'target_commitish':commit,'name':'2Baikal '+tag,
                 'body':body,'draft':True,'prerelease':False})
    upload=release['upload_url'].split('{',1)[0]
    for file in sorted(dest.iterdir()):
        asset=api(upload+'?name='+urllib.parse.quote(file.name),'POST',raw=file.read_bytes())
        if asset.get('size')!=file.stat().st_size: raise Invalid('Upload size mismatch')
        if asset.get('digest') and asset['digest']!='sha256:'+digest(file): raise Invalid('Upload checksum mismatch')
    published=api('/repos/'+repository+'/releases/'+str(release['id']),'PATCH',{'draft':False,'make_latest':'true'})
    print('Published:',published['html_url'])


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('operation',choices=['restore','prepare','publish'])
    parser.add_argument('--repository',default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--commit',default=os.environ.get('SOURCE_SHA'))
    args=parser.parse_args()
    if args.operation=='restore': restore(args.repository)
    elif args.operation=='prepare': prepare()
    else:
        if not args.commit: raise Invalid('Explicit source commit required')
        publish(args.repository,args.commit)
