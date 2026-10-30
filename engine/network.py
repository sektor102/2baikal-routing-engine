from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from .geodata import Database
from .io import StrictLoader, load_yaml, read_json, write_json
from .model import Invalid, parse_mihomo

MAX_BYTES = 80_000_000


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def request(url, headers=None, timeout=30):
    if not url.startswith('https://'):
        raise Invalid('Only HTTPS upstream allowed')
    req=urllib.request.Request(url,headers={'User-Agent':'2Baikal-Routing/0.1',**(headers or {})})
    with urllib.request.urlopen(req,timeout=timeout) as response:
        if not response.url.startswith('https://'): raise Invalid('Insecure redirect')
        declared=response.headers.get('Content-Length')
        if declared and int(declared)>MAX_BYTES: raise Invalid('Upstream too large')
        data=response.read(MAX_BYTES+1)
        if not data or len(data)>MAX_BYTES: raise Invalid('Empty or oversize upstream')
        return data,dict(response.headers),response.url


def verify(data, source, required=()):
    if source['format'] in {'geosite','geoip'}:
        db=Database(data,source['format'])
        db.require(required)
        return db.inventory()
    import yaml
    doc=yaml.load(data.decode('utf-8-sig'),Loader=StrictLoader)
    if not isinstance(doc,dict) or not isinstance(doc.get('payload'),list) or not doc['payload']:
        raise Invalid('Invalid classical payload')
    action='DIRECT' if source['id']=='friend-direct' else 'PROXY'
    rules=[parse_mihomo(text,action,source['id']) for text in doc['payload']]
    return {'format':'classical','rules':len(rules)}


def fetch_one(source, cache, required=(), offline=False, retries=2, allow_cache_days=7):
    cache=Path(cache)
    cache.mkdir(parents=True,exist_ok=True)
    binary=cache/(source['id']+'.bin')
    metadata=cache/(source['id']+'.json')
    old=read_json(metadata) if metadata.exists() else {}
    old_data=binary.read_bytes() if binary.exists() else None
    valid_old=bool(old_data and old.get('validated') and old.get('url')==source['url'] and
                   hashlib.sha256(old_data).hexdigest()==old.get('sha256'))
    if offline:
        if not valid_old: raise Invalid(f'{source["id"]}: verified offline cache missing')
        verify(old_data,source,required)
        return {**old,'retrieval':'verified-offline-cache'}
    headers={}
    if valid_old and old.get('etag'): headers['If-None-Match']=old['etag']
    if valid_old and old.get('last_modified'): headers['If-Modified-Since']=old['last_modified']
    last_error=None
    for attempt in range(retries+1):
        try:
            commit=None
            target_url=source['url']
            active_headers=headers
            if source.get('pin-api'):
                commit_data,_,_=request(source['pin-api'])
                commit=json.loads(commit_data)
                revision=commit['sha']
                import re
                if not re.fullmatch('[0-9a-f]{40}',revision): raise Invalid('Invalid upstream commit')
                target_url=source['pin-template'].replace('{sha}',revision)
                if old.get('pinned_url')!=target_url: active_headers={}
            try:
                data,head,final_url=request(target_url,active_headers)
            except urllib.error.HTTPError as exc:
                if exc.code!=304 or not valid_old: raise
                data,head,final_url=old_data,{},old.get('final_url',source['url'])
            info=verify(data,source,required)
            sha=hashlib.sha256(data).hexdigest()
            record={**source,**info,'sha256':sha,'bytes':len(data),'checked_at':now(),
                    'verified_at':now(),'validated':True,'retrieval':'network',
                    'etag':head.get('ETag',old.get('etag')),
                    'last_modified':head.get('Last-Modified',old.get('last_modified')),
                    'final_url':final_url,'source_updated_at':head.get('Last-Modified',old.get('source_updated_at'))}
            # The historical GeoIP has no repository license. Reference a pinned upstream
            # URL instead of redistributing the database or derived GeoIP providers.
            if commit is not None:
                record.update(pinned_url=target_url,revision=revision,
                              source_updated_at=commit.get('commit',{}).get('committer',{}).get('date'))
            if valid_old and old['sha256']!=sha:
                previous=cache/(source['id']+'.previous.bin')
                previous.write_bytes(old_data)
            temp=binary.with_suffix('.pending')
            temp.write_bytes(data)
            temp.replace(binary)
            write_json(metadata,record)
            return record
        except Exception as exc:
            last_error=exc
            if attempt<retries: time.sleep(min(2**attempt,4))
    if valid_old and allow_cache_days:
        age=dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(old['verified_at'])
        if age.total_seconds()<=allow_cache_days*86400:
            verify(old_data,source,required)
            return {**old,'checked_at':now(),'retrieval':'verified-stale-cache',
                    'fetch_error':str(last_error),'cache_age_seconds':int(age.total_seconds())}
    raise Invalid(f'{source["id"]}: download/validation failed: {last_error}')


def retrieve(root, offline=False):
    root=Path(root)
    manifest=load_yaml(root/'sources/manifest.yaml')
    policy=load_yaml(root/'rules/policy.yaml')
    results=[]
    errors=[]
    for source in manifest['sources']:
        is_selected=source['id'] in manifest['selected'].values()
        required=policy[source['format']+'-required'] if is_selected else ()
        try:
            result=fetch_one(source,root/'.cache/upstream',required,offline)
            if source['format'] in {'geosite','geoip'}:
                result['missing_required']=sorted(set(policy[source['format']+'-required'])-set(result['categories']))
            results.append(result)
        except Exception as exc:
            result={**source,'checked_at':now(),'error':str(exc),'retrieval':'failed'}
            results.append(result)
            if is_selected: errors.append(str(exc))
    write_json(root/'reports/upstream.json',results)
    if errors: raise Invalid('; '.join(errors))
    return results
