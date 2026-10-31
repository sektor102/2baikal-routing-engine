"""Sync verified Release profiles to Remnawave 3.4.x without exposing its token."""
import argparse
import base64
import binascii
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from engine.io import digest,read_json,validate_happ
from engine.model import Invalid
from scripts.release import api as github_api

FILES={'pc':'mihomo-config.yaml','router':'mihomo-router-config.yaml','happ':'happ-import-link.txt'}
SECRETS=('REMNAWAVE_URL','REMNAWAVE_API_TOKEN','REMNAWAVE_MIHOMO_TEMPLATE_UUID',
         'REMNAWAVE_ROUTER_TEMPLATE_UUID')


def valid_uuid(value):
    try: return str(uuid.UUID(value))
    except (ValueError,TypeError,AttributeError): raise Invalid('Invalid template/settings UUID') from None


def happ_profile(link):
    if not isinstance(link,str) or not link.startswith('happ://routing/add/'):
        raise Invalid('Expected a complete happ://routing/add/ link')
    try:
        profile=json.loads(base64.b64decode(link.split('/add/',1)[1],validate=True))
        validate_happ(profile)
        int(profile['LastUpdated'])
        return profile
    except (ValueError,KeyError,TypeError,binascii.Error):
        raise Invalid('Invalid HAPP routing payload') from None


def routing_header(headers):
    keys=[key for key in headers if key.lower()=='routing']
    if len(keys)>1: raise Invalid('Duplicate routing headers in panel')
    return (keys[0],headers[keys[0]]) if keys else ('routing',None)


def desired_headers(settings,link):
    headers=settings.get('customResponseHeaders') or {}
    if not isinstance(headers,dict) or any(not isinstance(v,str) for v in headers.values()):
        raise Invalid('Unexpected customResponseHeaders format')
    headers=dict(headers)
    key,old=routing_header(headers)
    incoming=happ_profile(link)
    if old:
        current=happ_profile(old)
        if current['Name']!=incoming['Name']:
            raise Invalid('Panel routing belongs to another HAPP profile')
        if int(current['LastUpdated'])>int(incoming['LastUpdated']):
            raise Invalid('Panel HAPP profile is newer; refusing rollback')
    headers[key]=link
    return headers


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise Invalid('Refusing panel API redirect; use its direct HTTPS URL')


class Panel:
    def __init__(self,url,token):
        parsed=urllib.parse.urlsplit(url)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in {'','/'}):
            raise Invalid('REMNAWAVE_URL must be a direct HTTPS origin without path/query')
        if not token or any(c.isspace() for c in token): raise Invalid('Invalid API token format')
        self.origin=url.rstrip('/')
        self.token=token
        self.opener=urllib.request.build_opener(NoRedirect())

    def request(self,path,method='GET',body=None):
        if not re.fullmatch(r'/subscription-(?:settings|templates(?:/[0-9a-f-]{36})?)',path):
            raise Invalid('Unexpected panel API path')
        data=json.dumps(body,ensure_ascii=False).encode() if body is not None else None
        request=urllib.request.Request(self.origin+'/api'+path,data=data,method=method,
            headers={'Authorization':'Bearer '+self.token,'Accept':'application/json',
                     'Content-Type':'application/json','User-Agent':'2Baikal-Routing-Sync/1'})
        try:
            with self.opener.open(request,timeout=30) as response:
                raw=response.read(4_000_001)
                if len(raw)>4_000_000: raise Invalid('Panel API response too large')
                parsed=json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise Invalid(f'Panel {method} {path}: HTTP {exc.code}') from None
        except (urllib.error.URLError,TimeoutError,OSError):
            raise Invalid(f'Panel {method} {path}: connection failed') from None
        except Invalid:
            raise
        except (ValueError,UnicodeError):
            raise Invalid('Panel returned a non-JSON response') from None
        if not isinstance(parsed,dict) or not isinstance(parsed.get('response'),dict):
            raise Invalid('Unexpected panel API response envelope')
        return parsed['response']


def verified_candidate(repository,commit,assets):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository or ''):
        raise Invalid('Explicit owner/repository required')
    if not re.fullmatch(r'[0-9a-f]{40}',commit or ''): raise Invalid('Explicit source commit required')
    meta=read_json(assets/'release.json')
    if meta.get('repository')!=repository or not meta.get('publishable'):
        raise Invalid('Candidate is not publishable for this repository')
    if github_api('/repos/'+repository+'/git/ref/heads/main')['object']['sha']!=commit:
        raise Invalid('main moved; refusing stale panel synchronization')
    published=github_api('/repos/'+repository+'/releases/latest')
    if published.get('draft') or published.get('prerelease') or published.get('tag_name')!=meta['version']:
        raise Invalid('Candidate is not the latest published stable Release')
    result={}
    for role,name in FILES.items():
        file=assets/name
        matches=[a for a in published['assets'] if a['name']==name]
        if (len(matches)!=1 or matches[0].get('digest')!='sha256:'+digest(file)
                or matches[0].get('size')!=file.stat().st_size):
            raise Invalid('Published asset checksum mismatch: '+name)
        result[role]=file.read_bytes().decode('utf-8')
    result['happ']=result['happ'].strip()
    happ_profile(result['happ'])
    result['version']=meta['version']
    return result


def template_content(panel,template_id):
    template=panel.request('/subscription-templates/'+template_id)
    if template.get('uuid')!=template_id or template.get('templateType')!='MIHOMO':
        raise Invalid('Target is not the configured MIHOMO template')
    encoded=template.get('encodedTemplateYaml')
    if not isinstance(encoded,str): raise Invalid('Template lacks encoded YAML')
    try: base64.b64decode(encoded,validate=True).decode('utf-8')
    except (ValueError,UnicodeError,binascii.Error): raise Invalid('Invalid existing template encoding') from None
    return encoded


def synchronize(panel,candidate,pc_id,router_id,dry_run=False):
    ids={'pc':valid_uuid(pc_id),'router':valid_uuid(router_id)}
    if ids['pc']==ids['router']: raise Invalid('PC and Router must use separate templates')
    before={role:template_content(panel,key) for role,key in ids.items()}
    after={role:base64.b64encode(candidate[role].encode()).decode() for role in ids}
    settings=panel.request('/subscription-settings')
    valid_uuid(settings.get('uuid'))
    headers=desired_headers(settings,candidate['happ'])
    changes={role:before[role]!=after[role] for role in ids}
    changes['happ']=headers!=(settings.get('customResponseHeaders') or {})
    if dry_run or not any(changes.values()): return changes
    attempted=[]
    header_before=None
    try:
        for role,key in ids.items():
            if not changes[role]: continue
            if template_content(panel,key)!=before[role]: raise Invalid('Template edited concurrently')
            attempted.append(role)
            panel.request('/subscription-templates','PATCH',{'uuid':key,'encodedTemplateYaml':after[role]})
            if template_content(panel,key)!=after[role]: raise Invalid('Template read-back mismatch')
        # Re-read immediately before merging to preserve unrelated header edits.
        settings=panel.request('/subscription-settings')
        valid_uuid(settings.get('uuid'))
        headers=desired_headers(settings,candidate['happ'])
        if headers!=(settings.get('customResponseHeaders') or {}):
            header_before=routing_header(settings.get('customResponseHeaders') or {})
            attempted.append('happ')
            panel.request('/subscription-settings','PATCH',{'uuid':settings['uuid'],'customResponseHeaders':headers})
            checked=panel.request('/subscription-settings')
            if routing_header(checked.get('customResponseHeaders') or {})[1]!=candidate['happ']:
                raise Invalid('HAPP header read-back mismatch')
    except Exception:
        rollback_errors=[]
        for role in reversed(attempted):
            try:
                if role=='happ':
                    current=panel.request('/subscription-settings')
                    restored=dict(current.get('customResponseHeaders') or {})
                    key,value=routing_header(restored)
                    if value==candidate['happ']:
                        restored.pop(key,None)
                        if header_before[1] is not None: restored[header_before[0]]=header_before[1]
                        panel.request('/subscription-settings','PATCH',{'uuid':current['uuid'],'customResponseHeaders':restored})
                    elif value!=header_before[1]: raise Invalid('Header edited during rollback')
                    if routing_header(panel.request('/subscription-settings').get('customResponseHeaders') or {})[1]!=header_before[1]:
                        raise Invalid('Header rollback read-back mismatch')
                else:
                    current=template_content(panel,ids[role])
                    if current==after[role]:
                        panel.request('/subscription-templates','PATCH',{'uuid':ids[role],'encodedTemplateYaml':before[role]})
                    elif current!=before[role]: raise Invalid('Template edited during rollback')
                    if template_content(panel,ids[role])!=before[role]: raise Invalid('Template rollback read-back mismatch')
            except Exception: rollback_errors.append(role)
        if rollback_errors: raise Invalid('Sync failed; rollback incomplete for '+', '.join(rollback_errors)) from None
        print('Sync failed; previous profile values restored',file=sys.stderr)
        raise
    return changes


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--commit',default=os.environ.get('SOURCE_SHA'))
    parser.add_argument('--assets',type=pathlib.Path,default=ROOT/'release-assets')
    parser.add_argument('--if-configured',action='store_true')
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    configured={key:os.environ.get(key,'') for key in SECRETS}
    if not any(configured.values()) and args.if_configured:
        print('Remnawave sync not configured; Release is available for manual import')
        return
    missing=[key for key,value in configured.items() if not value]
    if missing: raise Invalid('Missing GitHub Secrets: '+', '.join(missing))
    candidate=verified_candidate(args.repository,args.commit,args.assets)
    panel=Panel(configured['REMNAWAVE_URL'],configured['REMNAWAVE_API_TOKEN'])
    changes=synchronize(panel,candidate,configured['REMNAWAVE_MIHOMO_TEMPLATE_UUID'],
                        configured['REMNAWAVE_ROUTER_TEMPLATE_UUID'],args.dry_run)
    print(json.dumps({'version':candidate['version'],'dry_run':args.dry_run,'changes':changes}))


if __name__=='__main__':
    try: main()
    except Invalid as exc:
        print('ERROR: '+str(exc),file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError,TimeoutError,OSError):
        print('ERROR: GitHub/network request failed',file=sys.stderr)
        sys.exit(1)
