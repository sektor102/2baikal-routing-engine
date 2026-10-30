from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from .model import Invalid, parse_happ, parse_mihomo


class StrictLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for keynode, valnode in node.value:
        key = loader.construct_object(keynode,deep=deep)
        if key in result:
            raise Invalid(f'Duplicate YAML key: {key}')
        result[key] = loader.construct_object(valnode,deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)


def load_yaml(path):
    try:
        return yaml.load(Path(path).read_text(encoding='utf-8-sig'),Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise Invalid(f'Invalid YAML: {path}') from exc


def read_json(path):
    def pairs(items):
        out = {}
        for key,value in items:
            if key in out: raise Invalid(f'Duplicate JSON key: {key}')
            out[key]=value
        return out
    return json.loads(Path(path).read_text(encoding='utf-8-sig'),object_pairs_hook=pairs)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_happ(doc):
    required = {'Name','GlobalProxy','RouteOrder','RemoteDNSType','RemoteDNSDomain','RemoteDNSIP',
                'DomesticDNSType','DomesticDNSDomain','DomesticDNSIP','Geoipurl','Geositeurl',
                'LastUpdated','DnsHosts','DomainStrategy','UseChunkFiles','DirectSites','DirectIp',
                'ProxySites','ProxyIp','BlockSites','BlockIp'}
    if not isinstance(doc,dict) or required-doc.keys():
        raise Invalid(f'Missing HAPP keys: {required-set(doc if isinstance(doc,dict) else [])}')
    if doc['GlobalProxy'] != 'false' or doc['UseChunkFiles'] != 'true':
        raise Invalid('Require GlobalProxy="false", UseChunkFiles="true"')
    if sorted(doc['RouteOrder'].split('-')) != ['block','direct','proxy']:
        raise Invalid('Unsupported HAPP RouteOrder')
    if doc['DomainStrategy'] not in {'AsIs','IPIfNonMatch','IPOnDemand'}:
        raise Invalid('Invalid HAPP DomainStrategy')
    if not isinstance(doc['LastUpdated'],str) or (doc['LastUpdated'] and not doc['LastUpdated'].isdigit()):
        raise Invalid('LastUpdated must be Unix seconds string')
    if not isinstance(doc['DnsHosts'],dict): raise Invalid('Invalid DnsHosts')
    for key in required-{'DnsHosts'}:
        if key.endswith(('Sites','Ip')):
            if not isinstance(doc[key],list) or not all(isinstance(x,str) for x in doc[key]):
                raise Invalid(f'{key} must be a list of strings')
        elif not isinstance(doc[key],str): raise Invalid(f'{key} must be a string')
    for key in ['Geoipurl','Geositeurl']:
        if not doc[key].startswith('https://'): raise Invalid('Geodata URL must be HTTPS')
    for label in ['Remote','Domestic']:
        import ipaddress
        ipaddress.ip_address(doc[label+'DNSIP'])
        if doc[label+'DNSType']=='DoH' and not doc[label+'DNSDomain'].startswith('https://'):
            raise Invalid('DoH URL must be HTTPS')


def load_inputs(root):
    root = Path(root)
    names = {'happ':'legacy/happ-current.json','mihomo':'legacy/mihomo-current.yaml',
             'friend-proxy':'upstream-snapshots/friend-proxy.yaml',
             'friend-direct':'upstream-snapshots/friend-direct.yaml'}
    files = {name:root/'inputs'/path for name,path in names.items()}
    missing = [str(path) for path in files.values() if not path.is_file()]
    if missing: raise Invalid('Required inputs missing: '+', '.join(missing))
    happ = read_json(files['happ'])
    validate_happ(happ)
    mihomo = load_yaml(files['mihomo'])
    if not isinstance(mihomo,dict) or not isinstance(mihomo.get('rules'),list):
        raise Invalid('Mihomo rules missing')
    if mihomo['rules'][-1] != 'MATCH,DIRECT': raise Invalid('Require MATCH,DIRECT')
    raw = files['mihomo'].read_text(encoding='utf-8-sig')
    if raw.count('# LEAVE THIS LINE!') != 2:
        raise Invalid('Expected both client subscription insertion markers')
    # Export must be a template. Never copy any endpoint credentials into a build.
    if mihomo.get('proxies') or mihomo.get('proxy-providers'):
        raise Invalid('Remove subscription credentials from legacy template first')
    rules=[]
    for action,label in [('BLOCK','Block'),('PROXY','Proxy'),('DIRECT','Direct')]:
        for suffix in ['Sites','Ip']:
            key=label+suffix
            for i,value in enumerate(happ[key]):
                rules.append(parse_happ(value,action,'legacy:happ:'+key,i,ip=suffix=='Ip'))
    for i,text in enumerate(mihomo['rules']):
        rule=parse_mihomo(text,source='legacy:mihomo',index=i)
        if rule.kind!='MATCH': rules.append(rule)
    friend={}
    for source,action in [('friend-proxy','PROXY'),('friend-direct','DIRECT')]:
        doc=load_yaml(files[source])
        if not isinstance(doc,dict) or not isinstance(doc.get('payload'),list) or not doc['payload']:
            raise Invalid(f'{source}: empty or invalid payload')
        friend[source]=[parse_mihomo(t,action,source,i,60) for i,t in enumerate(doc['payload'])]
    inventory={name:{'path':str(path.relative_to(root)).replace('\\','/'),'sha256':digest(path),
                          'bytes':path.stat().st_size,'source_date':None,
                          'freshness':'user-supplied snapshot, source date unknown'} for name,path in files.items()}
    return happ,mihomo,raw,rules,friend,inventory
