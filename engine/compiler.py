from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path

import yaml

from .geodata import Database, fields, message
from .io import digest, load_inputs, load_yaml, read_json, validate_happ, write_json
from .model import Invalid, Rule, conflicts, covers, matches, parse_happ, route
from .policy import baseline_report, classify
from .organization import Catalog,organize,verify_layout,legacy_provider_count,STAGES

GOLDEN_PROXY=['x.com','t.co','pbs.twimg.com','video.twimg.com','discord.com','chatgpt.com',
              'youtube.com','api.epicgames.dev','steamcommunity.com','claude.ai','spotify.com',
              'wardogs.n4lab.dev','live.wardogs.bulkhead.pragmaengine.com',
              'deeep-storage.anybrain.gg','opm.elytra.ac','grok.com','x.ai']
GOLDEN_DIRECT=['wardxp-mim.vivox.com','vivox.com','escapefromtarkov.com','battlestategames.com',
               'apple.com','push.apple.com','mask.icloud.com','lkfl2.nalog.ru','lknpd.nalog.ru']
GOLDEN_IPS=['127.0.0.1','10.1.2.3','172.16.1.1','192.168.1.1','100.64.0.1','169.254.1.1',
            '::1','fd12::1','fe80::1234','ff02::1']


def text_yaml(path,value):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(yaml.safe_dump(value,allow_unicode=True,sort_keys=False,width=120),encoding='utf-8',newline='\n')


def happ_value(rule):
    names={'DOMAIN':'full:','DOMAIN-SUFFIX':'domain:','DOMAIN-REGEX':'regexp:',
           'DOMAIN-KEYWORD':'','GEOSITE':'geosite:','GEOIP':'geoip:',
           'IP-CIDR':'','IP-CIDR6':''}
    if rule.kind not in names: raise Invalid('Windows-only rule in HAPP')
    return names[rule.kind]+rule.value


def happ_rule_order(profile):
    output=[]
    for action in profile['RouteOrder'].upper().split('-'):
        label=action.title()
        for suffix in ['Sites','Ip']:
            output += [parse_happ(value,action,'output:happ',i,ip=suffix=='Ip')
                       for i,value in enumerate(profile[label+suffix])]
    return output


def effective_happ(rules):
    """Resolve explicit same-match overrides without relying on action-group order."""
    actions={}
    result=[]
    for rule in rules:
        if rule.kind=='PROCESS-NAME': continue
        key=(rule.kind,rule.value)
        previous=actions.get(key)
        if previous and previous.action!=rule.action:
            if previous.priority==rule.priority: raise Invalid('Conflicting equal-priority HAPP rule: '+rule.value)
            continue
        actions[key]=rule
        result.append(rule)
    # Arbitrary cross-action suffix complements cannot be represented by HAPP's
    # action groups. Detect them rather than silently changing the policy.
    direct=[r for r in result if r.action=='DIRECT' and r.kind in {'DOMAIN','DOMAIN-SUFFIX'}]
    proxy=[r for r in result if r.action=='PROXY' and r.kind in {'DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','DOMAIN-REGEX'}]
    for d in direct:
        for p in proxy:
            if covers(d,p) or covers(p,d) or (p.kind in {'DOMAIN-KEYWORD','DOMAIN-REGEX'} and matches(p,d.value)):
                raise Invalid('HAPP explicit cross-action overlap needs review: '+d.value+' / '+p.value)
    return result


def route_happ(profile,host='',ip=None,geosite=None,geoip=None):
    rules=happ_rule_order(profile)
    # Xray IPIfNonMatch: try domains before DNS/IP rules. Never perform real DNS.
    if host and profile['DomainStrategy']=='IPIfNonMatch':
        nonip=[r for r in rules if r.kind not in {'GEOIP','IP-CIDR','IP-CIDR6'}]
        action,matched=route(nonip,host=host,geosite=geosite,geoip=geoip)
        if matched: return action,matched
    if host and profile['DomainStrategy']=='AsIs': ip=None
    return route(rules,host=host,ip=ip,geosite=geosite,geoip=geoip)


def protect_geosite(db,categories,rules):
    """Subtract only entries wholly covered by explicit personal DIRECT.

    If a broader upstream proxy entry would require domain-set complement, fail.
    No attempt is made to invent regex complements or weaken broad proxy coverage.
    """
    direct=[r for r in rules if r.action=='DIRECT' and r.kind in {'DOMAIN','DOMAIN-SUFFIX'}]
    proxycats={r.value.split('@')[0] for r in rules if r.kind=='GEOSITE' and r.action=='PROXY'}
    removed=[]
    result=[]
    for category in sorted({c.split('@')[0] for c in categories}):
        entry=db.entries[category]
        if category not in proxycats:
            result.append(message(1,entry.raw))
            continue
        kept=[]
        for raw,rule in zip(entry.members,entry.parsed):
            covering=[d for d in direct if covers(d,rule)]
            if covering:
                removed.append({'category':category,'removed':rule.record(),
                                'reason':'personal DIRECT overrides aggregate proxy',
                                'covered_by':[d.record() for d in covering]})
                continue
            for d in direct:
                if covers(rule,d) or (rule.kind in {'DOMAIN-KEYWORD','DOMAIN-REGEX'} and
                                     (matches(rule,d.value) or matches(rule,'probe.'+d.value))):
                    raise Invalid(f'Cannot subtract DIRECT {d.value} from broader {category}:{rule.kind},{rule.value}')
            kept.append(raw)
        # Keep all metadata except the removed repeated domain fields.
        other=b''.join(raw for n,w,v,raw in fields(entry.raw) if n!=2)
        result.append(message(1,other+b''.join(message(2,m) for m in kept)))
    return b''.join(result),removed


def classical(rule):
    kind='IP-CIDR6' if rule.kind=='IP-CIDR6' else rule.kind
    return ','.join([kind,rule.value,*rule.options])


def provider(out,name,rules,mihomo):
    """Domain/IP sets become MRS; regex/keyword/process remain classical YAML."""
    domains=[r for r in rules if r.kind in {'DOMAIN','DOMAIN-SUFFIX'}]
    ips=[r for r in rules if r.kind in {'IP-CIDR','IP-CIDR6'}]
    rest=[r for r in rules if r.kind not in {'DOMAIN','DOMAIN-SUFFIX','IP-CIDR','IP-CIDR6'}]
    definitions=[]
    for suffix,behavior,subset in [('domain','domain',domains),('ip','ipcidr',ips),('classical','classical',rest)]:
        if not subset: continue
        filename=f'{name}-{suffix}'
        if behavior=='domain':
            payload=sorted({('+.' if r.kind=='DOMAIN-SUFFIX' else '')+r.value for r in subset})
        elif behavior=='ipcidr':
            # Exact networks retained. Collapsing is optional, never across policy tiers.
            payload=sorted({r.value for r in subset})
        else: payload=list(dict.fromkeys(classical(r) for r in subset))
        path=out/'providers'/(filename+'.yaml')
        text_yaml(path,{'payload':payload})
        fmt='yaml'
        if mihomo and behavior!='classical':
            mrs=path.with_suffix('.mrs')
            subprocess.run([str(mihomo),'convert-ruleset',behavior,'yaml',str(path.resolve()),str(mrs.resolve())],
                           check=True,capture_output=True,timeout=60)
            if not mrs.exists() or mrs.stat().st_size<8: raise Invalid('Empty MRS conversion')
            fmt='mrs'
        definitions.append((filename,behavior,fmt))
    return definitions


def inline_mihomo(rule):
    outbound={'PROXY':'→ Remnawave','DIRECT':'DIRECT','BLOCK':'REJECT'}[rule.action]
    options=list(rule.options)
    if rule.kind in {'IP-CIDR','IP-CIDR6'} and 'no-resolve' not in options: options.append('no-resolve')
    return ','.join([rule.kind,rule.value,outbound,*options])


def make_mihomo(base,raw,rules,site_db,ip_db,out,mihomo,geoip_url,base_url,catalog,router=False):
    config=copy.deepcopy(base)
    if router:
        config['find-process-mode']='off'
    config['proxies']=None
    config['geo-auto-update']=False
    config['rule-providers']={}
    lines=[]
    groups,certificate=organize(rules,catalog)
    if router:
        kept=[i for i,r in enumerate(rules) if r.kind!='PROCESS-NAME']
        remap={old:new for new,old in enumerate(kept)}
        projected=[replace(g,indices=[remap[i] for i in g.indices if i in remap]) for g in groups]
        certificate=verify_layout([rules[i] for i in kept],[g for g in projected if g.indices])
    records=[]
    for group in groups:
        indices=[i for i in group.indices if not router or rules[i].kind!='PROCESS-NAME']
        if not indices: continue
        action=group.action
        outbound={'PROXY':'→ Remnawave','DIRECT':'DIRECT','BLOCK':'REJECT'}[action]
        if group.kind in {'GEOSITE','GEOIP'}:
            rule=rules[indices[0]]
            database=site_db if group.kind=='GEOSITE' else ip_db
            subset=list(database.rules(rule.value,rule.action))
        else:
            subset=[rules[i] for i in indices]
        start=len(lines)
        files=[]
        if group.provider:
            definitions=provider(out,group.name,subset,mihomo)
            for name,behavior,fmt in definitions:
                relative=f'providers/{name}.{fmt}'
                definition={'type':'http' if base_url else 'file','behavior':behavior,'format':fmt,'path':'./'+relative}
                if base_url: definition.update(url=base_url+'/mihomo/'+relative,interval=21600)
                if name in config['rule-providers']: raise Invalid('Duplicate readable provider name: '+name)
                config['rule-providers'][name]=definition
                lines.append(f'RULE-SET,{name},{outbound}'+(',no-resolve' if behavior=='ipcidr' else ''))
                files.append(name+'.'+fmt)
        else:
            lines.extend(inline_mihomo(rule) for rule in subset)
        records.append({'service':group.service,'title':group.title,'action':action,
                        'priority':group.priority,'origin':group.kind.lower() if group.kind in {'GEOSITE','GEOIP'} else STAGES.get(group.priority,'custom'),
                        'mode':'provider' if group.provider else 'inline','source_indices':indices,
                        'files':files,'emitted_start':start,'emitted_count':len(lines)-start,
                        'members':len({(r.kind,r.value) for r in subset})})
    config['rules']=lines+['MATCH,DIRECT']
    layout={'certificate':certificate,'before_providers':legacy_provider_count(rules,site_db,ip_db,router),
            'providers':len(config['rule-providers']),'inline_rules':sum(r['emitted_count'] for r in records if r['mode']=='inline'),
            'groups':records}
    # Keep the original client structure AND both insertion comments.
    text=yaml.safe_dump(config,allow_unicode=True,sort_keys=False,width=140)
    text=re.sub(r'^proxies: null$', 'proxies: # LEAVE THIS LINE!',text,flags=re.M)
    text=re.sub(r'^(\s+)proxies: null$',r'\1proxies: # LEAVE THIS LINE!',text,flags=re.M)
    if text.count('# LEAVE THIS LINE!')!=2: raise Invalid('Lost Mihomo client insertion markers')
    (out/'config.yaml').write_text(text,encoding='utf-8',newline='\n')
    if router: return config,layout
    optional=copy.deepcopy(config)
    optional.setdefault('hosts',{})['common.dot.dns.yandex.net']='77.88.8.8'
    dns=optional.setdefault('dns',{})
    dns.update({'listen':'127.0.0.1:1053','ipv6':False,'respect-rules':True,
                'default-nameserver':['https://1.1.1.1/dns-query'],
                'nameserver':['https://1.1.1.1/dns-query#→ Remnawave'],
                'proxy-server-nameserver':['https://1.1.1.1/dns-query'],
                'direct-nameserver':['https://common.dot.dns.yandex.net/dns-query'],
                'direct-nameserver-follow-policy':False,
                'nameserver-policy':{'+.lan':'rcode://refused','+.local':'rcode://refused',
                                     '+.home.arpa':'rcode://refused',
                                     '+.vivox.com':'https://common.dot.dns.yandex.net/dns-query',
                                     '+.escapefromtarkov.com':'https://common.dot.dns.yandex.net/dns-query',
                                     '+.battlestategames.com':'https://common.dot.dns.yandex.net/dns-query'}})
    text=yaml.safe_dump(optional,allow_unicode=True,sort_keys=False,width=140)
    text=re.sub(r'^proxies: null$','proxies: # LEAVE THIS LINE!',text,flags=re.M)
    text=re.sub(r'^(\s+)proxies: null$',r'\1proxies: # LEAVE THIS LINE!',text,flags=re.M)
    (out/'config-doh-optional.yaml').write_text(text,encoding='utf-8',newline='\n')
    return config,layout


def check_golden(pc,profile,site,geoip):
    rows=[]
    for client in ['pc','ios']:
        for expected,hosts in [('PROXY',GOLDEN_PROXY),('DIRECT',GOLDEN_DIRECT)]:
            for host in hosts:
                actual,matched=(route(pc,host=host,geosite=site,geoip=geoip) if client=='pc' else
                                route_happ(profile,host=host,geosite=site,geoip=geoip))
                rows.append({'client':client,'host':host,'expected':expected,'actual':actual,
                             'matched':matched.record() if matched else None})
        for ip in GOLDEN_IPS:
            actual,matched=(route(pc,ip=ip,geosite=site,geoip=geoip) if client=='pc' else
                            route_happ(profile,ip=ip,geosite=site,geoip=geoip))
            rows.append({'client':client,'ip':ip,'expected':'DIRECT','actual':actual})
    for host,process,expected in [('wardxp-mim.vivox.com','WardogsClient-Win64-Shipping.exe','DIRECT'),
                                  ('vivox.com','msedge.exe','DIRECT'),
                                  ('escapefromtarkov.com','msedge.exe','DIRECT'),
                                  ('example.net','WardogsClient-Win64-Shipping.exe','PROXY'),
                                  ('example.net','BEService.exe','DIRECT')]:
        actual,_=route(pc,host=host,process=process,geosite=site,geoip=geoip)
        rows.append({'client':'pc','host':host,'process':process,'expected':expected,'actual':actual})
    for client in ['pc','ios']:
        kwargs={'host':'wardxp-mim.vivox.com','ip':'85.236.102.48','geosite':site,'geoip':geoip}
        actual,_=(route(pc,process='WardogsClient-Win64-Shipping.exe',**kwargs) if client=='pc' else route_happ(profile,**kwargs))
        rows.append({'client':client,'host':kwargs['host'],'ip':kwargs['ip'],
                     'expected':'DIRECT','actual':actual,'scenario':'domain exception versus proxy IP/process'})
        actual,_=(route(pc,ip='2001:b28:f23d::1',geosite=site,geoip=geoip) if client=='pc' else
                  route_happ(profile,ip='2001:b28:f23d::1',geosite=site,geoip=geoip))
        rows.append({'client':client,'ip':'2001:b28:f23d::1','expected':'PROXY','actual':actual})
    return rows


def check_router_golden(rules,site,geoip):
    rows=[]
    for expected,hosts in [('PROXY',GOLDEN_PROXY),('DIRECT',GOLDEN_DIRECT)]:
        for host in hosts:
            actual,_=route(rules,host=host,geosite=site,geoip=geoip)
            rows.append({'client':'router','host':host,'expected':expected,'actual':actual})
    for ip in GOLDEN_IPS+['2001:b28:f23d::1']:
        expected='PROXY' if ip=='2001:b28:f23d::1' else 'DIRECT'
        actual,_=route(rules,ip=ip,geosite=site,geoip=geoip)
        rows.append({'client':'router','ip':ip,'expected':expected,'actual':actual})
    actual,_=route(rules,host='example.net',process='WardogsClient-Win64-Shipping.exe',
                   geosite=site,geoip=geoip)
    rows.append({'client':'router','host':'example.net','scenario':'PC process has no router effect',
                 'expected':'DIRECT','actual':actual})
    return rows


def scan_secrets(path):
    patterns=[r'(?i)(?:uuid|password|private-key|public-key|token|authorization)\s*[:=]\s*[^\s#]+',
              r'(?i)(?:vless|vmess|trojan|ss)://',
              r'(?<![a-zA-Z0-9.-])[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}(?![a-zA-Z0-9.-])']
    for file in Path(path).rglob('*'):
        if file.is_file() and file.suffix in {'.json','.yaml','.txt','.md'}:
            text=file.read_text(encoding='utf-8')
            if any(re.search(pattern,text) for pattern in patterns):
                raise Invalid(f'Potential secret in {file.name}')


def build(root,mihomo=None,repository=None,previous=None):
    root=Path(root)
    happ,base,raw,personal,friend,inventory=load_inputs(root)
    policy=load_yaml(root/'rules/policy.yaml')
    catalog=Catalog(load_yaml(root/'rules/service-groups.yaml'))
    manifest=load_yaml(root/'sources/manifest.yaml')
    rules,review,duplicates=classify(personal,friend,policy)
    ios_rules=effective_happ(rules)
    upstream=read_json(root/'reports/upstream.json')
    byid={s['id']:s for s in upstream}
    selected=manifest['selected']
    for sid in selected.values():
        record=byid.get(sid,{})
        if not record.get('validated') or record.get('error'): raise Invalid(f'Unverified selected upstream: {sid}')
        file=root/'.cache/upstream'/(sid+'.bin')
        if digest(file)!=record['sha256']: raise Invalid(f'Cache checksum mismatch: {sid}')
    site=Database((root/'.cache/upstream'/(selected['geosite']+'.bin')).read_bytes(),'geosite')
    ip=Database((root/'.cache/upstream'/(selected['geoip']+'.bin')).read_bytes(),'geoip')
    sites=set(policy['geosite-required']) | {r.value for r in rules if r.kind=='GEOSITE'}
    ips=set(policy['geoip-required']) | {r.value for r in rules if r.kind=='GEOIP'}
    site.require(sites)
    ip.require(ips)
    compact,pruned=protect_geosite(site,sites,ios_rules)
    site_compact=Database(compact,'geosite')
    site_compact.require(sites)
    profile=copy.deepcopy(happ)
    for label in ['Direct','Proxy','Block']:
        for suffix in ['Sites','Ip']: profile[label+suffix]=[]
    for rule in ios_rules:
        if rule.kind in {'PROCESS-NAME','MATCH'}: continue
        label=rule.action.title()
        suffix='Ip' if rule.kind in {'IP-CIDR','IP-CIDR6','GEOIP'} else 'Sites'
        value=happ_value(rule)
        if value not in profile[label+suffix]: profile[label+suffix].append(value)
    # Exact contradictory personal matches require an explicit priority override.
    for first in rules:
        for second in rules:
            if first.kind==second.kind and first.value==second.value and first.action!=second.action:
                if first.priority==second.priority: raise Invalid(f'Conflicting personal routes: {first.value}')
    rows=check_golden(rules,profile,site_compact,ip)
    reports=root/'reports'
    write_json(reports/'baseline.json',baseline_report(personal,friend,inventory))
    write_json(reports/'review.json',review)
    write_json(reports/'conflicts.json',{'overlaps':conflicts(rules),'duplicates':duplicates,
                                       'geosite_personal_direct_overrides':pruned,
                                       'category_collisions':[{'proxy':'ru-blocked','direct':'ru-available-only-inside',
                                                              'note':'intersection depends on real database; proxy first in HAPP'}],
                                       'process_policy':'Personal domain/IP exceptions precede process rules on PC.'})
    write_json(reports/'golden.json',rows)
    failures=[row for row in rows if row['actual']!=row['expected']]
    if failures: raise Invalid('Golden routing failed: '+json.dumps(failures,ensure_ascii=False))
    geoip_url=byid[selected['geoip']].get('pinned_url')
    if not geoip_url: raise Invalid('Pinned and verified GeoIP URL missing')
    if repository and not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository):
        raise Invalid('Repository must be owner/repo')
    # Stable fingerprint over actual payload semantics, ignoring times/probe metadata.
    semantic={'happ':{k:v for k,v in profile.items() if k not in {'LastUpdated','Geositeurl','Geoipurl'}},
              'mihomo':base,'rules':[r.record() for r in rules],
              'geosite':hashlib.sha256(compact).hexdigest(),'geoip':byid[selected['geoip']]['sha256'],
              'geoip_url':geoip_url,'repository':repository,'mrs':bool(mihomo)}
    fingerprint=hashlib.sha256(json.dumps(semantic,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    tag='routing-'+fingerprint[:20]
    prev=read_json(Path(previous)/'release.json') if previous and (Path(previous)/'release.json').exists() else {}
    changed=fingerprint!=prev.get('fingerprint')
    updated=prev.get('updated_at') if not changed else str(max(int(time.time()),int(prev.get('updated_at','0'))+1))
    base_url=f'https://github.com/{repository}/releases/download/{tag}' if repository else None
    profile['Geositeurl']=(base_url or 'https://example.invalid/2baikal/'+tag)+'/geosite.dat'
    profile['Geoipurl']=geoip_url
    profile['LastUpdated']=updated
    validate_happ(profile)
    root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='2baikal-build-',dir=root) as temporary:
        out=Path(temporary)
        (out/'happ').mkdir()
        (out/'mihomo').mkdir()
        (out/'mihomo-router').mkdir()
        (out/'geosite.dat').write_bytes(compact)
        write_json(out/'happ/routing.json',profile)
        _,pc_layout=make_mihomo(base,raw,rules,site_compact,ip,out/'mihomo',mihomo,geoip_url,base_url,catalog)
        _,router_layout=make_mihomo(base,raw,rules,site_compact,ip,out/'mihomo-router',mihomo,geoip_url,base_url,catalog,router=True)
        write_json(reports/'ruleset-layout.json',{'schema':1,'pc':pc_layout,'router':router_layout})
        index=['# Rulesets by service','',
               'Names change organization only. Explicit overrides, personal rules, processes and Geo categories keep their priorities.',
               'Singletons and order-sensitive fragments are explicit rules; they do not need separate downloads.','',
               f"PC providers: {pc_layout['before_providers']} → {pc_layout['providers']}; Router: {router_layout['before_providers']} → {router_layout['providers']}.",'',
               '| Service | Route | Layer | Storage | Members | Files |','|---|---|---|---|---:|---|']
        for row in pc_layout['groups']:
            index.append('| '+ ' | '.join([row['title'],row['action'],row['origin'],row['mode'],str(row['members']),', '.join(row['files']) or 'inline'])+' |')
        (reports/'rulesets.md').write_text('\n'.join(index)+'\n',encoding='utf-8',newline='\n')
        # Release assets are flat archives; URLs inside config point at flat asset names.
        if base_url:
            for file in [*(out/'mihomo').glob('config*.yaml'),*(out/'mihomo-router').glob('config*.yaml')]:
                file.write_text(file.read_text(encoding='utf-8').replace(base_url+'/mihomo/providers/',base_url+'/'),encoding='utf-8',newline='\n')
        # Decide no-op from generated payload bytes, not source sizes, timestamps,
        # irrelevant categories, or compiler source comments. Normalize the two
        # self-references (release tag and LastUpdated) before hashing.
        payload_hash=hashlib.sha256()
        for file in sorted(out.rglob('*')):
            if not file.is_file(): continue
            data=file.read_bytes()
            if file==out/'happ/routing.json':
                canonical=copy.deepcopy(profile)
                canonical['LastUpdated']=''
                canonical['Geositeurl']=canonical['Geositeurl'].replace(tag,'RELEASE')
                data=json.dumps(canonical,sort_keys=True,ensure_ascii=False).encode()
            elif file.suffix in {'.yaml','.txt','.json'}:
                data=data.replace(tag.encode(),b'RELEASE')
            payload_hash.update(file.relative_to(out).as_posix().encode()+b'\0'+hashlib.sha256(data).digest())
        fingerprint=payload_hash.hexdigest()
        final_tag='routing-'+fingerprint[:20]
        changed=fingerprint!=prev.get('fingerprint')
        updated=prev.get('updated_at') if not changed else str(max(int(time.time()),int(prev.get('updated_at','0'))+1))
        for file in [*(out/'mihomo').glob('config*.yaml'),*(out/'mihomo-router').glob('config*.yaml')]:
            file.write_text(file.read_text(encoding='utf-8').replace(tag,final_tag),encoding='utf-8',newline='\n')
        profile['Geositeurl']=profile['Geositeurl'].replace(tag,final_tag)
        profile['LastUpdated']=updated
        tag=final_tag
        write_json(out/'happ/routing.json',profile)
        link='happ://routing/add/'+base64.b64encode(json.dumps(profile,ensure_ascii=False,separators=(',',':')).encode()).decode()
        (out/'happ/import-link.txt').write_text(link+'\n',encoding='utf-8',newline='\n')
        scan_secrets(out)
        release={'version':tag,'fingerprint':fingerprint,'updated_at':updated,
                 'publishable':bool(repository and mihomo),'repository':repository,
                 'geosite':site_compact.inventory(),
                 'geoip':{'url':geoip_url,'sha256':byid[selected['geoip']]['sha256'],
                          'bytes':ip.size,'raw_database_redistributed':False,
                          'mihomo_derived_categories':sorted(ips)},
                 'counts':{'personal':len(personal),'compiled':len(rules),
                           'router_compiled':sum(r.kind!='PROCESS-NAME' for r in rules),
                           'review':dict(Counter(r['status'] for r in review))},
                 'upstreams':upstream,'input_hashes':inventory,
                 'limitations':['HAPP native iOS execution requires device testing.',
                                'Optional DoH validated syntactically; network/device DNS leakage is not proven.']}
        write_json(out/'release.json',release)
        for name in ['golden.json','conflicts.json','review.json','baseline.json','ruleset-layout.json','rulesets.md']:
            shutil.copyfile(reports/name,out/name)
        sums=''.join(f'{digest(file)}  {file.relative_to(out).as_posix()}\n'
                     for file in sorted(out.rglob('*')) if file.is_file())
        (out/'SHA256SUMS').write_text(sums,encoding='utf-8',newline='\n')
        # Only the completed candidate replaces dist. Failures leave old files intact.
        destination=root/'dist'
        old=root/'.dist-previous'
        if old.exists(): shutil.rmtree(old)
        if destination.exists(): destination.rename(old)
        try: shutil.copytree(out,destination)
        except Exception:
            if destination.exists(): shutil.rmtree(destination)
            if old.exists(): old.rename(destination)
            raise
        if old.exists(): shutil.rmtree(old)
    write_json(reports/'build-result.json',{'version':tag,'changed':changed,'publishable':release['publishable']})
    return {**release,'changed':changed}
