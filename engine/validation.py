from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .compiler import check_golden, check_router_golden, happ_rule_order
from .geodata import Database
from .io import digest, load_inputs, load_yaml, read_json, validate_happ, write_json
from .model import Invalid, Rule, parse_mihomo
from .organization import Group,verify_layout
from .policy import classify


def expanded_mihomo(directory,texts=None):
    directory=Path(directory)
    config=load_yaml(directory/'config.yaml')
    output=[]
    for text in config['rules'] if texts is None else texts:
        parts=[s.strip() for s in text.split(',')]
        if parts[0]!='RULE-SET':
            output.append(parse_mihomo(text,source='output:mihomo'))
            continue
        _,name,target,*options=parts
        action={'DIRECT':'DIRECT','REJECT':'BLOCK','→ Remnawave':'PROXY'}[target]
        definition=config['rule-providers'][name]
        if definition['format']=='mrs' and definition['behavior']=='classical':
            raise Invalid('classical cannot use MRS')
        path=directory/definition['path']
        if not path.resolve().is_relative_to(directory.resolve()): raise Invalid('Provider path escape')
        payload=load_yaml(path.with_suffix('.yaml'))['payload']
        for value in payload:
            if definition['behavior']=='classical':
                rule=parse_mihomo(value,action,source='output:'+name)
            elif definition['behavior']=='domain':
                rule=Rule('DOMAIN-SUFFIX' if value.startswith('+.') else 'DOMAIN',
                          value[2:] if value.startswith('+.') else value,action,'output:'+name).normalized()
            elif definition['behavior']=='ipcidr':
                rule=Rule('IP-CIDR',value,action,'output:'+name,options=tuple(options)).normalized()
            else: raise Invalid('Unknown provider behavior')
            output.append(rule)
    return output


def semantic_key(rule):
    options=set(rule.options)
    if rule.kind in {'IP-CIDR','IP-CIDR6'}: options.add('no-resolve')
    return rule.kind,rule.value,rule.action,tuple(sorted(options))


def verify_service_output(directory,reference,layout,site,geoip,router=False):
    kept=[i for i,r in enumerate(reference) if not router or r.kind!='PROCESS-NAME']
    remap={old:new for new,old in enumerate(kept)}
    ordered=[]
    config=load_yaml(Path(directory)/'config.yaml')
    end=0
    for row in layout['groups']:
        indices=row['source_indices']
        if not indices or any(i not in remap for i in indices): raise Invalid('Invalid service source indices')
        ordered.append(Group('', '', '', 0, '', [remap[i] for i in indices]))
        if row['emitted_start']!=end: raise Invalid('Unaccounted rules in service layout')
        end+=row['emitted_count']
        originals=[reference[i] for i in indices]
        if any(r.kind in {'GEOSITE','GEOIP'} for r in originals):
            if len(originals)!=1: raise Invalid('Geo category merged with personal service rules')
            rule=originals[0]
            originals=list((site if rule.kind=='GEOSITE' else geoip).rules(rule.value,rule.action))
        actual=expanded_mihomo(directory,config['rules'][row['emitted_start']:end])
        if {semantic_key(r) for r in actual}!={semantic_key(r) for r in originals}:
            raise Invalid('Service provider membership changed: '+row['service'])
    if config['rules'][end:]!=['MATCH,DIRECT']: raise Invalid('Unexpected rules outside service layout')
    return verify_layout([reference[i] for i in kept],ordered)


def mihomo_test(dist,mihomo,geoip_path):
    dist=Path(dist)
    logs=[]
    for family,name in [('mihomo','config.yaml'),('mihomo','config-doh-optional.yaml'),
                        ('mihomo-router','config.yaml')]:
        with tempfile.TemporaryDirectory(prefix='2baikal-mihomo-',dir=dist.parent/'.cache') as temp:
            home=Path(temp)
            shutil.copytree(dist/family/'providers',home/'providers')
            config=load_yaml(dist/family/name)
            # Test only: blackhole-type reject mock group, no subscription or listeners.
            config['proxies']=[{'name':'MOCK','type':'reject'}]
            config['proxy-groups']=[{'name':'→ Remnawave','type':'select','proxies':['MOCK']}]
            for provider in config['rule-providers'].values():
                provider['type']='file'
                provider.pop('url',None)
                provider.pop('interval',None)
            config.pop('tun',None)
            config['allow-lan']=False
            config['external-controller']='127.0.0.1:0'
            config['dns']['listen']='127.0.0.1:0'
            (home/'test.yaml').write_text(__import__('yaml').safe_dump(config,allow_unicode=True,sort_keys=False),encoding='utf-8')
            shutil.copyfile(geoip_path,home/'geoip.dat')
            result=subprocess.run([str(mihomo),'-t','-d',str(home),'-f',str(home/'test.yaml')],
                                  capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
            logs.append({'profile':family+'/'+name,'returncode':result.returncode,'output':result.stdout+result.stderr})
            if result.returncode: raise Invalid('Mihomo -t failed: '+result.stdout+result.stderr)
            if 'parse classical rule' in (result.stdout+result.stderr).lower():
                raise Invalid('Mihomo silently dropped an invalid classical rule')
    return logs


def xray_config(profile):
    rules=[]
    for action in profile['RouteOrder'].split('-'):
        for suffix,field in [('Sites','domain'),('Ip','ip')]:
            values=profile[action.title()+suffix]
            if values: rules.append({'type':'field',field:values,'outboundTag':action})
    return {'log':{'loglevel':'warning'},
            'outbounds':[{'protocol':'blackhole','tag':tag} for tag in ['direct','proxy','block']],
            'routing':{'domainStrategy':profile['DomainStrategy'],'rules':rules}}


def xray_test(dist,xray,geoip_path):
    dist=Path(dist)
    with tempfile.TemporaryDirectory(prefix='2baikal-xray-',dir=dist.parent/'.cache') as temp:
        home=Path(temp)
        shutil.copyfile(dist/'geosite.dat',home/'geosite.dat')
        shutil.copyfile(geoip_path,home/'geoip.dat')
        write_json(home/'test.json',xray_config(read_json(dist/'happ/routing.json')))
        env={**os.environ,'XRAY_LOCATION_ASSET':str(home)}
        result=subprocess.run([str(xray),'run','-test','-config',str(home/'test.json')],env=env,
                              capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
        if result.returncode: raise Invalid('Xray test failed: '+result.stdout+result.stderr)
        return {'returncode':result.returncode,'output':result.stdout+result.stderr,
                'note':'Validates an equivalent Xray ruleset; not a native HAPP/iOS execution.'}


def validate(root,mihomo=None,xray=None,require_binaries=False):
    root=Path(root)
    dist=root/'dist'
    if not dist.is_dir(): raise Invalid('dist is missing')
    for file in dist.rglob('*'):
        if file.is_file() and not file.stat().st_size: raise Invalid('Empty output: '+str(file))
    for line in (dist/'SHA256SUMS').read_text().splitlines():
        sha,path=line.split('  ',1)
        file=dist/path
        if not file.resolve().is_relative_to(dist.resolve()) or digest(file)!=sha:
            raise Invalid('Checksum mismatch: '+path)
    profile=read_json(dist/'happ/routing.json')
    validate_happ(profile)
    source=load_yaml(root/'sources/manifest.yaml')['selected']['geoip']
    geoip_path=root/'.cache/upstream'/(source+'.bin')
    release=read_json(dist/'release.json')
    if digest(geoip_path)!=release['geoip']['sha256']:
        raise Invalid('GeoIP cache changed after build; rebuild before validation')
    if digest(dist/'geosite.dat')!=release['geosite']['sha256']:
        raise Invalid('Compact GeoSite checksum mismatch')
    geoip=Database(geoip_path.read_bytes(),'geoip')
    site=Database((dist/'geosite.dat').read_bytes(),'geosite')
    site.require({r.value for r in happ_rule_order(profile) if r.kind=='GEOSITE'})
    geoip.require({r.value for r in happ_rule_order(profile) if r.kind=='GEOIP'})
    rules=expanded_mihomo(dist/'mihomo')
    rows=check_golden(rules,profile,site,geoip)
    router=expanded_mihomo(dist/'mihomo-router')
    if load_yaml(dist/'mihomo-router/config.yaml').get('find-process-mode')!='off':
        raise Invalid('Router process lookup must be off')
    if any(r.kind=='PROCESS-NAME' for r in router):
        raise Invalid('Process rule leaked into router output')
    rows+=check_router_golden(router,site,geoip)
    bad=[r for r in rows if r['actual']!=r['expected']]
    if bad: raise Invalid('Rendered output routing regression: '+json.dumps(bad))
    _,_,_,personal,friend,_=load_inputs(root)
    reference,_,_=classify(personal,friend,load_yaml(root/'rules/policy.yaml'))
    layout=read_json(dist/'ruleset-layout.json')
    equivalence={'pc':verify_service_output(dist/'mihomo',reference,layout['pc'],site,geoip),
                 'router':verify_service_output(dist/'mihomo-router',reference,layout['router'],site,geoip,router=True)}
    output_keys={(r.kind,r.value,r.action) for r in rules}
    router_keys={(r.kind,r.value,r.action) for r in router}
    ios_keys={(r.kind,r.value,r.action) for r in happ_rule_order(profile)}
    coverage=[]
    for original in personal:
        key=(original.kind,original.value,original.action)
        if original.kind in {'GEOSITE','GEOIP'}:
            database=site if original.kind=='GEOSITE' else geoip
            members={(r.kind,r.value,original.action) for r in database.rules(original.value,original.action)}
            preserved=members.issubset(output_keys)
            router_preserved=members.issubset(router_keys)
        else:
            preserved=key in output_keys
            router_preserved=original.kind=='PROCESS-NAME' or key in router_keys
        ios_preserved=original.kind=='PROCESS-NAME' or key in ios_keys
        coverage.append({'rule':original.record(),'pc':preserved,'ios':ios_preserved,
                         'ios_applicable':original.kind!='PROCESS-NAME',
                         'router':router_preserved,'router_applicable':original.kind!='PROCESS-NAME'})
    if any(not r['pc'] or not r['ios'] or not r['router'] for r in coverage):
        raise Invalid('Personal input coverage lost in rendered output')
    if require_binaries and (not mihomo or not xray): raise Invalid('Both Mihomo and Xray required for release validation')
    result={'golden_cases':len(rows),'golden_failures':len(bad),'schema':'passed',
            'service_equivalence':equivalence,
            'personal_coverage':coverage,
            'mihomo':mihomo_test(dist,mihomo,geoip_path) if mihomo else 'NOT RUN',
            'xray':xray_test(dist,xray,geoip_path) if xray else 'NOT RUN'}
    # The publisher trusts only a validation result bound to these exact file bytes.
    result['artifact_tree_sha256']=digest(dist/'SHA256SUMS')
    write_json(root/'reports/validation.json',result)
    return result
