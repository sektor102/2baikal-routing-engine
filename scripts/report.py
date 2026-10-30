import json
import pathlib
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from engine.io import load_inputs,read_json,write_json
from engine.geodata import Database
from engine.io import load_yaml
from engine.model import parse_mihomo,route
from engine.compiler import route_happ
from engine.validation import expanded_mihomo


def main():
    current=read_json(ROOT/'dist/release.json')
    previous_path=ROOT/'.previous-release/release.json'
    previous=read_json(previous_path) if previous_path.exists() else {}
    before={s['id']:s for s in previous.get('upstreams',[])}
    changes=[]
    for source in current['upstreams']:
        old=before.get(source['id'],{})
        record={'id':source['id'],'sha256_before':old.get('sha256'),'sha256_after':source.get('sha256'),
                'changed':source.get('sha256')!=old.get('sha256'),
                'checked_at':source.get('checked_at'),'source_updated_at':source.get('source_updated_at'),
                'retrieval':source.get('retrieval'),'missing_required':source.get('missing_required')}
        path=ROOT/'.cache/upstream'/(source['id']+'.bin')
        last=path.with_name(source['id']+'.previous.bin')
        if record['changed'] and source.get('format') in {'geosite','geoip'} and last.exists():
            record['member_diff_available']=True
            record['category_diff']=Database(path.read_bytes(),source['format']).diff(Database(last.read_bytes(),source['format']))
        else:
            record['member_diff_available']=False
            counts=source.get('categories',{})
            oldcounts=old.get('categories',{})
            record['category_counts']={name:{'before':oldcounts.get(name),'after':counts.get(name)}
                                      for name in sorted(counts.keys() | oldcounts.keys())
                                      if counts.get(name)!=oldcounts.get(name)}
        changes.append(record)
    coverage={'previous_release':previous.get('version'),'release':current['version'],
              'previous_personal_count':previous.get('counts',{}).get('personal'),
              'personal_count':current['counts']['personal'],'upstream_changes':changes}
    _,_,_,personal,_,_=load_inputs(ROOT)
    coverage['personal_coverage']=[{'rule':r.record(),'pc':'preserved',
                                   'ios':'not-applicable-process' if r.kind=='PROCESS-NAME' else 'preserved',
                                   'note':'Precedence and explicit-direct pruning documented in conflicts.json'} for r in personal]
    validation=read_json(ROOT/'reports/validation.json')
    coverage['personal_coverage']=validation['personal_coverage']
    write_json(ROOT/'reports/coverage-diff.json',coverage)
    selected=next(s for s in current['upstreams'] if s['id']=='historical-geosite')
    db=Database((ROOT/'.cache/upstream/historical-geosite.bin').read_bytes(),'geosite')
    twitter=list(db.rules('twitter','PROXY'))
    write_json(ROOT/'reports/twitter.json',{'sha256':db.sha256,'category':'twitter',
                'real_category_members':[r.record() for r in twitter],
                'personal_xai_grok':[r.record() for r in personal if r.value in {'x.ai','grok.com','accounts.x.ai'}],
                'golden_hosts':['x.com','t.co','pbs.twimg.com','video.twimg.com']})
    proxy=list(db.rules('ru-blocked','PROXY'))
    direct=list(db.rules('ru-available-only-inside','DIRECT'))
    suffix={r.value:r for r in direct if r.kind=='DOMAIN-SUFFIX'}
    exact={r.value:r for r in direct if r.kind=='DOMAIN'}
    descendants={}
    for rule in direct:
        if rule.kind not in {'DOMAIN','DOMAIN-SUFFIX'}: continue
        labels=rule.value.split('.')
        for i in range(len(labels)): descendants.setdefault('.'.join(labels[i:]),[]).append(rule)
    overlap=set()
    for rule in proxy:
        if rule.kind not in {'DOMAIN','DOMAIN-SUFFIX'}: continue
        labels=rule.value.split('.')
        for i in range(len(labels)):
            name='.'.join(labels[i:])
            if name in suffix: overlap.add((rule.kind,rule.value,suffix[name].kind,name))
        if rule.value in exact: overlap.add((rule.kind,rule.value,'DOMAIN',rule.value))
        if rule.kind=='DOMAIN-SUFFIX':
            for other in descendants.get(rule.value,[]): overlap.add((rule.kind,rule.value,other.kind,other.value))
    write_json(ROOT/'reports/category-overlaps.json',{'proxy':'ru-blocked','direct':'ru-available-only-inside',
                'count':len(overlap),'domain_pairs':sorted(overlap),
                'regex_keyword_in_proxy':sum(r.kind in {'DOMAIN-KEYWORD','DOMAIN-REGEX'} for r in proxy),
                'precedence':'HAPP proxy before direct; PC process policy precedes aggregate categories'})
    provider_diff=[]
    _,_,_,_,snapshots,_=load_inputs(ROOT)
    for source,original in snapshots.items():
        path=ROOT/'.cache/upstream'/(source+'.bin')
        if not path.exists():
            provider_diff.append({'id':source,'status':'unavailable; snapshot date unknown'})
            continue
        action='DIRECT' if source=='friend-direct' else 'PROXY'
        remote=[parse_mihomo(text,action,source) for text in load_yaml(path)['payload']]
        before={(r.kind,r.value) for r in original}
        after={(r.kind,r.value) for r in remote}
        provider_diff.append({'id':source,'snapshot_rules':len(original),'live_rules':len(remote),
                              'added':sorted(after-before),'removed':sorted(before-after),
                              'mode':'review; live changes never auto-enable new rules'})
    write_json(ROOT/'reports/provider-diff.json',provider_diff)
    compact=Database((ROOT/'dist/geosite.dat').read_bytes(),'geosite')
    ipdb=Database((ROOT/'.cache/upstream/historical-geoip.bin').read_bytes(),'geoip')
    profile=read_json(ROOT/'dist/happ/routing.json')
    pc=expanded_mihomo(ROOT/'dist/mihomo')
    sampled=[]
    seen=set()
    for rule in personal:
        if rule.kind not in {'DOMAIN','DOMAIN-SUFFIX'}: continue
        key=(rule.value,rule.action)
        if key in seen: continue
        seen.add(key)
        for client in ['pc','ios']:
            actual,matched=(route(pc,host=rule.value,geosite=compact,geoip=ipdb) if client=='pc' else
                            route_happ(profile,host=rule.value,geosite=compact,geoip=ipdb))
            if actual!=rule.action:
                sampled.append({'client':client,'input_rule':rule.record(),'sample_host':rule.value,
                                'actual':actual,'matched':matched.record() if matched else None,
                                'note':'Security/category ordering affects the effective route.'})
    write_json(ROOT/'reports/personal-route-collisions.json',sampled)
    lines=['# 2Baikal '+current['version'],'',
           'Personal input rules: '+str(current['counts']['personal'])+'.',
           'Review statuses: '+json.dumps(current['counts']['review'])+'.','',
           'Previous: '+str(previous.get('version','first verified build'))+'.','',
           '## Upstream changes','']
    for row in changes:
        lines.append('- '+row['id']+': '+('changed' if row['changed'] else 'unchanged')+
                     '; source date '+str(row['source_updated_at'])+'; checked '+str(row['checked_at'])+'.')
    (ROOT/'reports/changelog.md').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    print('Coverage diff and changelog written')


if __name__=='__main__': main()
