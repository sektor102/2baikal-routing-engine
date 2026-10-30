import json
import pathlib
import shutil
import sys
import time

from engine.geodata import message,vint
from engine.io import write_json

PROJECT=pathlib.Path(__file__).resolve().parents[1]
# Keep all test writes inside the checkout, including restricted Windows runners.
import tempfile
TEST_TEMP=PROJECT/'.cache/test-tmp'
TEST_TEMP.mkdir(parents=True,exist_ok=True)
tempfile.tempdir=str(TEST_TEMP)


def site_bytes(categories):
    output=[]
    for name,domains in sorted(categories.items()):
        entry=message(1,name.encode())
        for dtype,value in domains:
            member=vint(8)+vint(dtype)+message(2,value.encode())
            entry += message(2,member)
        output.append(message(1,entry))
    return b''.join(output)


def ip_bytes(categories):
    import ipaddress
    output=[]
    for name,nets in sorted(categories.items()):
        entry=message(1,name.encode())
        for net in nets:
            net=ipaddress.ip_network(net)
            entry+=message(2,message(1,net.network_address.packed)+vint(16)+vint(net.prefixlen))
        output.append(message(1,entry))
    return b''.join(output)


def fixture(root):
    from engine.io import load_yaml
    from engine.network import verify
    root=pathlib.Path(root)
    for folder in ['inputs','rules','sources']:
        shutil.copytree(PROJECT/folder,root/folder,dirs_exist_ok=True)
    policy=load_yaml(root/'rules/policy.yaml')
    site={name:[(2,'category-'+name+'.invalid')] for name in policy['geosite-required']}
    site['ru-blocked']=[(2,'x.com'),(2,'apple.com'),(2,'mask.icloud.com')]
    site['epicgames']=[(2,'epicgames.dev')]
    site['steam']=[(2,'steamcommunity.com')]
    site['twitter']=[(2,'x.com'),(2,'twitter.com'),(2,'twimg.com'),(2,'t.co')]
    data={'historical-geosite':site_bytes(site),
          'historical-geoip':ip_bytes({'private':['10.0.0.0/8','::1/128','fc00::/7','fe80::/10'],
                                      'direct':['17.0.0.0/8'],'whitelist':['192.0.2.0/24']})}
    cache=root/'.cache/upstream'
    cache.mkdir(parents=True,exist_ok=True)
    records=[]
    for source in load_yaml(root/'sources/manifest.yaml')['sources']:
        if source['id'] not in data: continue
        raw=data[source['id']]
        record={**source,**verify(raw,source),'validated':True,'verified_at':'2026-10-30T20:00:00+00:00',
                'pinned_url':'https://example.invalid/fixture/geoip.dat','retrieval':'synthetic-test-fixture',
                'sha256':__import__('hashlib').sha256(raw).hexdigest()}
        (cache/(source['id']+'.bin')).write_bytes(raw)
        write_json(cache/(source['id']+'.json'),record)
        records.append(record)
    write_json(root/'reports/upstream.json',records)
    return root
