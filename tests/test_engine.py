import copy
import hashlib
import json
import pathlib
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from engine.compiler import build,effective_happ,protect_geosite,route_happ,scan_secrets
from engine.geodata import Database,message,vint
from engine.io import load_inputs,load_yaml,read_json,validate_happ,write_json
from engine.model import Invalid,Rule,covers,domain,normalize,parse_happ,parse_mihomo,route
from engine.network import fetch_one
from engine.policy import classify
from engine.validation import validate,expanded_mihomo
from helpers import PROJECT,fixture,site_bytes,ip_bytes


class NormalizationTests(unittest.TestCase):
    def test_idna(self):
        self.assertEqual(domain('ПРИМЕР.РФ.'),'xn--e1afmkfd.xn--p1ai')
        self.assertEqual(domain('RuTracker.ORG'),'rutracker.org')

    def test_bad_domains(self):
        for value in ['https://x.com','x..com','bad domain.com','-bad.com','x.com/path']:
            with self.subTest(value=value),self.assertRaises(Invalid): domain(value)

    def test_provider_whitespace(self):
        self.assertEqual(parse_mihomo('DOMAIN-SUFFIX, wardxp-mim.vivox.com','DIRECT').value,'wardxp-mim.vivox.com')

    def test_xray_types_distinct(self):
        self.assertEqual(parse_happ('domain:x.com','PROXY','test').kind,'DOMAIN-SUFFIX')
        self.assertEqual(parse_happ('full:x.com','PROXY','test').kind,'DOMAIN')
        self.assertEqual(parse_happ('x.com','PROXY','test').kind,'DOMAIN-KEYWORD')

    def test_exact_dedup_retains_action_type_priority(self):
        values=[Rule('DOMAIN-SUFFIX','x.com','PROXY','a'),Rule('DOMAIN-SUFFIX','x.com','PROXY','b'),
                Rule('DOMAIN','x.com','PROXY','c'),Rule('DOMAIN-SUFFIX','x.com','DIRECT','d'),
                Rule('DOMAIN-SUFFIX','x.com','PROXY','e',10)]
        rules,duplicates=normalize(values)
        self.assertEqual(len(rules),4)
        self.assertEqual(len(duplicates),1)

    def test_nested_coverage_not_substring(self):
        parent=Rule('DOMAIN-SUFFIX','nexus-cdn.com','PROXY','test')
        self.assertTrue(covers(parent,Rule('DOMAIN-SUFFIX','files.nexus-cdn.com','PROXY','test')))
        self.assertFalse(covers(parent,Rule('DOMAIN-SUFFIX','notnexus-cdn.com','PROXY','test')))

    def test_ipv6_and_host_bits(self):
        self.assertEqual(Rule('IP-CIDR','fc00::/7','DIRECT','test').normalized().kind,'IP-CIDR6')
        with self.assertRaises(Invalid): Rule('IP-CIDR','10.1.2.3/8','DIRECT','test').normalized()

    def test_no_process_on_ios(self):
        with tempfile.TemporaryDirectory() as temp:
            root=fixture(temp)
            result=build(root)
            profile=read_json(root/'dist/happ/routing.json')
            self.assertNotIn('.exe',json.dumps(profile))
            self.assertFalse(result['publishable'])

    def test_bad_yaml_duplicate_key(self):
        with tempfile.TemporaryDirectory() as temp:
            path=pathlib.Path(temp)/'bad.yaml'
            for text in ['payload: [oops','payload: [one]\npayload: [two]']:
                path.write_text(text)
                with self.assertRaises(Invalid): load_yaml(path)

    def test_bad_rule_type(self):
        with self.assertRaises(Invalid): parse_mihomo('UNKNOWN,example.com,DIRECT')

    def test_happ_exact_override(self):
        rules=[Rule('DOMAIN-SUFFIX','example.org','DIRECT','override',10),
               Rule('DOMAIN-SUFFIX','example.org','PROXY','personal',20)]
        result=effective_happ(rules)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0].action,'DIRECT')

    def test_happ_unrepresentable_explicit_overlap(self):
        rules=[Rule('DOMAIN','api.example.org','DIRECT','override',10),
               Rule('DOMAIN-SUFFIX','example.org','PROXY','personal',20)]
        with self.assertRaises(Invalid): effective_happ(rules)

    def test_regex_comma_quantifier(self):
        value=r'^[a-z]{2,6}\.example$'
        self.assertEqual(parse_mihomo('DOMAIN-REGEX,'+value,'BLOCK').value,value)
        self.assertEqual(parse_mihomo('DOMAIN-REGEX,'+value+',REJECT').value,value)

    def test_process_case_windows(self):
        self.assertEqual(route([Rule('PROCESS-NAME','Discord.exe','PROXY','test')],process='discord.EXE')[0],'PROXY')

    def test_fake_ip_no_lan_bypass(self):
        with self.assertRaises(Invalid): route([],ip='198.18.1.1')
        rules=[Rule('DOMAIN-SUFFIX','x.com','PROXY','test')]
        self.assertEqual(route(rules,host='x.com',ip='198.18.1.1')[0],'PROXY')


class BinaryTests(unittest.TestCase):
    def test_real_wire_schema_types_and_subset(self):
        data=site_bytes({'twitter':[(2,'x.com'),(3,'t.co'),(0,'twimg'),(1,r'^video\.example$')],
                         'unused':[(2,'unused.invalid')]})
        db=Database(data,'geosite')
        self.assertEqual([r.kind for r in db.rules('twitter','DIRECT')],
                         ['DOMAIN-SUFFIX','DOMAIN','DOMAIN-KEYWORD','DOMAIN-REGEX'])
        selected=Database(db.subset({'twitter'}),'geosite')
        self.assertEqual(set(selected.entries),{'twitter'})
        self.assertEqual(selected.entries['twitter'].raw,db.entries['twitter'].raw)

    def test_missing_category(self):
        db=Database(site_bytes({'twitter':[(2,'x.com')]}),'geosite')
        with self.assertRaises(Invalid): db.require({'ru-blocked'})

    def test_corrupt_truncated_not_html(self):
        for raw in [b'',b'<html>error</html>',b'\x0a\xff',b'\x0a\x10a',b'\x00']:
            with self.subTest(raw=raw),self.assertRaises((Invalid,UnicodeError,ValueError)):
                Database(raw,'geosite')

    def test_geoip_ipv6(self):
        db=Database(ip_bytes({'private':['fc00::/7','192.168.0.0/16']}),'geoip')
        self.assertEqual(db.inventory()['categories']['private'],2)

    def test_inverse_geoip_rejected(self):
        data=message(1,message(1,b'private')+vint(24)+vint(1))
        with self.assertRaises(Invalid): Database(data,'geoip')

    def test_protect_apple(self):
        db=Database(site_bytes({'ru-blocked':[(2,'apple.com'),(2,'x.com')]}),'geosite')
        rules=[Rule('DOMAIN-SUFFIX','apple.com','DIRECT','personal'),Rule('GEOSITE','ru-blocked','PROXY','personal')]
        raw,removed=protect_geosite(db,{'ru-blocked'},rules)
        self.assertEqual([r.value for r in Database(raw,'geosite').rules('ru-blocked','DIRECT')],['x.com'])
        self.assertEqual(len(removed),1)

    def test_broader_proxy_cannot_be_silently_subtracted(self):
        db=Database(site_bytes({'ru-blocked':[(2,'google.com')]}),'geosite')
        rules=[Rule('DOMAIN-SUFFIX','mtalk.google.com','DIRECT','personal'),Rule('GEOSITE','ru-blocked','PROXY','personal')]
        with self.assertRaises(Invalid): protect_geosite(db,{'ru-blocked'},rules)


class ImportTests(unittest.TestCase):
    def test_four_originals_and_friend_counts(self):
        happ,pc,raw,personal,friend,_=load_inputs(PROJECT)
        self.assertEqual(len(personal),330)
        self.assertEqual(len(friend['friend-proxy']),121)
        self.assertEqual(len(friend['friend-direct']),1)
        self.assertEqual(sum(r.kind=='DOMAIN-SUFFIX' for r in friend['friend-proxy']),97)
        self.assertEqual(sum(r.kind=='PROCESS-NAME' for r in friend['friend-proxy']),23)
        self.assertEqual(raw.count('# LEAVE THIS LINE!'),2)

    def test_dangerous_friend_rules_review(self):
        _,_,_,personal,friend,_=load_inputs(PROJECT)
        rules,review,_=classify(personal,friend,load_yaml(PROJECT/'rules/policy.yaml'))
        for kind,value in [('DOMAIN-SUFFIX','gstatic.com'),('DOMAIN-KEYWORD','battleye'),
                           ('PROCESS-NAME','code.exe'),('PROCESS-NAME','Photoshop.exe'),
                           ('PROCESS-NAME','IntelliJ IDEA.exe'),('PROCESS-NAME','Antigravity.exe')]:
            record=next(r for r in review if r['rule']['kind']==kind and r['rule']['value']==value)
            self.assertEqual(record['status'],'REVIEW')
            self.assertFalse(any(r.kind==kind and r.value==value for r in rules))

    def test_opt_in_exact_only(self):
        _,_,_,personal,friend,_=load_inputs(PROJECT)
        policy=load_yaml(PROJECT/'rules/policy.yaml')
        policy['friend-approved']=['DOMAIN-SUFFIX,virustotal.com']
        rules,review,_=classify(personal,friend,policy)
        self.assertTrue(any(r.value=='virustotal.com' for r in rules))
        self.assertFalse(any(r.value=='gstatic.com' for r in rules))

    def test_required_happ_schema(self):
        doc=read_json(PROJECT/'inputs/legacy/happ-current.json')
        validate_happ(doc)
        doc.pop('RouteOrder')
        with self.assertRaises(Invalid): validate_happ(doc)

    def test_all_personal_keys_preserved(self):
        _,_,_,personal,friend,_=load_inputs(PROJECT)
        rules,_,_=classify(personal,friend,load_yaml(PROJECT/'rules/policy.yaml'))
        keys={(r.kind,r.value,r.action) for r in rules}
        self.assertTrue(all((r.kind,r.value,r.action) in keys for r in personal))


class FetchTests(unittest.TestCase):
    source={'id':'test','url':'https://example.invalid/test.dat','format':'geosite'}

    def test_no_cache_download_failure(self):
        with tempfile.TemporaryDirectory() as temp,patch('engine.network.request',side_effect=OSError('offline')):
            with self.assertRaises(Invalid): fetch_one(self.source,temp,retries=0)

    def test_verified_cache_fallback_and_checksum(self):
        raw=site_bytes({'twitter':[(2,'x.com')]})
        with tempfile.TemporaryDirectory() as temp:
            with patch('engine.network.request',return_value=(raw,{'ETag':'test'},self.source['url'])):
                first=fetch_one(self.source,temp,{'twitter'},retries=0)
            with patch('engine.network.request',side_effect=OSError('offline')):
                last=fetch_one(self.source,temp,{'twitter'},retries=0)
            self.assertEqual(last['sha256'],first['sha256'])
            self.assertEqual(last['retrieval'],'verified-stale-cache')
            (pathlib.Path(temp)/'test.bin').write_bytes(b'corrupted')
            with self.assertRaises(Invalid): fetch_one(self.source,temp,offline=True)

    def test_missing_category_never_cached(self):
        raw=site_bytes({'twitter':[(2,'x.com')]})
        with tempfile.TemporaryDirectory() as temp,patch('engine.network.request',return_value=(raw,{},self.source['url'])):
            with self.assertRaises(Invalid): fetch_one(self.source,temp,{'ru-blocked'},retries=0)
            self.assertFalse((pathlib.Path(temp)/'test.bin').exists())

    def test_conditional_304(self):
        raw=site_bytes({'twitter':[(2,'x.com')]})
        with tempfile.TemporaryDirectory() as temp:
            with patch('engine.network.request',return_value=(raw,{'ETag':'etag'},self.source['url'])):
                fetch_one(self.source,temp,retries=0)
            with patch('engine.network.request',side_effect=urllib.error.HTTPError(self.source['url'],304,'same',{},None)) as request:
                result=fetch_one(self.source,temp,retries=0)
            self.assertEqual(result['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(request.call_args.args[1],{'If-None-Match':'etag'})

    def test_pin_resolves_commit_before_immutable_download(self):
        raw=site_bytes({'twitter':[(2,'x.com')]})
        revision='a'*40
        source={**self.source,'pin-api':'https://example.invalid/api',
                'pin-template':'https://example.invalid/{sha}/test.dat'}
        def response(url,*args):
            if url==source['pin-api']:
                return json.dumps({'sha':revision,'commit':{'committer':{'date':'2026-10-30T20:00:00Z'}}}).encode(),{},url
            self.assertEqual(url,'https://example.invalid/'+revision+'/test.dat')
            return raw,{},url
        with tempfile.TemporaryDirectory() as temp,patch('engine.network.request',side_effect=response):
            result=fetch_one(source,temp,{'twitter'},retries=0)
        self.assertEqual(result['revision'],revision)

    def test_offline_no_network(self):
        with tempfile.TemporaryDirectory() as temp,patch('engine.network.request') as request:
            with self.assertRaises(Invalid): fetch_one(self.source,temp,offline=True)
            request.assert_not_called()


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=fixture(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()

    def test_end_to_end_offline_smoke_and_golden_outputs(self):
        with patch('engine.network.request',side_effect=AssertionError('must stay offline')):
            result=build(self.root)
            validation=validate(self.root)
        self.assertGreaterEqual(validation['golden_cases'],70)
        self.assertEqual(validation['golden_failures'],0)
        profile=read_json(self.root/'dist/happ/routing.json')
        self.assertEqual(profile['UseChunkFiles'],'true')
        self.assertEqual(profile['RouteOrder'],'block-proxy-direct')
        original=read_json(self.root/'inputs/legacy/happ-current.json')
        for key in ['DnsHosts','RemoteDNSType','RemoteDNSIP','RemoteDNSDomain','DomesticDNSType',
                    'DomesticDNSIP','DomesticDNSDomain','DomainStrategy','GlobalProxy','FakeDNS']:
            self.assertEqual(profile[key],original[key])
        pc=load_yaml(self.root/'dist/mihomo/config.yaml')
        self.assertEqual(pc['dns'],load_yaml(self.root/'inputs/legacy/mihomo-current.yaml')['dns'])
        self.assertEqual(pc['rules'][-1],'MATCH,DIRECT')

    def test_noop_keeps_lastupdated_and_fingerprint(self):
        first=build(self.root)
        second=build(self.root,previous=self.root/'dist')
        self.assertFalse(second['changed'])
        self.assertEqual(first['updated_at'],second['updated_at'])
        self.assertEqual(first['fingerprint'],second['fingerprint'])

    def test_failed_build_keeps_dist(self):
        build(self.root)
        before=(self.root/'dist/happ/routing.json').read_bytes()
        path=self.root/'.cache/upstream/historical-geosite.bin'
        path.write_bytes(b'corrupt')
        with self.assertRaises(Invalid): build(self.root)
        self.assertEqual((self.root/'dist/happ/routing.json').read_bytes(),before)

    def test_no_classical_mrs(self):
        build(self.root)
        pc=load_yaml(self.root/'dist/mihomo/config.yaml')
        self.assertTrue(all(p['format']!='mrs' for p in pc['rule-providers'].values() if p['behavior']=='classical'))

    def test_router_keeps_domains_ips_and_disables_processes(self):
        build(self.root)
        router=load_yaml(self.root/'dist/mihomo-router/config.yaml')
        pc=expanded_mihomo(self.root/'dist/mihomo')
        rules=expanded_mihomo(self.root/'dist/mihomo-router')
        self.assertEqual(router['find-process-mode'],'off')
        self.assertEqual({r.key for r in rules},{r.key for r in pc if r.kind!='PROCESS-NAME'})
        self.assertTrue(any(r.kind=='DOMAIN-SUFFIX' for r in rules))
        self.assertTrue(any(r.kind in {'IP-CIDR','IP-CIDR6'} for r in rules))
        self.assertEqual(route(rules,host='example.net',process='WardogsClient-Win64-Shipping.exe')[0],'DIRECT')
        self.assertEqual(route(pc,host='example.net',process='WardogsClient-Win64-Shipping.exe')[0],'PROXY')
        self.assertEqual((self.root/'dist/mihomo-router/config.yaml').read_text().count('# LEAVE THIS LINE!'),2)
        pc_config=load_yaml(self.root/'dist/mihomo/config.yaml')
        self.assertLess(set(router['rule-providers']),set(pc_config['rule-providers']))
        for name in router['rule-providers']:
            for file in (self.root/'dist/mihomo-router/providers').glob(name+'.*'):
                self.assertEqual(file.read_bytes(),(self.root/'dist/mihomo/providers'/file.name).read_bytes())

    def test_secret_scan(self):
        file=self.root/'secret.yaml'
        file.write_text('uuid: '+'1'*8+'-'+'2'*4+'-'+'3'*4+'-'+'4'*4+'-'+'5'*12)
        with self.assertRaises(Invalid): scan_secrets(self.root)
        file.write_text('payload:\n- aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.example.com\n')
        scan_secrets(self.root)

    def test_import_link_roundtrip(self):
        import base64
        build(self.root)
        link=(self.root/'dist/happ/import-link.txt').read_text().strip()
        doc=json.loads(base64.b64decode(link.removeprefix('happ://routing/add/')))
        self.assertEqual(doc,read_json(self.root/'dist/happ/routing.json'))

    def test_block_before_personal_before_process_before_categories(self):
        _,_,_,personal,friend,_=load_inputs(self.root)
        rules,_,_=classify(personal,friend,load_yaml(self.root/'rules/policy.yaml'))
        priorities=[r.priority for r in rules]
        self.assertEqual(priorities,sorted(priorities))
        self.assertTrue(all(r.priority==0 for r in rules if r.action=='BLOCK'))
        self.assertTrue(all(r.priority==30 for r in rules if r.kind=='PROCESS-NAME'))


if __name__=='__main__': unittest.main()
