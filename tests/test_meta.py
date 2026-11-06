import hashlib
import tempfile
import unittest

from engine.compiler import build,route_happ,unblock_geosite
from engine.geodata import Database,message
from engine.io import load_yaml,read_json,write_json
from engine.model import Invalid,Rule,route
from engine.validation import expanded_mihomo,validate
from helpers import fixture,site_bytes

ENDPOINTS=['graph.whatsapp.com','graph.whatsapp.net']
META=['meta.com','meta.ai','metaaiusercontent.com','metaaivm.com','atmeta.com','llama.com','muse.ai',
      'fb.watch','fbcdn.com','fbsbx.net','tfbnw.net','m.me','msngr.com','ig.me','igcdn.com','igsonar.com']


def rules():
    return [Rule('GEOSITE','category-ads','BLOCK','test',0)]+[
        Rule('DOMAIN-SUFFIX',host,'PROXY','policy:overrides',10) for host in ENDPOINTS]


class BlockExceptionTests(unittest.TestCase):
    def test_remove_only_approved_subtrees_and_keep_other_categories(self):
        db=Database(site_bytes({'category-ads':[(2,h) for h in ENDPOINTS+[
            'sub.graph.whatsapp.net','ads.whatsapp.net','evilgraph.whatsapp.net','graph.instagram.com','ads-twitter.com']],
            'other':[(2,'graph.whatsapp.net')]}),'geosite')
        raw,removed=unblock_geosite(db,rules(),ENDPOINTS)
        result=Database(raw,'geosite')
        self.assertEqual({r.value for r in result.rules('category-ads','BLOCK')},
                         {'ads.whatsapp.net','evilgraph.whatsapp.net','graph.instagram.com','ads-twitter.com'})
        self.assertEqual(len(removed),3)
        self.assertEqual(result.entries['other'].raw,db.entries['other'].raw)

    def test_empty_exceptions_preserve_raw_database(self):
        raw=site_bytes({'category-ads':[(2,ENDPOINTS[0])]})
        self.assertEqual(unblock_geosite(Database(raw,'geosite'),rules(),[]),(raw,[]))

    def test_matching_proxy_override_required(self):
        db=Database(site_bytes({'category-ads':[(2,ENDPOINTS[0])]}),'geosite')
        for candidates in [rules()[:1],[*rules()[:1],Rule('DOMAIN-SUFFIX',ENDPOINTS[0],'PROXY','personal',20)]]:
            with self.subTest(candidates=candidates),self.assertRaisesRegex(Invalid,'explicit PROXY'):
                unblock_geosite(db,candidates,[ENDPOINTS[0]])

    def test_broader_blocking_rules_fail_without_weakening_security(self):
        for kind,value in [(2,'whatsapp.net'),(0,'whatsapp'),(1,r'.*whatsapp\.net$')]:
            db=Database(site_bytes({'category-ads':[(kind,value)]}),'geosite')
            with self.subTest(kind=kind),self.assertRaisesRegex(Invalid,'broader BLOCK'):
                unblock_geosite(db,rules(),ENDPOINTS)

    def test_duplicate_or_noncanonical_exceptions_rejected(self):
        db=Database(site_bytes({'category-ads':[(2,ENDPOINTS[0])]}),'geosite')
        for domains in [[ENDPOINTS[0],ENDPOINTS[0]],['GRAPH.WHATSAPP.COM'],'graph.whatsapp.com']:
            with self.subTest(domains=domains),self.assertRaises(Invalid):
                unblock_geosite(db,rules(),domains)

    def test_rendered_pc_router_and_happ_routes_with_real_block_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=fixture(temporary)
            path=root/'.cache/upstream/historical-geosite.bin'
            original=Database(path.read_bytes(),'geosite')
            raw=b''.join(message(1,entry.raw) for name,entry in sorted(original.entries.items())
                         if name!='category-ads')+site_bytes({'category-ads':[(2,h) for h in ENDPOINTS+[
                             'ads.whatsapp.net','graph.instagram.com','ads-twitter.com']]})
            path.write_bytes(raw)
            records=read_json(root/'reports/upstream.json')
            record=next(r for r in records if r['id']=='historical-geosite')
            record.update(Database(raw,'geosite').inventory())
            record['sha256']=hashlib.sha256(raw).hexdigest()
            write_json(root/'reports/upstream.json',records)
            write_json(path.with_suffix('.json'),record)
            build(root)
            self.assertEqual(validate(root)['golden_failures'],0)
            site=Database((root/'dist/geosite.dat').read_bytes(),'geosite')
            profile=read_json(root/'dist/happ/routing.json')
            clients=[expanded_mihomo(root/'dist'/family) for family in ['mihomo','mihomo-router']]
            for host in META+ENDPOINTS+['probe.'+h for h in META+ENDPOINTS]:
                for client in clients:
                    self.assertEqual(route(client,host=host)[0],'PROXY',host)
                self.assertEqual(route_happ(profile,host=host,geosite=site)[0],'PROXY',host)
            for host in ['ads.whatsapp.net','graph.instagram.com','ads-twitter.com']:
                for client in clients: self.assertEqual(route(client,host=host)[0],'BLOCK',host)
                self.assertEqual(route_happ(profile,host=host,geosite=site)[0],'BLOCK',host)
            removed=read_json(root/'reports/conflicts.json')['geosite_block_exceptions']
            self.assertEqual({r['removed']['value'] for r in removed},set(ENDPOINTS))
            self.assertFalse(any(r.kind=='PROCESS-NAME' for r in clients[1]))


if __name__=='__main__': unittest.main()
