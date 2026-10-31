import base64
import copy
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from helpers import PROJECT
from engine.model import Invalid
from scripts.sync_remnawave import NoRedirect,Panel,FILES,synchronize,verified_candidate

PC='11111111-1111-4111-8111-111111111111'
ROUTER='22222222-2222-4222-8222-222222222222'
SETTINGS='33333333-3333-4333-8333-333333333333'


def encode_profile(updated=100,name='2Baikal-Routing'):
    profile=json.loads((PROJECT/'inputs/legacy/happ-current.json').read_text(encoding='utf-8'))
    profile.update(Name=name,LastUpdated=str(updated))
    return 'happ://routing/add/'+base64.b64encode(json.dumps(profile).encode()).decode()


class FakePanel:
    def __init__(self):
        self.templates={key:{'uuid':key,'templateType':'MIHOMO','name':name,
            'encodedTemplateYaml':base64.b64encode(('old '+name).encode()).decode()}
            for key,name in [(PC,'Default'),(ROUTER,'Router')]}
        self.settings={'uuid':SETTINGS,'customResponseHeaders':{
            'routing':encode_profile(),'profile-title':'keep me','custom-other':'preserve'},
            'serveJsonAtBaseSubscription':True,'hwidSettings':{'keep':'unchanged'}}
        self.writes=[]
        self.fail=None

    def request(self,path,method='GET',body=None):
        if method=='GET':
            return copy.deepcopy(self.settings if path=='/subscription-settings'
                                 else self.templates[path.rsplit('/',1)[1]])
        self.writes.append((path,copy.deepcopy(body)))
        if path=='/subscription-templates':
            self.templates[body['uuid']]['encodedTemplateYaml']=body['encodedTemplateYaml']
            target=body['uuid']
        else:
            self.settings['customResponseHeaders']=copy.deepcopy(body['customResponseHeaders'])
            target='happ'
        # Simulate the server applying a PATCH, then losing its response.
        if self.fail==target:
            self.fail=None
            raise Invalid('Simulated lost PATCH response')
        return self.request('/subscription-settings' if target=='happ'
                            else '/subscription-templates/'+target)


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.panel=FakePanel()
        self.candidate={'pc':'new PC','router':'new Router','happ':encode_profile(101)}

    def test_updates_both_templates_and_merges_only_routing(self):
        before=copy.deepcopy(self.panel.settings)
        self.assertEqual(synchronize(self.panel,self.candidate,PC,ROUTER),
                         {'pc':True,'router':True,'happ':True})
        for role,key in [('pc',PC),('router',ROUTER)]:
            self.assertEqual(base64.b64decode(self.panel.templates[key]['encodedTemplateYaml']).decode(),
                             self.candidate[role])
        before['customResponseHeaders']['routing']=self.candidate['happ']
        self.assertEqual(self.panel.settings,before)
        for path,body in self.panel.writes:
            self.assertEqual(set(body),{'uuid','encodedTemplateYaml'} if path.endswith('templates')
                             else {'uuid','customResponseHeaders'})

    def test_second_run_is_idempotent(self):
        synchronize(self.panel,self.candidate,PC,ROUTER)
        self.panel.writes.clear()
        self.assertEqual(synchronize(self.panel,self.candidate,PC,ROUTER),
                         {'pc':False,'router':False,'happ':False})
        self.assertFalse(self.panel.writes)

    def test_dry_run_does_not_write(self):
        self.assertTrue(synchronize(self.panel,self.candidate,PC,ROUTER,dry_run=True)['router'])
        self.assertFalse(self.panel.writes)

    def test_uncertain_patch_failures_restore_previous_values(self):
        for target in [PC,ROUTER,'happ']:
            with self.subTest(target=target):
                panel=FakePanel()
                before=(copy.deepcopy(panel.templates),copy.deepcopy(panel.settings))
                panel.fail=target
                with self.assertRaisesRegex(Invalid,'lost PATCH'):
                    synchronize(panel,self.candidate,PC,ROUTER)
                self.assertEqual((panel.templates,panel.settings),before)

    def test_newer_or_unrelated_happ_profile_stops_all_writes(self):
        for link in [encode_profile(200),encode_profile(100,'Another profile')]:
            self.panel.settings['customResponseHeaders']['routing']=link
            with self.assertRaises(Invalid): synchronize(self.panel,self.candidate,PC,ROUTER)
            self.assertFalse(self.panel.writes)

    def test_separate_mihomo_targets_required(self):
        with self.assertRaises(Invalid): synchronize(self.panel,self.candidate,PC,PC)
        self.panel.templates[ROUTER]['templateType']='XRAY_JSON'
        with self.assertRaises(Invalid): synchronize(self.panel,self.candidate,PC,ROUTER)
        self.assertFalse(self.panel.writes)

    def test_token_is_never_redirected_or_sent_to_http(self):
        with self.assertRaises(Invalid): Panel('http://panel.example','secret')
        with self.assertRaises(Invalid): Panel('https://user:password@panel.example','secret')
        with self.assertRaises(Invalid): NoRedirect().redirect_request(None,None,302,'',{},'https://other.example')

    def test_tampered_candidate_is_rejected_before_panel_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            assets=pathlib.Path(temporary)
            meta={'repository':'example/routing','publishable':True,'version':'routing-test'}
            (assets/'release.json').write_text(json.dumps(meta))
            published={'tag_name':'routing-test','draft':False,'prerelease':False,'assets':[]}
            for role,name in FILES.items():
                raw=self.candidate[role].encode()
                (assets/name).write_bytes(raw)
                published['assets'].append({'name':name,'size':len(raw),
                                            'digest':'sha256:'+hashlib.sha256(raw).hexdigest()})
            with patch('scripts.sync_remnawave.github_api',side_effect=[
                    {'object':{'sha':'a'*40}},published]):
                self.assertEqual(verified_candidate('example/routing','a'*40,assets)['happ'],self.candidate['happ'])
            (assets/FILES['router']).write_text('tampered')
            with patch('scripts.sync_remnawave.github_api',side_effect=[
                    {'object':{'sha':'a'*40}},published]),self.assertRaisesRegex(Invalid,'checksum mismatch'):
                verified_candidate('example/routing','a'*40,assets)


if __name__=='__main__': unittest.main()
