"""Published assets must stay untouched when only installation notes change."""
import hashlib
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from scripts import release


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dest=pathlib.Path(self.temp.name)
        self.files={'mihomo-config.yaml':'proxies: # LEAVE THIS LINE!\nrules: [MATCH,DIRECT]\n',
                    'mihomo-router-config.yaml':"find-process-mode: 'off'\nproxies: # LEAVE THIS LINE!\nrules: [MATCH,DIRECT]\n",
                    'happ-import-link.txt':'happ://routing/add/ZXhhbXBsZQ==\n'}
        for name,text in self.files.items():
            (self.dest/name).write_text(text,encoding='utf-8',newline='\n')
        self.meta={'repository':'example/routing','version':'routing-test',
                   'publishable':True,'counts':{'personal':330}}
        self.existing={'id':123,'tag_name':'routing-test','draft':False,'body':'old notes',
                       'html_url':'https://github.com/example/routing/releases/tag/routing-test',
                       'assets':[{'name':name,'digest':'sha256:'+hashlib.sha256(text.encode()).hexdigest()}
                                 for name,text in self.files.items()]}

    def publish(self,existing=None,head='source-head'):
        def response(path,method='GET',body=None,raw=None):
            if path.endswith('/git/ref/heads/main'): return {'object':{'sha':head}}
            if '/releases/tags/' in path: return existing or self.existing
            if method=='PATCH' and path.endswith('/releases/123'): return {}
            raise AssertionError('Unexpected GitHub mutation: '+method+' '+path)
        with patch.object(release,'prepare',return_value=(self.meta,self.dest)), \
             patch.object(release,'read_json',return_value={'changed':False}), \
             patch.object(release,'api',side_effect=response) as api:
            release.publish('example/routing','source-head')
        return api

    def test_unchanged_payload_only_patches_copyable_notes(self):
        api=self.publish()
        writes=[call for call in api.call_args_list if len(call.args)>1 and call.args[1]!='GET']
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0].args[:2],('/repos/example/routing/releases/123','PATCH'))
        self.assertEqual(set(writes[0].args[2]),{'body'})
        body=writes[0].args[2]['body']
        for text in self.files.values(): self.assertIn(text,body)
        self.assertIn('<details>',body)
        self.assertIn('/releases/download/routing-test/',body)
        for name,text in self.files.items(): self.assertEqual((self.dest/name).read_bytes(),text.encode())

    def test_same_notes_do_not_write_again(self):
        self.existing['body']=release.release_notes(self.meta,self.dest)
        api=self.publish()
        self.assertTrue(all(len(call.args)==1 for call in api.call_args_list))

    def test_refuses_notes_if_published_bytes_differ(self):
        self.existing['assets'][0]['digest']='sha256:'+'0'*64
        with self.assertRaisesRegex(release.Invalid,'Published configuration differs'):
            self.publish()

    def test_moved_main_does_not_edit_existing_release(self):
        with self.assertRaisesRegex(release.Invalid,'main moved'):
            self.publish(head='newer-head')


if __name__=='__main__': unittest.main()
