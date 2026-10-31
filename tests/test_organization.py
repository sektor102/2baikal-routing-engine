import copy
import random
import unittest

from engine.model import Invalid,Rule,route
from engine.organization import Catalog,Group,may_overlap,organize,verify_layout


def catalog():
    return Catalog({'version':1,'services':{
        'example':{'title':'Example','domains':['example.com'],'processes':['Example.exe','Helper.exe']},
        'other':{'title':'Other','domains':['other.org']}}})


class OrganizationTests(unittest.TestCase):
    def test_merges_disjoint_services_without_numeric_names(self):
        rules=[Rule('DOMAIN-SUFFIX','a.example.com','PROXY','test'),
               Rule('DOMAIN-SUFFIX','other.org','DIRECT','test'),
               Rule('DOMAIN-SUFFIX','b.example.com','PROXY','test')]
        groups,proof=organize(rules,catalog())
        self.assertEqual(groups[0].indices,[0,2])
        self.assertTrue(groups[0].provider)
        self.assertEqual(groups[0].name,'example-proxy-personal')
        self.assertEqual(proof['status'],'passed')

    def test_domain_ip_barrier_retains_first_match(self):
        rules=[Rule('DOMAIN','a.example.com','PROXY','test'),
               Rule('IP-CIDR','10.0.0.0/8','DIRECT','test'),
               Rule('DOMAIN','b.example.com','PROXY','test')]
        groups,_=organize(rules,catalog())
        self.assertEqual([g.indices for g in groups],[[0],[1],[2]])
        self.assertFalse(any(g.provider for g in groups))
        actual=[rules[i] for g in groups for i in g.indices]
        self.assertEqual(route(actual,host='a.example.com',ip='10.1.2.3')[0],'PROXY')
        self.assertEqual(route(actual,host='b.example.com',ip='10.1.2.3')[0],'DIRECT')
        unsafe=[Group('', '', '', 0, '', [0,2]),Group('', '', '', 0, '', [1])]
        with self.assertRaisesRegex(Invalid,'overlapping rule precedence'): verify_layout(rules,unsafe)

    def test_priority_layers_never_merge(self):
        rules=[Rule('DOMAIN-SUFFIX','a.example.com','PROXY','test',10),
               Rule('DOMAIN-SUFFIX','b.example.com','PROXY','test',20)]
        groups,_=organize(rules,catalog())
        self.assertEqual(len(groups),2)
        self.assertNotEqual(groups[0].name,groups[1].name)

    def test_unknown_overlap_is_conservative(self):
        suffix=Rule('DOMAIN-SUFFIX','example.com','DIRECT','test')
        for kind,value in [('DOMAIN-KEYWORD','other'),('DOMAIN-REGEX',r'^other\..*$'),
                           ('GEOSITE','twitter'),('GEOIP','private'),('PROCESS-NAME','Other.exe')]:
            self.assertTrue(may_overlap(suffix,Rule(kind,value,'PROXY','test')))
        self.assertFalse(may_overlap(suffix,Rule('DOMAIN-SUFFIX','notexample.com','PROXY','test')))
        self.assertFalse(may_overlap(Rule('IP-CIDR','10.0.0.0/8','DIRECT','test'),
                                     Rule('IP-CIDR6','fc00::/7','PROXY','test')))
        self.assertTrue(may_overlap(Rule('PROCESS-NAME','Example.exe','DIRECT','test'),
                                    Rule('PROCESS-NAME','EXAMPLE.EXE','PROXY','test')))

    def test_longest_domain_mapping_and_catalog_do_not_add_routes(self):
        data={'version':1,'services':{'parent':{'domains':['example.com']},
                                    'child':{'domains':['api.example.com']}}}
        cat=Catalog(data)
        rule=Rule('DOMAIN-SUFFIX','x.api.example.com','PROXY','test')
        before=rule.record()
        self.assertEqual(cat.service(rule)[0],'child')
        self.assertEqual(len(organize([rule],cat)[0]),1)
        self.assertEqual(rule.record(),before)

    def test_certificate_rejects_missing_duplicate_and_cross_priority_rules(self):
        rules=[Rule('DOMAIN-SUFFIX','example.com','PROXY','test',10),
               Rule('DOMAIN-SUFFIX','other.org','DIRECT','test',20)]
        for indices in [[0],[0,0],[1,0]]:
            with self.subTest(indices=indices),self.assertRaises(Invalid):
                verify_layout(rules,[Group('', '', '', 0, '', indices)])

    def test_differential_mixed_domain_ip_process_cases(self):
        rng=random.Random(2048)
        possibilities=[('DOMAIN','a.example.com'),('DOMAIN-SUFFIX','example.com'),
                       ('DOMAIN-SUFFIX','other.org'),('DOMAIN-KEYWORD','other'),
                       ('DOMAIN-REGEX',r'^b\..*'),('IP-CIDR','10.0.0.0/8'),
                       ('IP-CIDR','10.1.0.0/16'),('IP-CIDR6','fc00::/7'),
                       ('PROCESS-NAME','Example.exe'),('PROCESS-NAME','Helper.exe')]
        cases=[{'host':host,'ip':ip,'process':process}
               for host in ['a.example.com','b.example.com','notexample.com','other.org','x.other.org']
               for ip in ['10.1.2.3','203.0.113.1','fd00::1']
               for process in ['EXAMPLE.EXE','Helper.exe','Unknown.exe']]
        for _ in range(30):
            rules=[]
            for i in range(18):
                kind,value=rng.choice(possibilities)
                rules.append(Rule(kind,value,rng.choice(['PROXY','DIRECT','BLOCK']),'test',20,index=i))
            groups,_=organize(rules,catalog())
            actual=[rules[i] for group in groups for i in group.indices]
            for case in cases: self.assertEqual(route(actual,**case)[0],route(rules,**case)[0])


if __name__=='__main__': unittest.main()
