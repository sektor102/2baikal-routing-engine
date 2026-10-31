"""Human service names and conservative, first-match-preserving compaction."""
from dataclasses import dataclass,field
import ipaddress
import re

from .model import Invalid,covers,domain

DOMAIN_TYPES={'DOMAIN','DOMAIN-SUFFIX'}
IP_TYPES={'IP-CIDR','IP-CIDR6'}
STAGES={0:'security',10:'overrides',20:'personal',30:'apps',60:'approved',80:'categories'}
CATEGORY_NAMES={'win-spy':('windows-telemetry','Windows telemetry'),
                'category-ads':('advertising','Advertising'),
                'category-ru':('russian-services','Russian services'),
                'ru-blocked':('ru-blocked','Ru-blocked category'),
                'ru-available-only-inside':('russia-only','Russia-only category'),
                'private':('local-network','Local networks'),
                'escapefromtarkov':('tarkov','Escape from Tarkov'),
                'epicgames':('epic-games','Epic Games'),
                'github':('github','GitHub'),'youtube':('youtube','YouTube'),
                'twitter':('twitter','Twitter / X'),'telegram':('telegram','Telegram'),
                'apple':('apple','Apple / iCloud'),'microsoft':('microsoft','Microsoft'),
                'steam':('steam','Steam'),'riot':('riot','Riot Games'),
                'pinterest':('pinterest','Pinterest'),'faceit':('faceit','FACEIT'),
                'google-play':('google-play','Google Play')}


def slug(value):
    return re.sub('[^a-z0-9]+','-',value.lower()).strip('-') or 'custom'


class Catalog:
    def __init__(self,data):
        if data.get('version')!=1 or not isinstance(data.get('services'),dict):
            raise Invalid('Invalid service-groups catalog')
        self.domains={}
        self.processes={}
        self.networks=[]
        self.titles={}
        for name,entry in data['services'].items():
            if not re.fullmatch('[a-z][a-z0-9-]{0,63}',name): raise Invalid('Invalid service name')
            self.titles[name]=entry.get('title',name)
            if not isinstance(self.titles[name],str) or '\n' in self.titles[name] or '\r' in self.titles[name]:
                raise Invalid('Invalid service title')
            for value in entry.get('domains',[]):
                root=domain(value)
                if root in self.domains: raise Invalid('Duplicate service domain: '+root)
                self.domains[root]=name
            for value in entry.get('processes',[]):
                key=value.casefold()
                if key in self.processes: raise Invalid('Duplicate service process: '+value)
                self.processes[key]=name
            for value in entry.get('networks',[]):
                net=ipaddress.ip_network(value,strict=True)
                if any(net==previous for previous,_ in self.networks): raise Invalid('Duplicate service network')
                self.networks.append((net,name))

    def service(self,rule):
        if rule.kind in {'GEOSITE','GEOIP'}:
            return CATEGORY_NAMES.get(rule.value,(slug(rule.value),rule.value))
        if rule.kind=='PROCESS-NAME':
            name=self.processes.get(rule.value.casefold())
            return (name,self.titles[name]) if name else (slug(rule.value.removesuffix('.exe')),rule.value)
        if rule.kind in IP_TYPES:
            net=ipaddress.ip_network(rule.value)
            known=[(root.prefixlen,name) for root,name in self.networks
                   if root.version==net.version and net.subnet_of(root)]
            if known:
                name=max(known)[1]
                return name,self.titles[name]
            return 'network-exceptions','Network exceptions'
        if rule.kind in DOMAIN_TYPES or rule.kind=='DOMAIN-KEYWORD':
            try: value=domain(rule.value)
            except Invalid: return 'domain-patterns','Domain patterns'
            roots=[root for root in self.domains if value==root or value.endswith('.'+root)]
            if roots:
                name=self.domains[max(roots,key=len)]
                return name,self.titles[name]
            return slug(value),value
        return 'domain-patterns','Domain patterns'


def may_overlap(a,b):
    """False means proven disjoint. Unknown cases MUST return True."""
    if a.kind in DOMAIN_TYPES and b.kind in DOMAIN_TYPES:
        return covers(a,b) or covers(b,a)
    if a.kind in IP_TYPES and b.kind in IP_TYPES:
        first,second=ipaddress.ip_network(a.value),ipaddress.ip_network(b.value)
        return first.version==second.version and first.overlaps(second)
    if a.kind=='PROCESS-NAME' and b.kind=='PROCESS-NAME':
        return a.value.casefold()==b.value.casefold()
    if a.kind=='DOMAIN' and b.kind=='DOMAIN-KEYWORD': return b.value in a.value
    if b.kind=='DOMAIN' and a.kind=='DOMAIN-KEYWORD': return a.value in b.value
    # A suffix may have a subdomain containing any keyword. Domain and IP may
    # match the same connection. Geo categories, regex and processes are broad.
    return True


def family(rule):
    if rule.kind in DOMAIN_TYPES: return 'domain'
    if rule.kind in IP_TYPES: return 'ip'
    return 'classical'


@dataclass
class Group:
    service:str
    title:str
    action:str
    priority:int
    kind:str
    indices:list[int]=field(default_factory=list)
    provider:bool=False
    name:str=''


def verify_layout(rules,groups):
    """Independent certificate: no possibly overlapping opposite actions swap."""
    flattened=[i for group in groups for i in group.indices]
    if sorted(flattened)!=list(range(len(rules))): raise Invalid('Service layout lost or duplicated a rule')
    if [rules[i].priority for i in flattened]!=sorted(r.priority for r in rules):
        raise Invalid('Service layout crossed a priority boundary')
    positions={rule_index:position for position,rule_index in enumerate(flattened)}
    protected=0
    reordered=0
    for i,a in enumerate(rules):
        for j in range(i+1,len(rules)):
            b=rules[j]
            if a.action!=b.action and may_overlap(a,b):
                protected+=1
                if positions[i]>positions[j]:
                    raise Invalid('Service layout changed overlapping rule precedence: '+a.value+' / '+b.value)
            if positions[i]>positions[j]: reordered+=1
    return {'status':'passed','rules':len(rules),'protected_pairs':protected,
            'safe_reordered_pairs':reordered}


def organize(rules,catalog):
    groups=[]
    last={}
    for i,rule in enumerate(rules):
        service,title=catalog.service(rule)
        if rule.kind in {'GEOSITE','GEOIP'}:
            groups.append(Group(service,title,rule.action,rule.priority,rule.kind,[i],True))
            continue
        key=(service,title,rule.action,rule.priority,family(rule))
        previous=last.get(key)
        safe=previous is not None and all(
            rules[j].priority==rule.priority and
            (rules[j].action==rule.action or not may_overlap(rule,rules[j]))
            for group in groups[previous+1:] for j in group.indices)
        if safe: groups[previous].indices.append(i)
        else:
            last[key]=len(groups)
            groups.append(Group(service,title,rule.action,rule.priority,family(rule),[i]))
    # Only the largest safe fragment gets a provider. Small fragments remain
    # explicit rules at their certified position, avoiding numbered split files.
    largest={}
    for i,group in enumerate(groups):
        if group.kind in {'GEOSITE','GEOIP'}: continue
        key=(group.service,group.title,group.action,group.priority,group.kind)
        if key not in largest or len(group.indices)>len(groups[largest[key]].indices): largest[key]=i
    used=set()
    for i,group in enumerate(groups):
        stage=group.kind.lower() if group.kind in {'GEOSITE','GEOIP'} else STAGES.get(group.priority,'custom')
        group.name=f'{group.service}-{group.action.lower()}-{stage}'
        if group.kind not in {'GEOSITE','GEOIP'}:
            key=(group.service,group.title,group.action,group.priority,group.kind)
            unique={(rules[j].kind,rules[j].value,rules[j].options) for j in group.indices}
            group.provider=largest[key]==i and len(unique)>=2 and len(group.name)<180
        if group.provider:
            key=(group.name,group.kind)
            if key in used: raise Invalid('Readable ruleset name collision: '+group.name)
            used.add(key)
    certificate=verify_layout(rules,groups)
    return groups,certificate


def legacy_provider_count(rules,site_db,ip_db,router=False):
    """Before/after metric using the previous consecutive-run partition."""
    runs=[]
    for rule in rules:
        if rule.kind in {'GEOSITE','GEOIP'}: runs.append([rule])
        elif runs and runs[-1][0].kind not in {'GEOSITE','GEOIP'} and \
                (runs[-1][0].priority,runs[-1][0].action)==(rule.priority,rule.action): runs[-1].append(rule)
        else: runs.append([rule])
    count=0
    for run in runs:
        if run[0].kind in {'GEOSITE','GEOIP'}:
            rule=run[0]
            database=site_db if rule.kind=='GEOSITE' else ip_db
            run=list(database.rules(rule.value,rule.action))
        count+=len({family(r) for r in run if not router or r.kind!='PROCESS-NAME'})
    return count
