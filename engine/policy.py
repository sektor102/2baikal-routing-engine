from __future__ import annotations

from collections import Counter
from dataclasses import replace

from .model import Invalid, covers, normalize, parse_mihomo


def classify(personal, friend, policy):
    approved=set(policy.get('friend-approved',[]))
    denied=set(policy.get('friend-denied',[]))
    if approved & denied: raise Invalid('Same friend rule approved and denied')
    additions=[]
    review=[]
    for source,rules in friend.items():
        for rule in rules:
            key=rule.kind+','+rule.value
            same=[p for p in personal if p.action==rule.action and covers(p,rule)]
            if rule.kind=='PROCESS-NAME':
                same=[p for p in personal if p.kind==rule.kind and p.action==rule.action and p.value.casefold()==rule.value.casefold()]
            reason='new source rule requires explicit opt-in'
            if key in denied: status='DENIED'
            elif same: status='COVERED'
            elif key in approved: status='APPROVED'
            else: status='REVIEW'
            if rule.kind=='PROCESS-NAME': reason='new Windows process: all its traffic would be proxied'
            if key=='DOMAIN-SUFFIX,gstatic.com': reason='broad shared Google infrastructure'
            if rule.kind=='DOMAIN-KEYWORD': reason='substring can match unrelated domains'
            review.append({'rule':rule.record(),'status':status,'reason':reason,
                           'personal_coverage':[p.record() for p in same]})
            if status=='APPROVED': additions.append(rule)
    overrides=[parse_mihomo(t,source='policy:overrides',index=i,priority=10)
               for i,t in enumerate(policy.get('overrides',[]))]
    rules=[]
    for rule in overrides+personal+additions:
        if rule.action=='BLOCK': priority=0
        elif rule.kind in {'GEOSITE','GEOIP'}: priority=80
        elif rule.kind=='PROCESS-NAME': priority=30
        else: priority=rule.priority
        if rule.kind=='PROCESS-NAME': rule=replace(rule,client='pc')
        rules.append(replace(rule,priority=priority))
    result,duplicates=normalize(rules)
    return result,review,duplicates


def baseline_report(personal,friend,inventory):
    records=personal+[r for rules in friend.values() for r in rules]
    counts={}
    for source in sorted({r.source for r in records}):
        subset=[r for r in records if r.source==source]
        counts[source]={'total':len(subset),'types':dict(Counter(r.kind for r in subset)),
                        'actions':dict(Counter(r.action for r in subset))}
    return {'inputs':inventory,'counts':counts,'rules':[r.record() for r in records],
            'notes':['Provider comments are not evidence of legal status.',
                     'Snapshot source dates are unknown; capture date is not freshness.',
                     'X/Twitter and Grok/xAI are separate services; no broad CDN additions.']}
