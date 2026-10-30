from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, replace


class Invalid(ValueError):
    pass


def domain(value: str) -> str:
    value = value.strip().rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise Invalid(f'Invalid IDNA domain: {value}') from exc
    if len(value) > 253 or not value:
        raise Invalid(f'Invalid domain: {value}')
    for label in value.split('.'):
        if not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', label):
            raise Invalid(f'Invalid domain label: {value}')
    return value


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    action: str
    source: str
    priority: int = 20
    index: int = 0
    client: str = 'both'
    options: tuple[str, ...] = ()

    def normalized(self):
        value = self.value.strip()
        kind = self.kind.upper()
        if self.action not in {'DIRECT', 'PROXY', 'BLOCK'}:
            raise Invalid(f'Unknown action: {self.action}')
        if kind in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            value = domain(value)
        elif kind == 'DOMAIN-KEYWORD':
            value = value.lower()
            if not value or any(c.isspace() for c in value) or ',' in value:
                raise Invalid('Invalid domain keyword')
        elif kind == 'DOMAIN-REGEX':
            re.compile(value)
        elif kind in {'IP-CIDR', 'IP-CIDR6'}:
            try:
                net = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise Invalid(f'Invalid CIDR: {value}') from exc
            kind = 'IP-CIDR6' if net.version == 6 else 'IP-CIDR'
            value = str(net)
        elif kind in {'GEOSITE', 'GEOIP'}:
            value = value.lower()
            if not re.fullmatch(r'[a-z0-9_-]+(?:@[a-z0-9_-]+)?', value):
                raise Invalid(f'Unsupported category: {value}')
        elif kind == 'PROCESS-NAME':
            if not value or any(c in value for c in ',\r\n\\/'):
                raise Invalid(f'Invalid process: {value}')
            # Keep case as supplied. Windows matching is case-insensitive.
        elif kind != 'MATCH':
            raise Invalid(f'Unsupported rule type: {kind}')
        if set(self.options) - {'no-resolve'}:
            raise Invalid(f'Unsupported options: {self.options}')
        return replace(self, kind=kind, value=value)

    @property
    def key(self):
        return (self.kind, self.value, self.action, self.priority, self.client, self.options)

    def record(self):
        return asdict(self)


def parse_mihomo(text, action=None, source='unknown', index=0, priority=20, client='both'):
    if not isinstance(text, str):
        raise Invalid('Rule must be a string')
    bits = [part.strip() for part in text.split(',')]
    kind = bits[0].upper()
    if kind == 'MATCH':
        if len(bits) != 2 or bits[1] != 'DIRECT':
            raise Invalid('Only MATCH,DIRECT is allowed')
        return Rule('MATCH', '', 'DIRECT', source, 999, index, client)
    # Mihomo ParseRulePayload joins regex payload commas; target is the last
    # component for main rules, and absent for classical providers.
    if kind=='DOMAIN-REGEX':
        if action is None:
            if len(bits)<3: raise Invalid('Missing regex route')
            target=bits.pop()
            actions={'DIRECT':'DIRECT','PROXY':'PROXY','→ Remnawave':'PROXY','REJECT':'BLOCK'}
            if target not in actions: raise Invalid('Unknown regex outbound')
            action=actions[target]
        return Rule(kind,','.join(bits[1:]),action,source,priority,index,client).normalized()
    if action is None:
        if len(bits) < 3:
            raise Invalid(f'Missing route: {text}')
        route = bits[2]
        actions = {'DIRECT': 'DIRECT', 'REJECT': 'BLOCK', 'REJECT-DROP': 'BLOCK',
                   '→ Remnawave': 'PROXY', 'PROXY': 'PROXY'}
        if route not in actions:
            raise Invalid(f'Unknown outbound {route}; add explicit mapping')
        action, options = actions[route], tuple(bits[3:])
    else:
        options = tuple(bits[2:])
    if len(bits) < 2:
        raise Invalid(f'Invalid rule: {text}')
    return Rule(kind, bits[1], action, source, priority, index, client, options).normalized()


def parse_happ(value, action, source, index=0, priority=20, ip=False):
    if not isinstance(value, str):
        raise Invalid('HAPP rule must be a string')
    prefix, sep, rest = value.partition(':')
    names = {'geosite': 'GEOSITE', 'geoip': 'GEOIP', 'domain': 'DOMAIN-SUFFIX',
             'full': 'DOMAIN', 'keyword': 'DOMAIN-KEYWORD', 'regexp': 'DOMAIN-REGEX'}
    if prefix in names:
        kind, val = names[prefix], rest
    elif ip:
        kind, val = 'IP-CIDR', value
    else:
        # Xray unprefixed domains are plain substring matches, not suffixes.
        kind, val = 'DOMAIN-KEYWORD', value
    return Rule(kind, val, action, source, priority, index).normalized()


def normalize(rules):
    """Remove exact same-priority duplicates only; keep provenance for all inputs."""
    output, seen, duplicates = [], {}, []
    for rule in sorted(rules, key=lambda r: (r.priority, r.index)):
        rule = rule.normalized()
        if rule.key in seen:
            duplicates.append({'rule': rule.record(), 'covered_by': seen[rule.key].record()})
        else:
            seen[rule.key] = rule
            output.append(rule)
    return output, duplicates


def covers(parent, child):
    if parent.kind == 'DOMAIN-SUFFIX' and child.kind in {'DOMAIN', 'DOMAIN-SUFFIX'}:
        return child.value == parent.value or child.value.endswith('.' + parent.value)
    if parent.kind in {'IP-CIDR', 'IP-CIDR6'} and child.kind == parent.kind:
        return ipaddress.ip_network(child.value).subnet_of(ipaddress.ip_network(parent.value))
    return parent.kind == child.kind and parent.value == child.value


def conflicts(rules):
    result = []
    for i, first in enumerate(rules):
        for second in rules[i+1:]:
            if covers(first, second) or covers(second, first):
                if first.action != second.action:
                    result.append({'type': 'different-actions', 'first': first.record(), 'second': second.record()})
                elif first.kind == second.kind and first.value != second.value:
                    result.append({'type': 'nested-kept', 'first': first.record(), 'second': second.record()})
            elif {first.kind, second.kind} & {'PROCESS-NAME'} and first.action != second.action:
                # Report process-versus-domain policy as a group elsewhere, not O(n*m) rows.
                continue
    return result


def matches(rule, host='', ip=None, process='', geosite=None, geoip=None):
    if rule.kind == 'MATCH':
        return True
    if rule.kind == 'DOMAIN':
        return host == rule.value
    if rule.kind == 'DOMAIN-SUFFIX':
        return host == rule.value or host.endswith('.' + rule.value)
    if rule.kind == 'DOMAIN-KEYWORD':
        return rule.value in host
    if rule.kind == 'DOMAIN-REGEX':
        return bool(re.search(rule.value, host))
    if rule.kind == 'PROCESS-NAME':
        return process.casefold() == rule.value.casefold()
    if rule.kind in {'IP-CIDR', 'IP-CIDR6'}:
        return ip is not None and ipaddress.ip_address(ip) in ipaddress.ip_network(rule.value)
    if rule.kind in {'GEOSITE', 'GEOIP'}:
        db = geosite if rule.kind == 'GEOSITE' else geoip
        if db is None:
            raise Invalid(f'Cannot simulate without {rule.kind} database')
        return any(matches(r, host, ip, process) for r in db.rules(rule.value, 'DIRECT'))
    return False


def route(rules, host='', ip=None, process='', geosite=None, geoip=None):
    if host:
        host = domain(host)
    # fake-ip pool must be mapped back to its domain by the client. Never LAN-direct it.
    if ip and ipaddress.ip_address(ip) in ipaddress.ip_network('198.18.0.0/15'):
        if not host:
            raise Invalid('fake-IP requires domain mapping')
        ip = None
    for rule in rules:
        if matches(rule, host, ip, process, geosite, geoip):
            return rule.action, rule
    return 'DIRECT', None
