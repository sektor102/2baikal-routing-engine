"""Strict minimal V2Fly protobuf reader/writer, preserving raw entry bytes.

Wire schema: v2fly/v2ray-core app/router/routercommon/common.proto.
Not binary concatenation. Unknown fields and attributes survive subsetting.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass

from .model import Invalid, Rule


def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise Invalid('Truncated protobuf varint')
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, pos
    raise Invalid('Oversize protobuf varint')


def fields(data):
    pos = 0
    while pos < len(data):
        start = pos
        tag, pos = varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if not number:
            raise Invalid('Protobuf field zero')
        if wire == 0:
            value, pos = varint(data, pos)
        elif wire == 2:
            size, pos = varint(data, pos)
            if size > len(data)-pos:
                raise Invalid('Truncated protobuf message')
            value, pos = data[pos:pos+size], pos+size
        elif wire in {1, 5}:
            size = 8 if wire == 1 else 4
            if size > len(data)-pos:
                raise Invalid('Truncated protobuf fixed field')
            value, pos = data[pos:pos+size], pos+size
        else:
            raise Invalid(f'Unsupported protobuf wire type {wire}')
        yield number, wire, value, data[start:pos]


def vint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def message(number, data):
    return vint(number*8+2) + vint(len(data)) + data


@dataclass
class Entry:
    name: str
    raw: bytes
    members: list[bytes]
    kind: str
    _parsed: list[Rule] | None = None

    @property
    def parsed(self):
        if self._parsed is None:
            self._parsed = [parse_member(member,self.kind,self.name) for member in self.members]
        return self._parsed


def parse_member(member, kind, name):
    if kind == 'geosite':
        dtype, dvalue = 0, ''
        for field, typ, value, _ in fields(member):
            if field == 1 and typ == 0: dtype = value
            if field == 2 and typ == 2: dvalue = value.decode('utf-8')
        kinds = {0:'DOMAIN-KEYWORD', 1:'DOMAIN-REGEX', 2:'DOMAIN-SUFFIX', 3:'DOMAIN'}
        if dtype not in kinds: raise Invalid('Unknown protobuf Domain.Type')
        return Rule(kinds[dtype], dvalue, 'DIRECT', 'geodata:'+name).normalized()
    address, prefix = None, 0
    for field, typ, value, _ in fields(member):
        if field == 1 and typ == 2: address = value
        if field == 2 and typ == 0: prefix = value
    if address is None or len(address) not in {4,16}:
        raise Invalid('Invalid protobuf IP bytes')
    net = ipaddress.ip_network((ipaddress.ip_address(address),prefix),strict=True)
    return Rule('IP-CIDR',str(net),'DIRECT','geodata:'+name).normalized()


class Database:
    def __init__(self, data, kind):
        if kind not in {'geosite', 'geoip'} or not data or len(data)>80_000_000:
            raise Invalid('Empty, oversize, or unknown geodata')
        self.kind, self.entries = kind, {}
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.size = len(data)
        for number, wire, raw, _ in fields(data):
            if number != 1 or wire != 2:
                raise Invalid('Unexpected geodata root field')
            name, members = '', []
            inverse = False
            for field, typ, value, _ in fields(raw):
                if field == 1 and typ == 2:
                    name = value.decode('utf-8').lower()
                elif field == 2 and typ == 2:
                    members.append(value)
                elif field == 3 and typ == 0 and kind == 'geoip':
                    inverse = bool(value)
            if not name or name in self.entries or inverse:
                raise Invalid(f'Missing/duplicate/inverse category: {name}')
            self.entries[name] = Entry(name,raw,members,kind)
        if not self.entries:
            raise Invalid('No categories')

    def rules(self, category, action):
        from dataclasses import replace
        # Attribute selection must be supported explicitly, never silently ignored.
        if '@' in category:
            base, attribute = category.split('@',1)
        else:
            base, attribute = category, None
        if base not in self.entries:
            raise Invalid(f'Missing {self.kind} category: {base}')
        entry = self.entries[base]
        for raw, rule in zip(entry.members,entry.parsed):
            attrs = []
            if attribute:
                for n,t,v,_ in fields(raw):
                    if n==3 and t==2:
                        attrs += [x.decode('utf-8').lower() for f,w,x,_ in fields(v) if f==1 and w==2]
            if attribute is None or attribute in attrs:
                yield rule if rule.action==action else replace(rule,action=action)

    def require(self, categories):
        for name in sorted(categories):
            if not list(self.rules(name,'DIRECT')):
                raise Invalid(f'Missing or empty {self.kind} category: {name}')

    def subset(self, categories):
        # Only whole selected categories are packaged; no semantic rewriting.
        self.require(categories)
        return b''.join(message(1,self.entries[name].raw) for name in sorted({c.split('@')[0] for c in categories}))

    def inventory(self):
        return {'format':'v2ray-protobuf-'+self.kind,'bytes':self.size,'sha256':self.sha256,
                'categories':{name:len(entry.members) for name,entry in sorted(self.entries.items())},
                'members':sum(len(e.members) for e in self.entries.values())}

    def diff(self, previous):
        if previous is None: return {'baseline':True}
        result = {}
        for name in sorted(self.entries.keys() | previous.entries.keys()):
            if name in self.entries and name in previous.entries and self.entries[name].raw==previous.entries[name].raw:
                continue
            before = set(previous.entries[name].members) if name in previous.entries else set()
            after = set(self.entries[name].members) if name in self.entries else set()
            if before != after:
                def examples(items):
                    values=[]
                    for raw in sorted(items)[:20]:
                        rule=parse_member(raw,self.kind,name)
                        values.append((rule.kind,rule.value))
                    return values
                result[name] = {'added':len(after-before),'removed':len(before-after),
                                'added_examples':examples(after-before), 'removed_examples':examples(before-after)}
        return result
