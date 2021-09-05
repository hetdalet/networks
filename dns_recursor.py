# -*- coding: utf-8 -*-

import collections
import sys
import time
import dns
import dns.name
import dns.query
import dns.resolver
import flask
from dns.exception import DNSException


app = flask.Flask(__name__)
Response = collections.namedtuple('Response',
                                  ('answer', 'authority', 'additional'))
RR = collections.namedtuple('RR', ('name', 'ttl', 'cls', 'type', 'data'))
CacheRecord = collections.namedtuple('CacheRecord', ('ts', 'data'))


ROOT = '.'
ROOT_SERVERS = {
    'a.root-servers.net.': '198.41.0.4',
    'b.root-servers.net.': '199.9.14.201',
    'c.root-servers.net.': '192.33.4.12',
    'd.root-servers.net.': '199.7.91.13',
    'e.root-servers.net.': '192.203.230.10',
    'f.root-servers.net.': '192.5.5.241',
    'g.root-servers.net.': '192.112.36.4',
    'h.root-servers.net.': '198.97.190.53',
    'i.root-servers.net.': '192.36.148.17',
    'j.root-servers.net.': '192.58.128.30',
    'k.root-servers.net.': '193.0.14.129',
    'l.root-servers.net.': '199.7.83.42',
    'm.root-servers.net.': '202.12.27.33',
}
ROOT_RRSET = Response(
    answer=[
        RR('.', '3180', 'IN', 'NS', 'a.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'b.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'c.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'd.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'e.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'f.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'g.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'h.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'i.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'j.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'k.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'l.root-servers.net.'),
        RR('.', '3180', 'IN', 'NS', 'm.root-servers.net.'),
    ],
    authority=[],
    additional=[],
)
CACHE = collections.defaultdict(list)


@app.route("/get-a-records", methods=['GET'])
def main():
    name = flask.request.args.get('domain')
    trace = False
    if flask.request.args.get('trace') == 'true':
        trace = True
    return flask.json.jsonify(get_a_records(name, trace))


def get_a_records(name, trace):

    def recurs(name, ns_list, trace, auth_ns_list):
        resp = query(name, dns.rdatatype.A, ns_list, trace)
        if resp.answer:
            return resp.answer
        ns_list, rr_list = extract_ns(resp)
        auth_ns_list.extend(' '.join(rr) for rr in rr_list)
        if ns_list:
            return recurs(name, ns_list, trace, auth_ns_list)
        for rr in resp.authority:
            resp = recurs(rr.data, ROOT_SERVERS.values(), trace, auth_ns_list)
            if resp:
                ns_list.extend(rr.data for rr in resp)
                break
        return recurs(name, ns_list, trace, auth_ns_list)

    auth_ns_list = []
    try:
        a_recs = recurs(name.lower(), ROOT_SERVERS.values(), trace, auth_ns_list)
    except dns.exception.DNSException as exc:
        result = str(exc)
    else:
        result = {
            'A': [' '.join(rr) for rr in a_recs],
            'NS': auth_ns_list if trace else []
        }
    return result
     

def extract_ns(resp):
    name_to_addr_map = {}
    for rr in resp.additional:
        name_to_addr_map[(rr.name, rr.type)] = rr.data
    ns_list = []
    rr_list = []
    for rr in resp.authority:
        rr_list.append(rr)
        try:
            addr = name_to_addr_map[(rr.data, 'A')]
        except KeyError:
            addr = name_to_addr_map.get((rr.data, 'AAAA'))
        if addr:
            ns_list.append(addr)
    return ns_list, rr_list


def query(name, rdtype, name_servers, trace):
    name = name.lower()
    result = Response([], [], [])

    cached = []
    if not trace:
        cached = get_cached(name)
    if cached:
        result.answer.extend(cached)
        return result

    for ns in name_servers:
        req = dns.message.make_query(name, rdtype)
        req.flags |= dns.flags.RD
        resp = dns.query.udp(req, ns)
        if resp.rcode() == dns.rcode.NOERROR:
            result = handle_resp(resp)
            break
        elif resp.rcode() == dns.rcode.NXDOMAIN:
            msg = 'Domain {} does not exist'.format(name)
            raise dns.exception.DNSException(msg)
    CACHE[name].append(CacheRecord(time.time(), result.answer))

    return result


def get_cached(name):
    cached = CACHE.get(name)
    now = time.time()
    result = []
    if cached:
        for crec in cached:
            dt = now - crec.ts
            result = [rr for rr in crec.data if float(rr.ttl) > dt]
        if not result:
            del CACHE[name]
    return result


def handle_resp(resp):
    sections = []
    for section in ('answer', 'authority', 'additional'):
        recs = []
        for rr_set in getattr(resp, section):
            for rr_str in rr_set.to_text().split('\n'):
                fields = rr_str.split(' ')
                fields[0] = fields[0].lower()
                fields[-1] = fields[-1].lower()
                recs.append(RR(*fields))
        sections.append(recs)
    return Response(*sections)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5005)
