# -*- coding: utf-8 -*-


import argparse
import collections
import functools
import json
import os
import socket
import struct
import sys
import time


ICMP_DEST_UNREACH = 3
ICMP_PORT_UNREACH = 3
DEFAULT_DST_PORT = 33434
DEFAULT_SRC_PORT = 0
DEFAULT_COUNT = 3
RECV_TIMEOUT = 1.0


def traceroute(dst_ip, src_ip, start_dst_port, max_hops, count, timeout):
    p_send = (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    p_recv = (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    with socket.socket(*p_send) as s_send, socket.socket(*p_recv) as s_recv:
        s_send.bind((src_ip, DEFAULT_SRC_PORT))
        s_recv.settimeout(timeout)
        ttl = 1
        hop = 0
        dst_port = start_dst_port
        probes = {}
        done = False
        unreach_counts = max_hops*[0]
        while hop < max_hops:
            s_send.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            for i in range(count):
                s_send.sendto(b'', (dst_ip, dst_port))
                probes[dst_port] = {
                    'hop': hop,
                    'num': dst_port - start_dst_port,
                    'unreach_count': 0,
                    'ts_req': time.time(),
                    'ts_res': None,
                    'ip': None
                }
                try:
                    data, addr = s_recv.recvfrom(4096)
                except socket.timeout:
                    continue
                finally:
                    dst_port += 1
                ts_res = time.time()
                resp = parse_icmp(data)
                if resp.src_port in probes:
                    probe = probes[resp.src_port]
                    probe['ts_res'] = ts_res
                    probe['ip'] = addr[0]
                    if (resp.type == ICMP_DEST_UNREACH and
                            resp.code == ICMP_PORT_UNREACH):
                        probe['unreach_count'] += 1
                        unreach_counts[probe['hop']] += 1
                        if unreach_counts[probe['hop']] == count:
                            done = True
            ttl += 1
            hop += 1
            if done:
                break
    return make_report(probes, hop)


def parse_icmp(data):
    ICMPPkt = collections.namedtuple('ICMPPkt', ('type', 'code', 'src_port'))
    ihl = (data[0] & 15)*4  # IP header length
    icmp_type, icmp_code = struct.unpack('!BB', data[ihl:ihl + 2])
    orig_ihl = (data[ihl + 8] & 15)*4
    offset = ihl + 8 + orig_ihl
    src_port = struct.unpack('!H', data[offset + 2:offset + 4])[0]
    return ICMPPkt(icmp_type, icmp_code, src_port)


def make_report(probes, max_hop):
    hops = [collections.defaultdict(list) for i in range(max_hop)]
    for probe_res in probes.values():
        hop = probe_res['hop']
        ip = probe_res['ip']
        num = probe_res['num']
        if ip is not None:
            dt = probe_res['ts_res'] - probe_res['ts_req']
        else:
            dt = None
        hops[hop][ip].append((num, dt))

    report = []
    for hop_data in hops:
        hop_report = []
        for ip, delays in hop_data.items():
            probe_report = dict.fromkeys(('ip', 'delays'))
            delays.sort(key=lambda x: x[0])
            probe_report['ip'] = ip
            probe_report['delays'] = delays
            hop_report.append(probe_report)
        hop_report.sort(key=lambda x: x['delays'][0][0])
        for ip_report in hop_report:
            ip_report['delays'] = [d[1] for d in ip_report['delays']]
        report.append(hop_report)
    return report


def print_report(report):

    def get_delays_str(delays):
        delays_str = []
        for delay in delays:
            if delay is not None:
                delays_str.append('{:.3f} ms'.format(1000*delay))
            else:
                delays_str.append('*')
        return '  '.join(delays_str)

    def get_ip_str(ip):
        return '{: <17}'.format(ip) if ip else ''

    cnt = 1
    num_width = len(str(len(report)))
    num_tmpl = '{{: >{}}}. '.format(num_width)
    empty_indent = (num_width + 2)*' '
    for num, hop_report in enumerate(report, 1):
        ip_report = hop_report[0]
        print(
            num_tmpl.format(num),
            get_ip_str(ip_report['ip']),
            get_delays_str(ip_report['delays']),
            sep=''
        )
        for ip_report in hop_report[1:]:
            print(
                empty_indent,
                get_ip_str(ip_report['ip']),
                get_delays_str(ip_report['delays']),
                sep=''
            )


def print_report_json(report):
    print(json.dumps(report))


def quiet_log_msg(*args, **kwargs):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, help='The host to traceroute to')
    parser.add_argument(
        '-p', '--port',
        type=int, default=DEFAULT_DST_PORT,
        help='Set the initial destination udp port port to use. '
             'Default is {}'.format(DEFAULT_DST_PORT)
    )
    parser.add_argument(
        '-q', '--queries',
        metavar='NQUERIES', type=int, default=DEFAULT_COUNT,
        help='Set the number of probes per each hop. '
             'Default is {}'.format(DEFAULT_COUNT)
    )
    parser.add_argument(
        '-m', '--max-hops',
        metavar='MAX_TTL', type=int, default=30,
        help='Set the max number of hops (max TTL to be reached). Default is 30'
    )
    parser.add_argument(
        '-s', '--source',
        metavar='SRC_ADDR', type=str, default='',
        help='Use source SRC_ADDR for outgoing packets'
    )
    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='Enable JSON output'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=float, default=RECV_TIMEOUT,
        help='Set timeout (in sec) to wait responce before send next packet. '
             'Default is {} sec'.format(RECV_TIMEOUT)
    )
    args = parser.parse_args()
    report = traceroute(args.host, args.source, args.port,
                        args.max_hops, args.queries, args.timeout)
    if args.json:
        print_report_json(report)
    else:
        print_report(report)
