#!/usr/bin/env python3
"""Oracle for PcapLens: every packet field from REAL scapy, plus
independent python checksums over the raw bytes scapy wrote."""
from scapy.all import rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ARP, DNS, DNSQR, DNSRR
import json, os, struct

def ipcksum_ok(hdr20):
    s = 0
    for i in range(0, len(hdr20), 2):
        s += (hdr20[i] << 8) | hdr20[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF

def dump(path):
    pkts = rdpcap(path)
    raw = open(path, 'rb').read()
    out = {'file': os.path.basename(path), 'count': len(pkts), 'packets': []}
    # header facts from raw
    magic = raw[:4]
    out['nano'] = magic in (b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1')
    little = magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1')
    e = '<' if little else '>'
    out['little_endian'] = little
    (vmaj, vmin, tz, sig, snap, net) = struct.unpack_from(e+'HHiiii', raw, 4)
    out['version'] = [vmaj, vmin]
    out['snaplen'] = snap & 0xFFFFFFFF
    out['linktype'] = net & 0xFFFFFFFF
    off = 24
    for i, p in enumerate(pkts):
        ts_sec, ts_frac, incl, orig = struct.unpack_from(e+'IIII', raw, off)
        d = {'i': i, 'ts_sec': ts_sec, 'ts_frac': ts_frac, 'incl_len': incl, 'orig_len': orig,
             'offset': off}
        body = raw[off+16:off+16+incl]
        d['ts'] = ts_sec + (ts_frac / (1e9 if out['nano'] else 1e6))
        if Ether in p:
            d['eth'] = {'src': p[Ether].src, 'dst': p[Ether].dst, 'type': p[Ether].type}
        if IP in p:
            ip = p[IP]
            d['ip'] = {'src': ip.src, 'dst': ip.dst, 'proto': ip.proto, 'ttl': ip.ttl,
                       'len': ip.len, 'id': ip.id, 'flags': int(ip.flags), 'chksum': ip.chksum,
                       'ihl_words': ip.ihl, 'version': ip.version}
            d['ip_chksum_ok'] = ipcksum_ok(body[14:14+ip.ihl*4])
        if IPv6 in p:
            v6 = p[IPv6]
            d['ipv6'] = {'src': v6.src, 'dst': v6.dst, 'nh': v6.nh, 'hlim': v6.hlim, 'plen': v6.plen}
        if TCP in p:
            t = p[TCP]
            d['tcp'] = {'sport': t.sport, 'dport': t.dport, 'seq': t.seq, 'ack': t.ack,
                        'flags': str(t.flags), 'window': t.window, 'chksum': t.chksum}
        if UDP in p:
            u = p[UDP]
            d['udp'] = {'sport': u.sport, 'dport': u.dport, 'len': u.len, 'chksum': u.chksum}
        if ICMP in p:
            d['icmp'] = {'type': p[ICMP].type, 'code': p[ICMP].code}
            if hasattr(p[ICMP], 'id'):
                d['icmp']['id'] = p[ICMP].id; d['icmp']['seq'] = p[ICMP].seq
        for cls, nm in ((ICMPv6EchoRequest, 'icmpv6_echo_request'), (ICMPv6EchoReply, 'icmpv6_echo_reply')):
            if cls in p:
                d['icmpv6'] = {'kind': nm, 'id': p[cls].id, 'seq': p[cls].seq}
        if ARP in p:
            a = p[ARP]
            d['arp'] = {'op': a.op, 'psrc': a.psrc, 'pdst': a.pdst, 'hwsrc': a.hwsrc, 'hwdst': a.hwdst}
        if DNS in p:
            dns = p[DNS]
            d['dns'] = {'id': dns.id, 'qr': dns.qr, 'qdcount': dns.qdcount, 'ancount': dns.ancount}
            qd = dns.qd[0] if isinstance(dns.qd, list) and dns.qd else dns.qd
            an = dns.an[0] if isinstance(dns.an, list) and dns.an else dns.an
            if isinstance(qd, DNSQR):
                qn = qd.qname
                d['dns']['qname'] = qn.decode() if isinstance(qn, bytes) else qn
                d['dns']['qtype'] = qd.qtype
            if isinstance(an, DNSRR):
                rd = an.rdata
                d['dns']['answer'] = rd if isinstance(rd, str) else (rd.decode() if isinstance(rd, bytes) else str(rd))
                d['dns']['ttl'] = an.ttl
        d['payload_len'] = len(p.payload.payload) if p.payload else 0
        out['packets'].append(d)
        off += 16 + incl
    return out

items = []
for f in ['tcp_http.pcap', 'udp_dns.pcap', 'icmp_arp.pcap', 'ipv6.pcap']:
    items.append(dump(os.path.join('tests/corpus', f)))
# nano.pcap: scapy misreads the ns magic; same record bytes as tcp_http.pcap,
# so derive expectations from the tcp item with the nanosecond timebase.
import copy
nano = copy.deepcopy(items[0])
nano['file'] = 'nano.pcap'
nano['nano'] = True
for p in nano['packets']:
    p['ts'] = p['ts_sec'] + p['ts_frac'] / 1e9
items.append(nano)
items.append({'file': 'bad_trunc.pcap', 'expect_warning': 'truncated'})
json.dump({'items': items}, open('tests/expected.json', 'w'), indent=1)
open('tests/expected.json', 'a').write('\n')
print('wrote expected.json:', len(items), 'items')
for it in items:
    print(' ', it['file'], it.get('count'), 'pkts' if 'count' in it else '')
