"""
tests/suricata_pcap_helpers.py -- Phase G5.1

Scapy packet-crafting helpers shared by tests/test_suricata_pcap_replay.py.
Not a test module itself (no `test` prefix, so `unittest discover` skips it).

Deliberately does NOT import scapy at module scope: scapy is a test-only
dependency (not part of any subproject's requirements.txt), so the import
lives inside each function and the caller is expected to guard it the same
way test_suricata_pcap_replay.py does (skip the suite if scapy is absent).
"""

from __future__ import annotations

import itertools

_seq_counter = itertools.count(1000, 100)


def tcp_conversation(src, sport, dst, dport, payload=b"", resp_payload=b""):
    """A full SYN/SYN-ACK/ACK handshake, an optional client PSH payload, and
    an optional server PSH response -- enough for Suricata's stream engine
    and app-layer parsers (HTTP, SMB, ...) to actually track the flow.
    A bare single PSH packet with no handshake is NOT enough: app-layer
    protocol detection needs the full conversation."""
    from scapy.all import IP, TCP, Ether, Raw

    pkts = []
    iseq = next(_seq_counter)
    aseq = next(_seq_counter) + 50000
    pkts.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=iseq))
    pkts.append(
        Ether()
        / IP(src=dst, dst=src)
        / TCP(sport=dport, dport=sport, flags="SA", seq=aseq, ack=iseq + 1)
    )
    pkts.append(
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="A", seq=iseq + 1, ack=aseq + 1)
    )
    iseq2 = iseq + 1
    if payload:
        pkts.append(
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags="PA", seq=iseq + 1, ack=aseq + 1)
            / Raw(load=payload)
        )
        iseq2 = iseq + 1 + len(payload)
        pkts.append(
            Ether()
            / IP(src=dst, dst=src)
            / TCP(sport=dport, dport=sport, flags="A", seq=aseq + 1, ack=iseq2)
        )
    if resp_payload:
        pkts.append(
            Ether()
            / IP(src=dst, dst=src)
            / TCP(sport=dport, dport=sport, flags="PA", seq=aseq + 1, ack=iseq2)
            / Raw(load=resp_payload)
        )
        aseq2 = aseq + 1 + len(resp_payload)
        pkts.append(
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags="A", seq=iseq2, ack=aseq2)
        )
    return pkts


def smtp_session(src, sport, dst, dport, lines):
    """A line-by-line SMTP exchange: `lines` is [(direction, bytes), ...]
    with direction 'c' (client->server) or 's' (server->client). Suricata's
    smtp app-layer detector needs a real command/reply sequence (banner,
    EHLO, MAIL FROM, RCPT TO, DATA, body, QUIT) -- a single raw blob of
    SMTP-looking text in one packet is not enough for protocol detection."""
    from scapy.all import IP, TCP, Ether, Raw

    pkts = []
    iseq = next(_seq_counter)
    aseq = next(_seq_counter) + 60000
    pkts.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=iseq))
    pkts.append(
        Ether()
        / IP(src=dst, dst=src)
        / TCP(sport=dport, dport=sport, flags="SA", seq=aseq, ack=iseq + 1)
    )
    pkts.append(
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="A", seq=iseq + 1, ack=aseq + 1)
    )
    cseq, sseq = iseq + 1, aseq + 1
    for direction, data in lines:
        if direction == "s":
            pkts.append(
                Ether()
                / IP(src=dst, dst=src)
                / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq)
                / Raw(load=data)
            )
            sseq += len(data)
            pkts.append(
                Ether()
                / IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq)
            )
        else:
            pkts.append(
                Ether()
                / IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq)
                / Raw(load=data)
            )
            cseq += len(data)
            pkts.append(
                Ether()
                / IP(src=dst, dst=src)
                / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq)
            )
    return pkts


def udp_packet(src, sport, dst, dport, payload):
    from scapy.all import IP, UDP, Ether, Raw

    return [Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)]


def dns_query(src, sport, dst, dport, qname, *, txn_id=0, qtype="A", qclass="IN"):
    """A syntactically valid DNS query (RD set, QDCOUNT=1) -- Suricata's dns
    app-layer probing parser rejects malformed headers (e.g. QDCOUNT=0),
    so any dns-typed rule needs a real query to even be evaluated. qtype/
    qclass default to a normal A/IN lookup; pass qtype="TXT", qclass="CH"
    for a CHAOS-class version-scan-style query."""
    from scapy.all import DNS, IP, UDP, Ether, DNSQR

    pkt = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / DNS(id=txn_id, rd=1, qd=DNSQR(qname=qname, qtype=qtype, qclass=qclass))
    )
    return [pkt]


def syn_packets(src, dst, dport_start, count, *, dport_fixed=None, sport_start=40000):
    """`count` bare SYN packets, one per source port, to sequential dest
    ports starting at dport_start (or all to the same dport_fixed)."""
    from scapy.all import IP, TCP, Ether

    pkts = []
    for i in range(count):
        dport = dport_fixed if dport_fixed is not None else dport_start + i
        pkts.append(
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport_start + i, dport=dport, flags="S", seq=next(_seq_counter))
        )
    return pkts
