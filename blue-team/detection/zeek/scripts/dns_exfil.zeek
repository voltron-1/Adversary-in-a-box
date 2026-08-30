# dns_exfil.zeek — DNS Tunneling Detection
# Detects DNS tunnel exfiltration (T1048.003) via long/high-entropy
# subdomains, suspicious record types, query volume, and NXDOMAIN rate.

@load base/frameworks/notice

module DnsExfil;

export {
    redef enum Notice::Type += {
        DNS_Tunnel_Detected,
        High_DNS_Volume,
        High_Entropy_Subdomain,
        Suspicious_Query_Type,
        High_NXDOMAIN_Rate,
    };

    const long_subdomain_threshold: count = 30 &redef;
    const query_volume_threshold: count = 50 &redef;
    const query_volume_window: interval = 60sec &redef;

    # G4.2: a quiet DNS tunnel doesn't need a long subdomain to move data --
    # base32/64-encoded payloads look random regardless of length. Legitimate
    # hostnames are rarely this random (max entropy for a 36-symbol
    # alphanumeric alphabet is ~5.17 bits/char; base32's 32-symbol alphabet
    # tops out at 5.0). Only scored on labels long enough for the entropy
    # estimate to be meaningful.
    const entropy_threshold: double = 3.5 &redef;
    const min_label_len_for_entropy: count = 8 &redef;

    # TXT (16) and NULL (10) carry more payload per query than A/AAAA and
    # are the two record types most commonly abused for tunneling.
    const suspicious_qtypes: set[count] = { 16, 10 } &redef;
    const suspicious_qtype_threshold: count = 10 &redef;

    # A tunnel probing many nonexistent subdomains (each one encoding a
    # chunk of exfiltrated data) drives this ratio far above normal DNS
    # traffic, where NXDOMAIN is the rare case, not the common one.
    const nxdomain_rate_threshold: double = 0.8 &redef;
    const nxdomain_min_queries: count = 10 &redef;
}

# Shannon entropy in bits/char. Zeek's scripting language has no builtin
# log2, so this is ln(p)/ln(2) per the standard change-of-base identity;
# `ln` is one of the global math bifs (alongside exp/log10/sqrt).
function shannon_entropy(s: string): double {
    local n = |s|;
    if ( n == 0 )
        return 0.0;

    local counts: table[string] of count &default=0;
    for ( c in s )
        counts[c] += 1;

    local entropy = 0.0;
    for ( c in counts ) {
        local p = counts[c] * 1.0 / n;
        entropy -= p * (ln(p) / ln(2.0));
    }
    return entropy;
}

# Per-source counters. All share query_volume_window so a source's tally
# resets on the same cadence across every signal tracked below.
global dns_query_counts: table[addr] of count &create_expire=query_volume_window &default=0;
global dns_nxdomain_counts: table[addr] of count &create_expire=query_volume_window &default=0;
global dns_suspicious_qtype_counts: table[addr] of count &create_expire=query_volume_window &default=0;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local src = c$id$orig_h;

    # Detect long and/or high-entropy subdomains (possible base32/64-encoded
    # tunnel payload) -- either is independently suspicious.
    local labels = split_string(query, /\./);
    for (label in labels) {
        local seg = labels[label];
        if ( |seg| > long_subdomain_threshold ) {
            NOTICE([$note=DNS_Tunnel_Detected,
                    $conn=c,
                    $msg=fmt("Long DNS subdomain detected: %s (length=%d) from %s",
                             seg, |seg|, src),
                    $identifier=cat(src, query)]);
        }
        if ( |seg| >= min_label_len_for_entropy ) {
            local ent = shannon_entropy(seg);
            if ( ent >= entropy_threshold ) {
                NOTICE([$note=High_Entropy_Subdomain,
                        $conn=c,
                        $msg=fmt("High-entropy DNS subdomain from %s: %s (entropy=%.2f bits/char)",
                                 src, seg, ent),
                        $identifier=cat(src, query)]);
            }
        }
    }

    # Suspicious record types (TXT/NULL) carry more tunnel payload per query
    # than a typical A/AAAA lookup.
    if ( qtype in suspicious_qtypes ) {
        dns_suspicious_qtype_counts[src] += 1;
        if ( dns_suspicious_qtype_counts[src] >= suspicious_qtype_threshold ) {
            NOTICE([$note=Suspicious_Query_Type,
                    $conn=c,
                    $msg=fmt("High volume of TXT/NULL DNS queries from %s: %d in window",
                             src, dns_suspicious_qtype_counts[src]),
                    $identifier=cat(src, "qtype")]);
            dns_suspicious_qtype_counts[src] = 0;
        }
    }

    # Track query volume per source.
    dns_query_counts[src] += 1;
    if (dns_query_counts[src] > query_volume_threshold) {
        NOTICE([$note=High_DNS_Volume,
                $conn=c,
                $msg=fmt("High DNS query volume from %s: %d queries in window", src, dns_query_counts[src]),
                $identifier=cat(src)]);
        dns_query_counts[src] = 0;  # Reset after notice
    }
}

event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Fires on a negative DNS response (NXDOMAIN and similar). A tunnel
    # probing many nonexistent subdomains -- each one a data-bearing query
    # that was never meant to resolve -- pushes this ratio far above what
    # normal DNS traffic produces.
    local src = c$id$orig_h;
    dns_nxdomain_counts[src] += 1;

    local total = dns_query_counts[src];
    if ( total >= nxdomain_min_queries ) {
        local rate = dns_nxdomain_counts[src] * 1.0 / total;
        if ( rate >= nxdomain_rate_threshold ) {
            NOTICE([$note=High_NXDOMAIN_Rate,
                    $conn=c,
                    $msg=fmt("High NXDOMAIN rate from %s: %.0f%% of %d queries",
                             src, rate * 100, total),
                    $identifier=cat(src, "nxdomain")]);
            dns_nxdomain_counts[src] = 0;
        }
    }
}
