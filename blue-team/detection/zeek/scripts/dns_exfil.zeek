# dns_exfil.zeek — DNS Tunneling Detection
# Detects high-entropy DNS subdomains indicative of DNS tunnel exfiltration (T1048.003)

@load base/frameworks/notice

module DnsExfil;

export {
    redef enum Notice::Type += { DNS_Tunnel_Detected, High_DNS_Volume };
    const long_subdomain_threshold: count = 30 &redef;
    const query_volume_threshold: count = 50 &redef;
    const query_volume_window: interval = 60sec &redef;
}

# Track DNS query counts per source IP
global dns_query_counts: table[addr] of count &create_expire=120sec &default=0;

event dns_request(c: connection, msg: dns_msg, qtype: count, qclass: count) {
    local query = c$dns$query;
    local src = c$id$orig_h;

    # Detect long subdomains (possible base32/base64 encoded data)
    local labels = split_string(query, /\./);
    for (label in labels) {
        if (|labels[label]| > long_subdomain_threshold) {
            NOTICE([$note=DNS_Tunnel_Detected,
                    $conn=c,
                    $msg=fmt("Long DNS subdomain detected: %s (length=%d) from %s",
                             labels[label], |labels[label]|, src),
                    $identifier=cat(src, query)]);
        }
    }

    # Track query volume per source
    dns_query_counts[src] += 1;
    if (dns_query_counts[src] > query_volume_threshold) {
        NOTICE([$note=High_DNS_Volume,
                $conn=c,
                $msg=fmt("High DNS query volume from %s: %d queries in window", src, dns_query_counts[src]),
                $identifier=cat(src)]);
        dns_query_counts[src] = 0;  # Reset after notice
    }
}
