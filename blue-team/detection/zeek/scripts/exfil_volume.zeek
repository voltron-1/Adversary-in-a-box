# exfil_volume.zeek — Large Outbound Data Transfer Detection (T1041)
#
# G6.1 (Gap D): tracks cumulative bytes sent from a lab host to any
# non-lab destination and fires a NOTICE when the total within a window
# crosses a threshold -- the generic behavioral signature of bulk
# exfiltration over any outbound channel (HTTPS C2, plain HTTP, or
# anything else), independent of a chosen marker string or destination.
#
# PRODUCTION-REFERENCE ONLY -- does NOT fire on the lab simulation (P2).
# lab-net is `internal: true` (air-gapped) and exfiltration/https_exfil.py's
# own C2_URL (https://c2.lab.local/collect) never resolves, so no real
# outbound bytes cross the wire in this lab at all -- this script never
# sees matching traffic from that campaign. It is real, general-purpose
# infrastructure for any host that does reach outside the lab (a genuine
# misconfiguration, or a non-air-gapped deployment of this same lab).

@load base/frameworks/notice

module ExfilVolume;

export {
    redef enum Notice::Type += {
        High_Outbound_Volume,
    };

    const volume_threshold_bytes: count = 5000000 &redef;  # 5 MB
    const volume_window: interval = 5min &redef;

    # Audit-2 Gap #2 pattern (see lateral_movement.zeek): &redef so
    # per-student LAB_NET_PREFIX deployments can override at zeek load
    # time without forking this script.
    const local_net: subnet = 172.20.0.0/24 &redef;
}

global outbound_bytes: table[addr] of count &create_expire=volume_window &default=0;

event connection_state_remove(c: connection) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Only count traffic actually leaving the lab: originator inside,
    # responder outside.
    if (src !in local_net || dst in local_net)
        return;

    local sent = c$orig$size;
    if (sent == 0)
        return;

    outbound_bytes[src] += sent;
    if (outbound_bytes[src] >= volume_threshold_bytes) {
        NOTICE([$note=High_Outbound_Volume,
                $conn=c,
                $msg=fmt("High outbound data volume from %s: %d bytes to non-lab destinations in window",
                         src, outbound_bytes[src]),
                $identifier=cat(src)]);
        outbound_bytes[src] = 0;
    }
}
