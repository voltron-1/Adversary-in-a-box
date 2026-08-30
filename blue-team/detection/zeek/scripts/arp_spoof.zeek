# arp_spoof.zeek — ARP Spoofing / Duplicate IP-MAC Binding Detection (T1557)
#
# G6.1 (Gap D): a real, generic on-path-attack detector. Tracks each
# observed IP -> MAC binding from ARP traffic and fires a NOTICE when an
# address that already has an established binding is claimed by a
# different MAC in a later reply -- the actual behavioral signature of
# ARP cache poisoning, independent of any chosen marker string.
#
# PRODUCTION-REFERENCE ONLY -- does NOT fire on the lab simulation (P2).
# credential_access/mitm.py emits a syslog advisory instead of crafting
# real ARP frames (see blue-team/detection/sigma/mitm_arp_spoof.yml's own
# note: Docker bridges don't reliably forward client-injected ARP
# replies), so this script never sees matching traffic from that
# campaign. It is real, general-purpose infrastructure: any genuine
# ARP-cache-poisoning attempt on the wire is caught regardless of which
# campaign (or real incident) produced it.

@load base/frameworks/notice

module ArpSpoof;

export {
    redef enum Notice::Type += {
        Duplicate_IP_MAC_Binding,
    };
}

# The most recent MAC address seen claiming ownership of each IP, from
# arp_reply's sender protocol/hardware address (SPA/SHA) -- the binding a
# reply actually asserts, as opposed to arp_request's target fields (TPA/
# THA), which are just "who has this IP" and assert nothing.
global ip_to_mac: table[addr] of string &create_expire=1hr;

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
    if (SPA in ip_to_mac && ip_to_mac[SPA] != SHA) {
        NOTICE([$note=Duplicate_IP_MAC_Binding,
                $msg=fmt("Duplicate IP-MAC binding: %s now claimed by %s, previously %s (possible ARP spoofing)",
                         SPA, SHA, ip_to_mac[SPA]),
                $identifier=cat(SPA, SHA)]);
    }
    ip_to_mac[SPA] = SHA;
}
