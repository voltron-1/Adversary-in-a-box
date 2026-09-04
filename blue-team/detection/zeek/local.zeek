# local.zeek — Lab-specific Zeek configuration
# Loads all custom detection scripts for Adversary-in-a-Box

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/ssl
# G6.2 (Gap M): base/protocols/ssl on its own logs the TLS handshake
# (ssl.log) but not the certificate details -- x509.log needs the file
# analysis framework's X.509 script explicitly loaded.
@load base/files/x509
@load base/frameworks/notice
@load base/frameworks/sumstats
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssl/validate-certs
@load policy/frameworks/software/vulnerable

# Load custom lab detection scripts
@load scripts/dns_exfil
@load scripts/port_scan
@load scripts/lateral_movement
@load scripts/arp_spoof
@load scripts/exfil_volume

# Configure log paths
redef Log::default_logdir = "/var/log/zeek/";

# Enable JSON output for ELK ingestion
redef LogAscii::use_json = T;

# Set home network.
# Audit-2 Gap #2: this default matches LAB_NET_PREFIX=172.20.0 from
# .env.example. If a per-student deployment sets a different prefix, override
# at zeek load time:
#   zeek -i <iface> local.zeek "Site::local_nets={ 172.20.42.0/24 }"
# (Zeek has no env-var substitution, so for per-student wiring this needs to
# be generated from .env via a small entrypoint when zeek is added to compose.)
redef Site::local_nets = { 172.20.0.0/24 };

# G6.2 (Gap M): the lab's own PKI (pki-nginx, docker-compose.yml) serves a
# leaf cert chained to the lab's self-signed Root CA -- not a CA in
# Zeek's default trust store, so every connection to it would otherwise
# fire policy/protocols/ssl/validate-certs' SSL::Invalid_Server_Cert
# notice, every time, forever. That's not a real signal here (the lab
# PKI's own chain is the point of the exercise), so it's suppressed below
# for this one host rather than globally -- a genuine cert substitution
# against a DIFFERENT lab host would still notice normally.
# Audit-2 Gap #2 pattern: &redef for per-student LAB_NET_PREFIX overrides.
const pki_host: addr = 172.20.0.70 &redef;

# Tune notice policy
hook Notice::policy(n: Notice::Info) {
    # Page on critical events
    if (n$note == LateralMovement::Internal_SMB_Lateral_Movement)
        add n$actions[Notice::ACTION_LOG];
    if (n$note == DnsExfil::DNS_Tunnel_Detected)
        add n$actions[Notice::ACTION_LOG];
    # G6.1: real, general-purpose detectors (production-reference for this
    # lab's own simulated campaigns; see arp_spoof.zeek/exfil_volume.zeek).
    if (n$note == ArpSpoof::Duplicate_IP_MAC_Binding)
        add n$actions[Notice::ACTION_LOG];
    if (n$note == ExfilVolume::High_Outbound_Volume)
        add n$actions[Notice::ACTION_LOG];
    # G6.2: suppress the lab PKI's own expected self-signed-chain notice.
    # An empty ActionSet strips every action a default policy already
    # attached (including the default log action), so the notice never
    # reaches notice.log at all -- not available to test against a live
    # Zeek process in this environment; worth an integration.yml spot
    # check connecting to pki-nginx.
    if (n$note == SSL::Invalid_Server_Cert && n?$id && n$id$resp_h == pki_host)
        n$actions = Notice::ActionSet();
}
