# local.zeek — Lab-specific Zeek configuration
# Loads all custom detection scripts for Adversary-in-a-Box

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/ssl
@load base/frameworks/notice
@load base/frameworks/sumstats
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssl/validate-certs
@load policy/frameworks/software/vulnerable

# Load custom lab detection scripts
@load scripts/dns_exfil
@load scripts/port_scan
@load scripts/lateral_movement

# Configure log paths
redef Log::default_logdir = "/var/log/zeek/";

# Enable JSON output for ELK ingestion
redef LogAscii::use_json = T;

# Set home network
redef Site::local_nets = { 172.20.0.0/24 };

# Tune notice policy
hook Notice::policy(n: Notice::Info) {
    # Page on critical events
    if (n$note == LateralMovement::Internal_SMB_Lateral_Movement)
        add n$actions[Notice::ACTION_LOG];
    if (n$note == DnsExfil::DNS_Tunnel_Detected)
        add n$actions[Notice::ACTION_LOG];
}
