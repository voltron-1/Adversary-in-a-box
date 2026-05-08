# lateral_movement.zeek — Internal Lateral Movement Detection
# Detects SSH and SMB lateral movement patterns (T1550.002, T1563.001)

@load base/frameworks/notice

module LateralMovement;

export {
    redef enum Notice::Type += {
        Internal_SSH_Lateral_Movement,
        Internal_SMB_Lateral_Movement,
        Multiple_SSH_Auth_Failures,
    };

    const ssh_failure_threshold: count = 5 &redef;
    const ssh_failure_window: interval = 30sec &redef;
    const internal_net: subnet = 172.20.0.0/24 &redef;
}

# Track SSH authentication failures per source
global ssh_failures: table[addr] of count &create_expire=120sec &default=0;

event ssh_auth_failed(c: connection, authenticated: bool, peers: count, direction: count) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    ssh_failures[src] += 1;

    if (ssh_failures[src] >= ssh_failure_threshold) {
        NOTICE([$note=Multiple_SSH_Auth_Failures,
                $conn=c,
                $msg=fmt("SSH brute-force detected: %s failed %d times against %s",
                         src, ssh_failures[src], dst),
                $identifier=cat(src, dst)]);
        ssh_failures[src] = 0;
    }
}

event connection_established(c: connection) {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;

    # Detect internal-to-internal SSH
    if (src in internal_net && dst in internal_net && dport == 22/tcp) {
        NOTICE([$note=Internal_SSH_Lateral_Movement,
                $conn=c,
                $msg=fmt("Internal SSH connection: %s -> %s (possible lateral movement)", src, dst),
                $identifier=cat(src, dst)]);
    }

    # Detect internal SMB (Pass-the-Hash indicator)
    if (src in internal_net && dst in internal_net && (dport == 445/tcp || dport == 139/tcp)) {
        NOTICE([$note=Internal_SMB_Lateral_Movement,
                $conn=c,
                $msg=fmt("Internal SMB connection: %s -> %s (possible Pass-the-Hash)", src, dst),
                $identifier=cat(src, dst)]);
    }
}
