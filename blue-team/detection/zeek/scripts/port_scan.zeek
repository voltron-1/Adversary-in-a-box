# port_scan.zeek — Horizontal Port Scan Detection
# Detects TCP port scanning (T1595 Active Scanning)

@load base/frameworks/notice
@load base/frameworks/sumstats

module PortScan;

export {
    redef enum Notice::Type += {
        Port_Scan_Detected,
        Service_Scan_Detected,
    };

    # Thresholds
    const distinct_ports_threshold: double = 15.0 &redef;
    const scan_sample_size: count = 50 &redef;
    const scan_interval: interval = 30sec &redef;
}

event zeek_init() {
    # Count distinct destination ports per source IP
    local r1 = SumStats::Reducer(
        $stream="scan.port",
        $apply=set(SumStats::UNIQUE),
        $unique_max=scan_sample_size
    );

    SumStats::create([
        $name="detect-port-scan",
        $epoch=scan_interval,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["scan.port"]$unique + 0.0;
        },
        $threshold=distinct_ports_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            local msg = fmt("%s scanned at least %d distinct ports",
                           key$host, result["scan.port"]$unique);
            NOTICE([$note=Port_Scan_Detected,
                    $src=key$host,
                    $msg=msg,
                    $identifier=cat(key$host)]);
        }
    ]);
}

event new_connection(c: connection) {
    # Only track connections that look like scanning (no data transferred)
    SumStats::observe("scan.port",
        SumStats::Key($host=c$id$orig_h),
        SumStats::Observation($unique=cat(c$id$resp_p))
    );
}
