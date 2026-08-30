# port_scan.zeek — Horizontal Port Scan Detection
# Detects TCP port scanning (T1595 Active Scanning)

@load base/frameworks/notice
@load base/frameworks/sumstats

module PortScan;

export {
    redef enum Notice::Type += {
        Port_Scan_Detected,
        Service_Scan_Detected,
        Slow_Port_Scan_Detected,
    };

    # Thresholds
    # G4.2: lowered from 15 -> 8. 15 distinct ports in a 30s window missed a
    # deliberately paced scan entirely; 8 catches a scan that's still fast
    # enough to look like an attack, not background noise.
    const distinct_ports_threshold: double = 8.0 &redef;
    const scan_sample_size: count = 50 &redef;
    const scan_interval: interval = 30sec &redef;

    # G4.2: a second, longer epoch over the SAME observation stream so a
    # scanner deliberately paced to stay under distinct_ports_threshold in
    # any single 30s window (e.g. one port every 45s) still gets caught --
    # the fast epoch alone missed slow scans entirely. Threshold is higher
    # than the fast epoch's because it accumulates over 20x the time.
    const slow_scan_threshold: double = 20.0 &redef;
    const slow_scan_sample_size: count = 200 &redef;
    const slow_scan_interval: interval = 10min &redef;
}

event zeek_init() {
    # Count distinct destination ports per source IP -- fast epoch.
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

    # Same observation stream, a slower epoch with its own reducer instance
    # and a higher unique_max -- SumStats::observe() below feeds every
    # registered reducer watching "scan.port", regardless of which create()
    # call registered it, so this runs independently of the fast epoch.
    local r2 = SumStats::Reducer(
        $stream="scan.port",
        $apply=set(SumStats::UNIQUE),
        $unique_max=slow_scan_sample_size
    );

    SumStats::create([
        $name="detect-slow-port-scan",
        $epoch=slow_scan_interval,
        $reducers=set(r2),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["scan.port"]$unique + 0.0;
        },
        $threshold=slow_scan_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            local msg = fmt("%s scanned at least %d distinct ports over %s (slow scan)",
                           key$host, result["scan.port"]$unique, slow_scan_interval);
            NOTICE([$note=Slow_Port_Scan_Detected,
                    $src=key$host,
                    $msg=msg,
                    $identifier=cat(key$host, "slow")]);
        }
    ]);
}

event new_connection(c: connection) {
    # Only track connections that look like scanning (no data transferred).
    # Zeek 7 dropped the $unique field on SumStats::Observation -- the
    # UNIQUE reducer counts distinct $str values, so the destination
    # port goes there as a string.
    SumStats::observe("scan.port",
        SumStats::Key($host=c$id$orig_h),
        SumStats::Observation($str=cat(c$id$resp_p))
    );
}
