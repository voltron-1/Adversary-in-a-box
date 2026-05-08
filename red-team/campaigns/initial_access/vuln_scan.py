"""
campaigns/initial_access/vuln_scan.py — T1595 Active Reconnaissance

Performs active network scanning against target environment.
Enumerates open ports, services, and CVEs.

MITRE ATT&CK: T1595 — Active Scanning | T1589 — Gather Victim Identity
Tactic: Reconnaissance
"""

import os
import json
import socket
from datetime import datetime
from campaigns.base_campaign import BaseCampaign


class VulnScanCampaign(BaseCampaign):
    """
    T1595 — Active Scanning + T1589 — Gather Victim Identity Information

    Performs port scanning and service fingerprinting against the target
    environment using Python socket connections (simulating nmap behavior).
    """

    TECHNIQUE_ID = "T1595"
    TECHNIQUE_NAME = "Active Scanning"
    TACTIC = "Reconnaissance"

    # Common ports to scan
    TARGET_PORTS = [21, 22, 25, 80, 443, 3306, 5432, 8080, 8443, 3389]
    TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "1.0"))

    def run(self) -> dict:
        target_ip = self.target.replace("http://", "").replace("https://", "").split(":")[0]
        self.log_step("init", f"Starting reconnaissance against {target_ip}")

        # Step 1: Port scan
        open_ports = self._port_scan(target_ip)
        self.log_step("port_scan", f"Discovered {len(open_ports)} open ports: {open_ports}")
        self.simulate_delay(1)

        # Step 2: Service fingerprinting
        services = self._fingerprint_services(target_ip, open_ports)
        self.log_step("service_fingerprint", f"Identified services: {services}")
        self.simulate_delay(1)

        # Step 3: OS / banner grab
        banners = self._grab_banners(target_ip, open_ports)
        self.log_step("banner_grab", f"Collected {len(banners)} banners")
        self.simulate_delay(0.5)

        # Step 4: Simulated CVE lookup
        cves = self._lookup_cves(services)
        self.log_step("cve_lookup", f"Identified {len(cves)} potential CVEs")

        # Save results
        results = {
            "target": target_ip,
            "scan_time": datetime.utcnow().isoformat(),
            "open_ports": open_ports,
            "services": services,
            "banners": banners,
            "cves": cves,
            "technique": self.TECHNIQUE_ID,
        }
        self.save_artifact("recon_results.json", json.dumps(results, indent=2))

        return self.build_result(True, f"Reconnaissance complete. Found {len(open_ports)} ports, {len(cves)} CVEs")

    def _port_scan(self, target: str) -> list:
        """Scan common ports via TCP connect."""
        open_ports = []
        for port in self.TARGET_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                result = s.connect_ex((target, port))
                s.close()
                if result == 0:
                    open_ports.append(port)
            except (socket.error, OSError):
                pass
        return open_ports

    def _fingerprint_services(self, target: str, ports: list) -> dict:
        """Map port numbers to common service names."""
        service_map = {
            21: "ftp", 22: "ssh", 25: "smtp", 80: "http",
            443: "https", 3306: "mysql", 5432: "postgresql",
            8080: "http-alt", 8443: "https-alt", 3389: "rdp",
        }
        return {port: service_map.get(port, "unknown") for port in ports}

    def _grab_banners(self, target: str, ports: list) -> dict:
        """Attempt to grab service banners."""
        banners = {}
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                s.connect((target, port))
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                s.close()
                if banner:
                    banners[port] = banner[:200]  # Truncate
            except Exception:
                pass
        return banners

    def _lookup_cves(self, services: dict) -> list:
        """
        Simulate CVE lookup based on discovered services.
        In a real scenario this would query NVD or a vulnerability scanner.
        """
        simulated_cves = {
            "mysql": [{"id": "CVE-2023-21980", "severity": "HIGH", "description": "MySQL privilege escalation"}],
            "ftp": [{"id": "CVE-2023-0466", "severity": "MEDIUM", "description": "FTP path traversal"}],
            "http": [
                {"id": "CVE-2023-44487", "severity": "HIGH", "description": "HTTP/2 Rapid Reset (DDoS)"},
                {"id": "CVE-2021-41773", "severity": "CRITICAL", "description": "Apache path traversal"},
            ],
            "ssh": [{"id": "CVE-2023-38408", "severity": "CRITICAL", "description": "OpenSSH forwarding vuln"}],
        }
        found_cves = []
        for service in services.values():
            found_cves.extend(simulated_cves.get(service, []))
        return found_cves
