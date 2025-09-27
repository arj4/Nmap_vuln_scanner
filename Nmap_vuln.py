#!/usr/bin/env python3
"""
Subnet vulnerability sweep with Nmap (NSE)

Overview:
- Probes a CIDR range using service/version detection and the "vuln" NSE category.
- Collects open ports, detected services/versions, and script-reported findings.
- Produces two reports: a readable JSON and a spreadsheet-friendly CSV.

Quick start:
    python Nmap_vuln.py --subnet 192.168.1.0/24

Requirements:
- Python 3.8+
- python-nmap  (pip install python-nmap)

Output:
- vulnerability_report.json  (pretty printed)
- vulnerability_report.csv   (Host, Port, Protocol, Service, Script, Details)
"""


import nmap
import json
import csv
import argparse
import sys
import time


def scan_subnet(subnet: str, nmap_args: str = "-sV --script vuln") -> nmap.PortScanner:
    """Run nmap against a CIDR and enable version detection plus the 'vuln' NSE category.

Args:
    subnet (str): Target network in CIDR form (e.g., "192.168.1.0/24").
    nmap_args (str): Extra flags for nmap (default: "-sV --script vuln").

Returns:
    nmap.PortScanner: Scanner object populated with raw results.
"""

    nm = nmap.PortScanner()
    print(f"[+] Starting Nmap scan on {subnet} with args: {nmap_args}")
    try:
        nm.scan(hosts=subnet, arguments=nmap_args, sudo=False)
    except nmap.PortScannerError as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error during Nmap scan: {e}")
        sys.exit(1)

    print(f"[+] Nmap scan completed in {nm.scaninfo()}. Hosts up: {nm.all_hosts()}")
    return nm


def parse_scan_results(nm: nmap.PortScanner) -> list:
    """Transform a PortScanner result into a structured list of hosts and ports.

For each host, this extracts:
  - IP, best‑effort hostname (reverse DNS), and OS family (if available)
  - For each protocol (tcp/udp/…), all ports with state, service and version
  - Any NSE 'script' outputs that indicate potential vulnerabilities

Args:
    nm (nmap.PortScanner): The scan result returned by python-nmap.

Returns:
    list[dict]: Example shape:
        [
          {
            "host": "192.168.1.10",
            "hostname": "printer.local",
            "os": "Linux",
            "ports": [
              {
                "port": 80,
                "proto": "tcp",
                "state": "open",
                "service": "http",
                "service_version": "Apache httpd 2.4.29",
                "vulns": [
                  {"script": "http-vuln-cve2011-3192", "output": "…"},
                  {"script": "vulners", "output": "…"}
                ]
              }
            ]
          }
        ]
"""

    hosts_data = []

    for host in nm.all_hosts():
        host_entry = {
            "host": host,
            "hostname": None,
            "os": None,
            "ports": []
        }

        # Best‑effort hostname via reverse DNS, when present
        try:
            host_entry["hostname"] = nm[host]["hostnames"][0]["name"] if nm[host]["hostnames"] else None
        except Exception:
            host_entry["hostname"] = None

        # If OS detection ran, record the reported OS family
        try:
            if "osmatch" in nm[host]:
                host_entry["os"] = nm[host]["osmatch"][0]["name"]
        except Exception:
            host_entry["os"] = None

        # Walk all protocols reported by nmap (e.g., tcp, udp)
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service_info = nm[host][proto][port]

                port_entry = {
                    "port": port,
                    "protocol": proto,
                    "service": service_info.get("name", ""),
                    "service_version": service_info.get("version", ""),
                    "vulnerabilities": []
                }

                # NSE findings (if any) are exposed under the 'script' key
                script_results = service_info.get("script", {})
                for script_name, script_output in script_results.items():
                    vuln_entry = {
                        "script": script_name,
                        "output": script_output.strip()
                    }
                    port_entry["vulnerabilities"].append(vuln_entry)

                # Keep a port in the report if it is open or scripts produced output
                host_entry["ports"].append(port_entry)

        hosts_data.append(host_entry)

    return hosts_data


def generate_json_report(hosts_data: list, filename: str = "vulnerability_report.json") -> None:
    """Write the results to JSON (UTF‑8, indented) for easy reading and diffs.

Args:
    hosts_data (list): Output from parse_scan_results().
    filename (str): Destination path for the JSON file.
"""

    try:
        with open(filename, "w", encoding="utf-8") as json_file:
            json.dump(hosts_data, json_file, indent=2)
        print(f"[+] JSON report written to: {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to write JSON report: {e}")


def generate_csv_report(hosts_data: list, filename: str = "vulnerability_report.csv") -> None:
    """Save a flat CSV with common columns for quick filtering and pivoting.

Columns:
    Host, Hostname, OS, Port, Protocol, Service, Service Version, Script, Script Output

Args:
    hosts_data (list): Output from parse_scan_results().
    filename (str): Destination path for the CSV file.
"""

    try:
        with open(filename, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            # CSV header
            writer.writerow([
                "Host",
                "Hostname",
                "OS",
                "Port",
                "Protocol",
                "Service",
                "Service Version",
                "Script",
                "Script Output"
            ])

            for host_entry in hosts_data:
                host = host_entry.get("host", "")
                hostname = host_entry.get("hostname", "")
                os_name = host_entry.get("os", "")

                for port_info in host_entry["ports"]:
                    port = port_info.get("port", "")
                    proto = port_info.get("protocol", "")
                    svc = port_info.get("service", "")
                    svc_ver = port_info.get("service_version", "")

                    if port_info["vulnerabilities"]:
                        for vuln in port_info["vulnerabilities"]:
                            script = vuln.get("script", "")
                            output = vuln.get("output", "")
                            writer.writerow([
                                host,
                                hostname,
                                os_name,
                                port,
                                proto,
                                svc,
                                svc_ver,
                                script,
                                output.replace("\n", " | ")
                            ])
                    else:
                        # Even if no vulnerabilities, report the service/port as “no vuln”
                        writer.writerow([
                            host,
                            hostname,
                            os_name,
                            port,
                            proto,
                            svc,
                            svc_ver,
                            "",
                            ""
                        ])

        print(f"[+] CSV report written to: {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to write CSV report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan a subnet for vulnerabilities using Nmap NSE and generate JSON/CSV reports."
    )
    parser.add_argument(
        "--subnet",
        required=True,
        help="Target subnet in CIDR notation (e.g., 192.168.1.0/24)."
    )
    parser.add_argument(
        "--nmap-args",
        default="-sV --script vuln",
        help="Additional Nmap arguments for the scan (default: \"-sV --script vuln\")."
    )
    args = parser.parse_args()

    start_time = time.time()
    nm = scan_subnet(args.subnet, args.nmap_args)
    hosts_data = parse_scan_results(nm)

    # Write JSON and CSV artifacts
    generate_json_report(hosts_data, filename="vulnerability_report.json")
    generate_csv_report(hosts_data, filename="vulnerability_report.csv")

    elapsed = time.time() - start_time
    print(f"[+] Total time elapsed: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
