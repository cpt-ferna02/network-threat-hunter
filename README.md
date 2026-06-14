# Network Detection & Threat Hunting Platform

A web-based PCAP analysis platform that automatically detects malicious network traffic and generates structured SOC incident reports mapped to MITRE ATT&CK.

## Features

Upload a PCAP file and get:

- **C2 Beaconing Detection** — identifies periodic outbound connections via interval timing analysis (T1071)
- **DNS Tunneling Detection** — flags high-entropy subdomains and abnormal query lengths (T1048.003)
- **Suspicious HTTP Analysis** — detects malicious user-agents, oversized POSTs, long URIs (T1071.001)
- **Lateral Movement Detection** — identifies SMB/RDP/WinRM fan-out to multiple internal hosts (T1021)
- **IOC Extraction** — automatically pulls malicious IPs and domains from all findings
- **MITRE ATT&CK Mapping** — every finding tagged with technique ID, name, and tactic
- **SOC Incident Report** — structured report with executive summary, findings, IOCs, and remediation steps

## Detection Coverage

| Technique | MITRE ID | Tactic |
|-----------|----------|--------|
| C2 Beaconing via interval analysis | T1071 | Command and Control |
| DNS Tunneling via entropy scoring | T1048.003 | Exfiltration |
| Suspicious HTTP traffic | T1071.001 | Command and Control |
| SMB/RDP Lateral Movement | T1021 | Lateral Movement |

## Tech Stack

- **Python** — core detection logic and packet analysis
- **Scapy** — packet parsing and flow reconstruction
- **Flask** — web application and REST API
- **NumPy** — statistical beacon detection (coefficient of variation)
- **MITRE ATT&CK** — technique mapping and tactic classification

## Quick Start

git clone https://github.com/cpt-ferna02/network-threat-hunter.git
cd network-threat-hunter
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 app.py

Open http://localhost:5000, upload a PCAP, and get results.

## Project Structure

network-threat-hunter/
  app.py                    # Flask entry point
  modules/
    pcap_parser.py          # Scapy-based packet ingestion
    beacon_detector.py      # C2 beaconing via timing analysis
    dns_analyzer.py         # DNS tunneling via entropy scoring
    http_analyzer.py        # Suspicious HTTP detection
    lateral_movement.py     # SMB/RDP lateral movement detection
    ioc_extractor.py        # IP and domain IOC extraction
    attack_mapper.py        # MITRE ATT&CK mapping and timeline
    report_generator.py     # SOC incident report generation
  templates/
    index.html              # PCAP upload interface
    results.html            # Attack timeline dashboard

## Author

Fernando Cortez Jr. — https://github.com/cpt-ferna02
