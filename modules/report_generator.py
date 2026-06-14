from datetime import datetime

SEVERITY_COLORS = {
    'CRITICAL': '#ff4444',
    'HIGH': '#ff8c00',
    'MEDIUM': '#ffd700',
    'LOW': '#00c8ff'
}

def generate_report(findings, iocs, timeline):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = sum(len(v) for v in findings.values())

    # Executive Summary
    threat_types = []
    if findings['beacons']:
        threat_types.append(f"{len(findings['beacons'])} C2 beaconing flow(s)")
    if findings['dns']:
        threat_types.append(f"{len(findings['dns'])} suspicious DNS query(s)")
    if findings['http']:
        threat_types.append(f"{len(findings['http'])} suspicious HTTP request(s)")
    if findings['lateral']:
        threat_types.append(f"{len(findings['lateral'])} lateral movement source(s)")

    if threat_types:
        summary_text = f"Automated PCAP analysis detected {', '.join(threat_types)}. Immediate investigation is recommended. Affected systems should be isolated pending review."
    else:
        summary_text = "No threats were detected in this PCAP. Traffic appears to be benign."

    # Build findings HTML
    findings_html = ""
    for item in timeline:
        f = item['finding']
        color = SEVERITY_COLORS.get(item['severity'], '#888')
        details = " &nbsp;|&nbsp; ".join(
            f"<span style='color:#8b949e'>{k}:</span> <span style='color:#e6edf3'>{v}</span>"
            for k, v in f.items()
            if k not in ['mitre', 'severity']
        )
        findings_html += f"""
        <div style="border:1px solid #30363d; border-left:4px solid {color}; border-radius:8px; padding:16px; margin-bottom:12px; background:#0d1117;">
            <div style="display:flex; gap:10px; align-items:center; margin-bottom:8px;">
                <span style="background:{color}22; color:{color}; padding:2px 10px; border-radius:20px; font-size:0.75rem; font-weight:700">{item['severity']}</span>
                <span style="background:#1c2a3a; color:#00c8ff; padding:2px 10px; border-radius:20px; font-size:0.75rem">{item['mitre_id']}</span>
                <span style="color:#e6edf3; font-size:0.85rem; font-weight:600">{item['mitre_name']}</span>
                <span style="color:#8b949e; font-size:0.75rem">· {item['tactic']}</span>
            </div>
            <div style="font-family:monospace; font-size:0.8rem">{details}</div>
        </div>
        """

    # Build IOC HTML
    ioc_rows = ""
    for ip in iocs['ips']:
        ioc_rows += f"<tr><td style='padding:8px 12px; color:#8b949e'>IP Address</td><td style='padding:8px 12px; color:#00c8ff; font-family:monospace'>{ip}</td><td style='padding:8px 12px; color:#ff8c00'>Block at firewall · Add to SIEM watchlist</td></tr>"
    for domain in iocs['domains']:
        ioc_rows += f"<tr><td style='padding:8px 12px; color:#8b949e'>Domain</td><td style='padding:8px 12px; color:#00c8ff; font-family:monospace'>{domain}</td><td style='padding:8px 12px; color:#ff8c00'>Block at DNS · Investigate resolutions</td></tr>"

    if not ioc_rows:
        ioc_rows = "<tr><td colspan='3' style='padding:12px; color:#484f58; text-align:center'>No IOCs extracted</td></tr>"

    # Remediation
    remediations = []
    if findings['beacons']:
        remediations.append(("Block C2 IP at perimeter firewall", "Immediately block outbound connections to identified C2 infrastructure. Add IP to SIEM watchlist for alerting."))
        remediations.append(("Isolate affected host", "Take the beaconing host offline for forensic investigation. Preserve memory and disk image before remediation."))
        remediations.append(("Hunt for persistence", "Check scheduled tasks, registry run keys, and startup folders on the affected host for malware persistence mechanisms."))
    if findings['dns']:
        remediations.append(("Block suspicious domains at DNS", "Sinkhole or block flagged domains. Review DNS logs for other hosts querying the same domains."))
        remediations.append(("Enable DNS logging", "Ensure full DNS query logging is enabled and forwarded to SIEM for ongoing monitoring."))
    if findings['lateral']:
        remediations.append(("Review SMB/RDP exposure", "Restrict lateral movement protocols between workstations. Implement host-based firewall rules to limit east-west traffic."))
        remediations.append(("Reset credentials", "Assume credentials on affected hosts are compromised. Force password resets for all accounts that logged into affected systems."))
    if not remediations:
        remediations.append(("Continue monitoring", "No immediate action required. Continue standard monitoring procedures."))

    remediation_html = ""
    for i, (title, detail) in enumerate(remediations, 1):
        remediation_html += f"""
        <div style="display:flex; gap:16px; margin-bottom:16px; align-items:flex-start;">
            <div style="background:#00c8ff22; color:#00c8ff; width:28px; height:28px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:0.85rem; flex-shrink:0">{i}</div>
            <div>
                <div style="color:#e6edf3; font-weight:600; margin-bottom:4px">{title}</div>
                <div style="color:#8b949e; font-size:0.85rem">{detail}</div>
            </div>
        </div>
        """

    html = f"""
    <div style="font-family:'Segoe UI',sans-serif; color:#c9d1d9; background:#0d1117; padding:24px; border-radius:8px">

        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; padding-bottom:16px; border-bottom:1px solid #30363d">
            <div>
                <div style="font-size:1.3rem; font-weight:700; color:#e6edf3">SOC Incident Report</div>
                <div style="color:#8b949e; font-size:0.8rem">Generated: {now} · Network Threat Hunter</div>
            </div>
            <div style="background:{'#3d0000' if total > 0 else '#003d00'}; color:{'#ff4444' if total > 0 else '#00c8ff'}; padding:6px 16px; border-radius:20px; font-weight:700; font-size:0.85rem">
                {'⚠ THREATS DETECTED' if total > 0 else '✓ CLEAN'}
            </div>
        </div>

        <div style="margin-bottom:24px">
            <div style="color:#00c8ff; font-weight:700; text-transform:uppercase; font-size:0.75rem; margin-bottom:8px">Executive Summary</div>
            <div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; color:#c9d1d9; line-height:1.6">{summary_text}</div>
        </div>

        <div style="margin-bottom:24px">
            <div style="color:#00c8ff; font-weight:700; text-transform:uppercase; font-size:0.75rem; margin-bottom:8px">Detection Findings ({total})</div>
            {findings_html if findings_html else '<div style="color:#484f58; text-align:center; padding:20px">No findings</div>'}
        </div>

        <div style="margin-bottom:24px">
            <div style="color:#00c8ff; font-weight:700; text-transform:uppercase; font-size:0.75rem; margin-bottom:8px">Indicators of Compromise</div>
            <table style="width:100%; border-collapse:collapse; background:#161b22; border:1px solid #30363d; border-radius:8px; overflow:hidden">
                <tr style="background:#0d1117">
                    <th style="padding:8px 12px; text-align:left; color:#8b949e; font-weight:600; font-size:0.8rem">Type</th>
                    <th style="padding:8px 12px; text-align:left; color:#8b949e; font-weight:600; font-size:0.8rem">Indicator</th>
                    <th style="padding:8px 12px; text-align:left; color:#8b949e; font-weight:600; font-size:0.8rem">Recommended Action</th>
                </tr>
                {ioc_rows}
            </table>
        </div>

        <div>
            <div style="color:#00c8ff; font-weight:700; text-transform:uppercase; font-size:0.75rem; margin-bottom:16px">Remediation Recommendations</div>
            {remediation_html}
        </div>

    </div>
    """
    return html
