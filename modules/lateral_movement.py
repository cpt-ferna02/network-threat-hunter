from collections import defaultdict

LATERAL_PORTS = {
    445: 'SMB',
    3389: 'RDP',
    135: 'WMI/RPC',
    5985: 'WinRM',
    22: 'SSH'
}

class LateralMovementDetector:
    def __init__(self, packets, internal_prefix='192.168.'):
        self.packets = packets
        self.prefix = internal_prefix

    def detect(self):
        connections = defaultdict(lambda: defaultdict(set))
        for pkt in self.packets:
            if not pkt.get('src') or not pkt.get('dst'):
                continue
            port = pkt.get('dport', 0)
            if port in LATERAL_PORTS:
                connections[pkt['src']][port].add(pkt['dst'])

        findings = []
        for src, port_data in connections.items():
            for port, dst_set in port_data.items():
                if len(dst_set) >= 2:
                    findings.append({
                        'src_ip': src,
                        'protocol': LATERAL_PORTS[port],
                        'port': port,
                        'targets': list(dst_set),
                        'target_count': len(dst_set),
                        'mitre': 'T1021 - Remote Services',
                        'severity': 'CRITICAL'
                    })
        return findings
