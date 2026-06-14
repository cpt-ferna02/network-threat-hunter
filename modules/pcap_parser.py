from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
from collections import defaultdict

class PCAPParser:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.packets = []
        self.flows = defaultdict(list)
        self.dns_queries = []
        self.http_requests = []

    def parse(self):
        pkts = rdpcap(self.pcap_path)
        for pkt in pkts:
            self._process_packet(pkt)
        return self

    def _process_packet(self, pkt):
        try:
            if not pkt.haslayer(IP):
                return

            summary = {
                'time': float(pkt.time),
                'src': pkt[IP].src,
                'dst': pkt[IP].dst,
                'length': len(pkt)
            }

            if pkt.haslayer(TCP):
                summary['dport'] = pkt[TCP].dport
                summary['sport'] = pkt[TCP].sport
                key = f"{summary['src']}:{summary['dst']}:{summary['dport']}"
                self.flows[key].append(summary['time'])

            elif pkt.haslayer(UDP):
                summary['dport'] = pkt[UDP].dport
                summary['sport'] = pkt[UDP].sport
                key = f"{summary['src']}:{summary['dst']}:{summary['dport']}"
                self.flows[key].append(summary['time'])

            self.packets.append(summary)

            # DNS
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
                self.dns_queries.append({
                    'name': qname,
                    'time': summary['time']
                })

            # HTTP (look for Raw TCP on port 80)
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    payload = pkt[Raw].load.decode(errors='ignore')
                    if payload.startswith(('GET', 'POST', 'PUT', 'HEAD')):
                        lines = payload.split('\r\n')
                        method = lines[0].split(' ')[0] if lines else ''
                        uri = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else ''
                        host = ''
                        ua = ''
                        for line in lines[1:]:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                            if line.lower().startswith('user-agent:'):
                                ua = line.split(':', 1)[1].strip()
                        self.http_requests.append({
                            'host': host, 'uri': uri,
                            'method': method, 'user_agent': ua,
                            'time': summary['time']
                        })

        except Exception:
            pass
