from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap
import time, random

pkts = []
base = time.time()

# 1. C2 Beaconing — regular intervals to fake C2
for i in range(20):
    t = base + (i * (30 + random.uniform(-0.5, 0.5)))
    p = IP(src="192.168.1.100", dst="185.220.101.50") / TCP(dport=443, sport=random.randint(49152,65535))
    p.time = t
    pkts.append(p)

# 2. DNS Tunneling — high entropy subdomains
tunneling_domains = [
    "a3f9x2kqm8vbzlpwdrty5hjcn.evil-c2.com",
    "zx7m2kpqr4vbnlwdctyh9fjsa.evil-c2.com",
    "q8r3nvbzxklmpwdctyh2fjas5.evil-c2.com",
]
for domain in tunneling_domains:
    for _ in range(3):
        t = base + random.uniform(10, 300)
        p = IP(src="192.168.1.101", dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        p.time = t
        pkts.append(p)

# 3. Lateral Movement — SMB to multiple internal hosts
targets = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
for dst in targets:
    for _ in range(3):
        t = base + random.uniform(50, 200)
        p = IP(src="192.168.1.105", dst=dst) / TCP(dport=445, sport=random.randint(49152,65535))
        p.time = t
        pkts.append(p)

pkts.sort(key=lambda x: x.time)
wrpcap("uploads/full_attack.pcap", pkts)
print(f"Generated {len(pkts)} packets")
