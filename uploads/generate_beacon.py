from scapy.all import IP, TCP, wrpcap
import time, random

pkts = []
base_time = time.time()
c2_ip = "185.220.101.50"

for i in range(20):
    interval = 30 + random.uniform(-1, 1)
    t = base_time + (i * interval)
    pkt = IP(src="192.168.1.100", dst=c2_ip) / TCP(dport=443, sport=random.randint(49152, 65535))
    pkt.time = t
    pkts.append(pkt)

wrpcap("uploads/beacon_test.pcap", pkts)
print(f"Generated {len(pkts)} beacon packets")
