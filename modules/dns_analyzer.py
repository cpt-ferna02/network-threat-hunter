import math
from collections import Counter

class DNSAnalyzer:
    def __init__(self, dns_queries):
        self.dns_queries = dns_queries

    def entropy(self, text):
        if not text:
            return 0
        freq = Counter(text.lower())
        length = len(text)
        return -sum((c/length) * math.log2(c/length) for c in freq.values())

    def detect(self):
        findings = []
        seen = set()
        domain_counts = Counter(q['name'] for q in self.dns_queries)
        for query in self.dns_queries:
            name = query['name']
            if name in seen:
                continue
            seen.add(name)
            subdomain = name.split('.')[0] if '.' in name else name
            ent = self.entropy(subdomain)
            length = len(name)
            if ent > 3.5 or length > 52:
                findings.append({
                    'domain': name,
                    'subdomain': subdomain,
                    'entropy': round(ent, 3),
                    'length': length,
                    'query_count': domain_counts[name],
                    'mitre': 'T1048.003 - Exfiltration Over DNS',
                    'severity': 'HIGH' if ent > 4.0 else 'MEDIUM'
                })
        return findings
