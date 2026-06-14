import re

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

class IOCExtractor:
    def __init__(self, all_findings):
        self.findings = all_findings

    def extract(self):
        ips = set()
        domains = set()
        for category, findings in self.findings.items():
            for f in findings:
                text = str(f)
                ips.update(IP_REGEX.findall(text))
                domains.update(DOMAIN_REGEX.findall(text))
        # Remove private IPs from IOC list
        public_ips = {ip for ip in ips if not ip.startswith(('192.168.', '10.', '172.'))}
        return {
            'ips': list(public_ips),
            'domains': list(domains)
        }
