SUSPICIOUS_AGENTS = [
    'python-requests', 'curl', 'wget', 'go-http-client',
    'libwww-perl', 'masscan', 'nmap', 'sqlmap', 'nikto'
]

class HTTPAnalyzer:
    def __init__(self, http_requests):
        self.http_requests = http_requests

    def detect(self):
        findings = []
        for req in self.http_requests:
            flags = []
            agent = req.get('user_agent', '').lower()
            if any(s in agent for s in SUSPICIOUS_AGENTS):
                flags.append(f'Suspicious User-Agent: {agent}')
            if len(req.get('uri', '')) > 200:
                flags.append('Abnormally Long URI')
            if req.get('method') == 'POST':
                flags.append('POST request - possible data submission')
            if flags:
                findings.append({
                    'host': req.get('host'),
                    'uri': req.get('uri'),
                    'method': req.get('method'),
                    'flags': flags,
                    'mitre': 'T1071.001 - Web Protocols',
                    'severity': 'MEDIUM'
                })
        return findings
