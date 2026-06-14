TECHNIQUE_MAP = {
    'beacons':  {'id': 'T1071',     'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'dns':      {'id': 'T1048.003', 'name': 'Exfiltration Over DNS',       'tactic': 'Exfiltration'},
    'http':     {'id': 'T1071.001', 'name': 'Web Protocols',               'tactic': 'Command and Control'},
    'lateral':  {'id': 'T1021',     'name': 'Remote Services',             'tactic': 'Lateral Movement'},
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

def build_attack_timeline(all_findings):
    timeline = []
    for category, findings in all_findings.items():
        technique = TECHNIQUE_MAP.get(category, {})
        for f in findings:
            timeline.append({
                'category': category,
                'finding': f,
                'mitre_id': technique.get('id', ''),
                'mitre_name': technique.get('name', ''),
                'tactic': technique.get('tactic', ''),
                'severity': f.get('severity', 'MEDIUM')
            })
    timeline.sort(key=lambda x: SEVERITY_ORDER.get(x['severity'], 99))
    return timeline
