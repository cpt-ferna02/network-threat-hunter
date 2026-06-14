import os, uuid
from flask import Flask, request, render_template, jsonify
from dotenv import load_dotenv

load_dotenv()

from modules.pcap_parser import PCAPParser
from modules.beacon_detector import BeaconDetector
from modules.dns_analyzer import DNSAnalyzer
from modules.http_analyzer import HTTPAnalyzer
from modules.lateral_movement import LateralMovementDetector
from modules.ioc_extractor import IOCExtractor
from modules.attack_mapper import build_attack_timeline
from modules.report_generator import generate_report

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    file = request.files.get('pcap')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    filename = f"{uuid.uuid4()}.pcap"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    try:
        parser = PCAPParser(path).parse()
        findings = {
            'beacons': BeaconDetector(parser.flows).detect(),
            'dns':     DNSAnalyzer(parser.dns_queries).detect(),
            'http':    HTTPAnalyzer(parser.http_requests).detect(),
            'lateral': LateralMovementDetector(parser.packets).detect(),
        }
        iocs = IOCExtractor(findings).extract()
        timeline = build_attack_timeline(findings)
        report_html = generate_report(findings, iocs, timeline)

        print(f"DEBUG report length: {len(report_html)}")
        print(f"DEBUG report preview: {report_html[:100]}")

        stats = {
            'total_packets': len(parser.packets),
            'total_flows': len(parser.flows),
            'total_findings': sum(len(v) for v in findings.values()),
            'total_iocs': len(iocs['ips']) + len(iocs['domains'])
        }

        return render_template('results.html',
            findings=findings,
            iocs=iocs,
            timeline=timeline,
            report=report_html,
            stats=stats
        )
    finally:
        if os.path.exists(path):
            os.remove(path)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
