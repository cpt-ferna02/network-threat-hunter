import numpy as np
from collections import defaultdict

class BeaconDetector:
    def __init__(self, flows, threshold=0.3):
        self.flows = flows
        self.threshold = threshold

    def detect(self):
        beacons = []
        for flow_key, timestamps in self.flows.items():
            if len(timestamps) < 5:
                continue
            timestamps_sorted = sorted(timestamps)
            intervals = [timestamps_sorted[i+1] - timestamps_sorted[i]
                        for i in range(len(timestamps_sorted)-1)]
            mean = np.mean(intervals)
            std = np.std(intervals)
            cv = std / mean if mean > 0 else 999
            if cv < self.threshold and mean > 2:
                src, dst, port = flow_key.split(':')
                beacons.append({
                    'src_ip': src,
                    'dst_ip': dst,
                    'port': port,
                    'interval_avg_sec': round(mean, 2),
                    'coefficient_of_variation': round(cv, 4),
                    'hit_count': len(timestamps),
                    'mitre': 'T1071 - Application Layer Protocol',
                    'severity': 'HIGH'
                })
        return beacons

