import unittest
import json
import subprocess
import sys
from pathlib import Path

from main import analyze_ip


def connection(host="192.0.2.10", port=443, state="S0", sent=0, proto="tcp"):
    return {
        "id.orig_h": "198.51.100.10",
        "id.resp_h": host,
        "id.resp_p": port,
        "proto": proto,
        "conn_state": state,
        "orig_bytes": sent,
    }


class DetectionTests(unittest.TestCase):
    def test_port_scan_threshold(self):
        events = [connection(port=port) for port in range(8000, 8015)]
        self.assertNotIn("port_scan", analyze_ip(events[:14]))
        self.assertIn("port_scan", analyze_ip(events))
       
    def test_udp_port_scan_threshold(self):
        events = [connection(port=port, proto="udp") for port in range(8000, 8015)]
        self.assertNotIn("port_scan", analyze_ip(events[:14]))
        self.assertIn("port_scan", analyze_ip(events))

    def test_retries_to_one_port_do_not_count_as_distinct_ports(self):
        self.assertNotIn("port_scan", analyze_ip([connection()] * 30))

    def test_host_fanout_threshold(self):
        events = [connection(host=f"192.0.2.{i}") for i in range(1, 21)]
        self.assertNotIn("host_scan", analyze_ip(events[:19]))
        self.assertIn("host_scan", analyze_ip(events))

    def test_upload_threshold(self):
        limit = 100 * 1024 * 1024
        self.assertNotIn("large_upload", analyze_ip([connection(sent=limit - 1)]))
        self.assertIn("large_upload", analyze_ip([connection(sent=limit)]))

    def test_xss(self):
        self.assertIn("xss", analyze_ip([http("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")]))

    def test_sql_injection(self):
        self.assertIn("sql_injection", analyze_ip([http("/login", method="POST", request_body="username=admin%27+--+&password=anything")]))

    def test_directory_traversal(self):
        self.assertIn("directory_traversal", analyze_ip([http("/download?file=../secret.txt")]))

    def test_beaconing(self):
        events = [dict(connection(state="SF", port=80), ts=1000+i*60) for i in range(6)]
        self.assertNotIn("beaconing", analyze_ip(events[:4]))
        self.assertIn("beaconing", analyze_ip(events))

    def test_suspicious_http(self):
        self.assertIn("suspicious_http", analyze_ip([http("/fakeurl.htm", method="POST", user_agent="NetSupport Manager/1.3")]))

    def test_brute_force(self):
        events = [http("/login", method="POST", status_code=401) for _ in range(10)]
        self.assertNotIn("brute_force", analyze_ip(events[:9]))
        self.assertIn("brute_force", analyze_ip(events))

    def test_dos(self):
        events = [connection(state="SF", port=80) for _ in range(500)]
        self.assertNotIn("dos", analyze_ip(events[:499]))
        self.assertIn("dos", analyze_ip(events))

    def test_suspicious_dns(self):
        events = [{"id.orig_h": "198.51.100.10", "id.resp_h": "192.0.2.10", "query": f"test{i}.example.invalid", "rcode_name": "NXDOMAIN"} for i in range(50)]
        self.assertNotIn("suspicious_dns", analyze_ip(events[:49]))
        self.assertIn("suspicious_dns", analyze_ip(events))

    def test_normal_traffic(self):
        self.assertEqual({}, analyze_ip([http("/index.html", status_code=200), connection(state="SF")]))

    def test_combined_detections(self):
        events = [http("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"), http("/login", method="POST", request_body="username=admin%27+--+&password=anything"), http("/download?file=../secret.txt")]
        self.assertTrue({"xss", "sql_injection", "directory_traversal"}.issubset(analyze_ip(events)))
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("main.py"))], input="".join(json.dumps(e)+"\n" for e in events), text=True, capture_output=True, check=True)
        self.assertIn("Risk score: 100/100", result.stdout)
        self.assertIn("Possible XSS", result.stdout)
        self.assertIn("Possible SQL injection", result.stdout)
        self.assertIn("Possible directory traversal", result.stdout)

    def test_end_to_end_normal_traffic(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("main.py"))], input=json.dumps(http("/index.html", status_code=200))+"\n", text=True, capture_output=True, check=True)
        self.assertNotIn("[ALERT]", result.stdout)
        self.assertNotIn("Error:", result.stdout)


def http(uri, method="GET", **fields):
    return {"id.orig_h": "198.51.100.10", "id.resp_h": "192.0.2.10", "method": method, "uri": uri, **fields}


if __name__ == "__main__":
    unittest.main(verbosity=2)
