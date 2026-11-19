import unittest

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
        connection.proto = "udp"
        events = [connection(port=port) for port in range(8000, 8015)]
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