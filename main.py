import sys
import json
import time
from collections import defaultdict, deque

WINDOW = 300 # 5 minute rolling window

connections = defaultdict(deque)
active_alerts = defaultdict(set)

def analyze_ip(events):
    detections = {}

    # Detect port scans against same target
    failed_ports = defaultdict(set)

    for event in events:
        proto = event.get("proto")
        if proto in ("tcp", "udp") and event.get("conn_state") in ("S0", "REJ"):
            target = event.get("id.resp_h")
            port = event.get("id.resp_p")

            if target is not None and port is not None:
                failed_ports[(proto, target)].add(port)

    max_ports = max(
        (len(ports) for ports in failed_ports.values()), default = 0)
    if max_ports >= 15:
        detections["port_scan"] = (25, f"possible port scan: {max_ports} ports")

    hosts = {
        e.get("id.resp_h")
        for e in events
        if e.get("id.resp_h")
    }

    if len(hosts) >= 20:
        detections["host_scan"] = (29, f"contacted {len(hosts)} distinct hosts")

    uploaded = sum(int(event.get("orig_bytes") or 0) for event in events)

    if uploaded >= 100 * 1024 * 1024:
        detections["large_upload"] = (15, f"outbound volume: {uploaded / 1048576:.1f} MiB")

    return detections

def process_events(event):
    ip = event.get("id.orig_h")

    if not ip:
        return

    now = time.time()
    recent = connections[ip]

    recent.append((now, event))

    # remove events older than 5 minutes
    while recent and recent[0][0] < now - WINDOW:
        recent.popleft()

    # Strip timestamps before analysis
    events = [e for timestamp, e in recent]

    detections = analyze_ip(events)
    current = set(detections)
    previous = active_alerts[ip]

    new_alerts = current - previous

    if new_alerts:
        score = min(100, sum(weight for weight, _ in detections.values()))

        print(f"\n[ALERT] Source: {ip}")
        print(f"Risk score: {score}/100")

        for rule in sorted(new_alerts):
            print(f" - {detections[rule][1]}")
        print(flush=True)

    active_alerts[ip] = current

    # Restore timestamps for rolling window
    connections[ip] = recent

def main():
    print("Beginning threat monitoring session...", flush=True)

    for line in sys.stdin:
        try:
            event = json.loads(line)
            process_events(event)
        except(json.JSONDecodeError, ValueError, TypeError) as e:
            print(f"Error: {e}", flush=True)
            continue

if __name__ == "__main__":
    main()