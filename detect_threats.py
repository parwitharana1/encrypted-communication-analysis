import re
import math

from statistics import mean, pstdev
from collections import defaultdict, Counter
from urllib.parse import unquote_plus
'''
These include common web exploits and key indicators that could help identify them as malicious in network traffic 
'''

def normalize_text(value):
    #Decode URL-encoded input for inspection

    text = str(value or "")

    # Handle multiple layers of URL encoding
    for _ in range(3):
        decoded = unquote_plus(text)

        if decoded == text:
            break

        text = decoded

    return text.lower()


def get_http_payload(event):
    #Combine available HTTP request fields

    fields = [
        event.get("uri", ""),
        event.get("request_body", ""),
        event.get("post_data", "")
    ]

    return normalize_text(
        " ".join(str(field or "") for field in fields)
    )

def is_connection(event):
    return (
        "conn_state" in event
        and "proto" in event
    )

def is_http(event):
    return "method" in event and "uri" in event

def is_dns(event):
    return "query" in event

def numeric(value):
    try:
        return int(value or 0)
    except (ValueError, TypeError):
        return 0


# cross-site scripting (XSS) 

def detect_xss(events):

    patterns = [
        r"<\s*script\b",
        r"javascript\s*:",
        r"\bonerror\s*=",
        r"\bonload\s*=",
        r"<\s*iframe\b",
        r"<\s*svg\b.*\bonload\s*=",
        r"\balert\s*\("
    ]

    matches = []
    for event in events:
        if not is_http(event):
            continue
        payload = get_http_payload(event)
        if any(re.search(pattern, payload) for pattern in patterns):
            matches.append(event)
    if matches:
        return (
            35,
            f"Possible XSS: {len(matches)} suspicious HTTP requests"
        )

    return None
# SQL Injection 

def detect_sql_injection(events):

    patterns = [
        r"\bunion\s+(?:all\s+)?select\b",
        r"['\"]\s*(?:or|and)\s+",
        r"['\"]\s*--",
        r"\bdrop\s+table\b",
        r"\binsert\s+into\b",
        r"\bselect\b.+\bfrom\b",
        r"\bsleep\s*\(",
        r"\bbenchmark\s*\("
    ]

    matches = []
    for event in events:
        if not is_http(event):
            continue
        payload = get_http_payload(event)

        if any(re.search(pattern, payload) for pattern in patterns):
            matches.append(event)
    if matches:
        return (
            40,
            f"Possible SQL injection: {len(matches)} suspicious requests"
        )

    return None
# Directory Traversal 

def detect_directory_traversal(events):

    patterns = [
        r"\.\.[/\\]",
        r"/etc/passwd\b",
        r"/etc/shadow\b",
        r"windows[/\\]system32",
        r"windows[/\\]win\.ini"
    ]

    matches = []

    for event in events:
        if not is_http(event):
            continue
        payload = get_http_payload(event)
        if any(re.search(pattern, payload) for pattern in patterns):
            matches.append(event)

    if matches:
        return (
            35,
            f"Possible directory traversal: "
            f"{len(matches)} suspicious requests"
        )

    return None

# Command and control beaconing 
def detect_beaconing(events):

    destinations = defaultdict(list)

    for event in events:

        if not is_connection(event):
            continue

        target = event.get("id.resp_h")
        port = event.get("id.resp_p")
        timestamp = event.get("ts")

        if target and port is not None and timestamp is not None:

            destinations[(target, port)].append(
                float(timestamp)
            )

    for (target, port), timestamps in destinations.items():

        timestamps = sorted(set(timestamps))

        if len(timestamps) < 5:
            continue

        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        average_interval = mean(intervals)
        deviation = pstdev(intervals)

        if average_interval < 10:
            continue

        variation = deviation / average_interval

        if variation <= 0.15:
            return (
                40,
                f"Possible C2 beaconing to {target}:{port}; "
                f"average interval {average_interval:.1f} seconds"
            )

    return None

# Suspicious HTTP connection 
def detect_suspicious_http(events):

    repeated_posts = Counter()
    suspicious_markers = 0

    for event in events:

        if not is_http(event):
            continue

        method = str(event.get("method", "")).upper()
        target = event.get("id.resp_h")
        uri = normalize_text(event.get("uri"))
        payload = get_http_payload(event)

        user_agent = str(
            event.get("user_agent", "")
        ).lower()

        if method == "POST":
            repeated_posts[(target, uri)] += 1

        if (
            "cmd=encd" in payload
            or (
                "netsupport" in user_agent
                and "fakeurl.htm" in uri
            )
        ):
            suspicious_markers += 1

    if suspicious_markers:
        return (
            30,
            f"Suspicious HTTP communication: "
            f"{suspicious_markers} matching events"
        )

    for (target, uri), count in repeated_posts.items():

        if count >= 15:
            return (
                15,
                f"Repeated HTTP POST requests: "
                f"{count} requests to {target}{uri}"
            )

    return None

# brute force autehntication attempts 

def detect_brute_force(events):

    failures = Counter()
    for event in events:
        target = event.get("id.resp_h")
        if not target:
            continue
        if is_http(event):

            status = numeric(event.get("status_code"))
            uri = normalize_text(event.get("uri"))
            method = str(event.get("method", "")).upper()

            response = normalize_text(
                event.get("response_body")
            )

            login_endpoint = (
                "login" in uri
                or "signin" in uri
                or "auth" in uri
            )

            explicit_failure = (
                method == "POST"
                and (
                    "login failed" in response
                    or "invalid password" in response
                    or "invalid credentials" in response
                )
            )
            if (
                (login_endpoint and status == 401)
                or explicit_failure
            ):
                failures[target] += 1

        elif event.get("auth_success") is False:
            failures[target] += 1

    for target, count in failures.items():

        if count >= 10:
            return (
                30,
                f"Possible brute-force attack: "
                f"{count} authentication failures against {target}"
            )

    return None

# Denial of Service (DOS)

def detect_dos(events):

    connection_counts = Counter()
    request_counts = Counter()

    for event in events:

        target = event.get("id.resp_h")

        if not target:
            continue

        if is_connection(event):
            connection_counts[target] += 1

        if is_http(event):
            request_counts[target] += 1

    for target, count in connection_counts.items():

        if count >= 500:
            return (
                40,
                f"Possible DoS: {count} connections to {target}"
            )

    for target, count in request_counts.items():

        if count >= 1000:
            return (
                40,
                f"Possible HTTP flooding: "
                f"{count} requests to {target}"
            )

    return None

# Suspicious DNS activity 

def calculate_entropy(text):

    if not text:
        return 0.0

    frequencies = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def detect_suspicious_dns(events):

    dns_queries = []
    suspicious_queries = set()
    failed_queries = 0

    for event in events:

        if not is_dns(event):
            continue

        query = str(
            event.get("query", "")
        ).lower().rstrip(".")

        if not query:
            continue

        dns_queries.append(query)

        longest_label = max(
            query.split("."),
            key=len,
            default=""
        )

        entropy = calculate_entropy(longest_label)

        if len(longest_label) >= 40 and entropy >= 3.5:
            suspicious_queries.add(query)

        if event.get("rcode_name") == "NXDOMAIN":
            failed_queries += 1

    if len(suspicious_queries) >= 5:
        return (
            30,
            f"Possible DNS tunnelling: "
            f"{len(suspicious_queries)} unusual DNS queries"
        )

    if failed_queries >= 50:
        return (
            20,
            f"Suspicious DNS activity: "
            f"{failed_queries} NXDOMAIN responses"
        )

    if len(dns_queries) >= 300:
        return (
            20,
            f"High DNS query volume: {len(dns_queries)} queries"
        )

    return None

# sets the rules that helps figure out the type of activity 

DETECTION_RULES = {
    "xss": detect_xss,
    "sql_injection": detect_sql_injection,
    "directory_traversal": detect_directory_traversal,
    "beaconing": detect_beaconing,
    "suspicious_http": detect_suspicious_http,
    "brute_force": detect_brute_force,
    "dos": detect_dos,
    "suspicious_dns": detect_suspicious_dns
}

def analyze_additional_threats(events):
    detections = {}

    for rule_name, detector in DETECTION_RULES.items():

        result = detector(events)

        if result is not None:
            detections[rule_name] = result

    return detections
