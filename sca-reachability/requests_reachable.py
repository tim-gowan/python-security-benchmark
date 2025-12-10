"""
SCA Reachability Test: requests library (CVE-2023-32681, CVE-2024-35195)

This file demonstrates REACHABLE code that calls vulnerable functions in the requests
library and its transitive dependencies (urllib3, idna, werkzeug).

Call Path:
1. First-party code: main() → fetch_data() → requests.get()
2. Direct dependency: requests.get() → requests.api.request() → requests.sessions.Session.request()
3. Transitive dependency: Session.request() → Session.send() → urllib3 (vulnerable code)
4. Transitive dependency: Session.get_adapter() → werkzeug (CVE-2023-32681)
5. Transitive dependency: idna encoding (CVE-2023-32681)

CVE-2023-32681: Multiple packages (requests, urllib3, idna, werkzeug) have vulnerabilities
CVE-2024-35195: Session object does not verify requests after making first request with verify=False

Exploit Scenario:
- Attacker controls URL parameter, can trigger vulnerable code paths in transitive dependencies
- Session with verify=False can be exploited to bypass SSL verification on subsequent requests
"""

import requests


def fetch_data(url: str) -> dict:
    """
    Fetch data from a URL using requests library.
    
    This function calls requests.get() which transitively calls:
    - requests.api.request() (direct)
    - requests.sessions.Session.request() (direct)
    - requests.sessions.Session.send() (direct)
    - urllib3 connection pool (transitive - vulnerable)
    - idna encoding (transitive - CVE-2023-32681)
    - werkzeug utilities (transitive - CVE-2023-32681)
    
    Args:
        url: URL to fetch (could be attacker-controlled)
    
    Returns:
        Response data as dictionary
    """
    # Direct call to vulnerable function: requests.get()
    # This transitively calls Session.request() → Session.send() → urllib3
    response = requests.get(url, timeout=5)
    return response.json() if response.status_code == 200 else {}


def fetch_with_session(url: str, verify_ssl: bool = True) -> dict:
    """
    Fetch data using Session object (CVE-2024-35195).
    
    If verify=False is set on first request, subsequent requests may not verify SSL.
    This demonstrates the Session.request() → Session.send() → HTTPAdapter.send() path.
    
    Args:
        url: URL to fetch
        verify_ssl: Whether to verify SSL certificates
    
    Returns:
        Response data as dictionary
    """
    session = requests.Session()
    # First request with verify=False can affect subsequent requests (CVE-2024-35195)
    # Call path: Session.request() → Session.send() → HTTPAdapter.send()
    response = session.get(url, verify=verify_ssl, timeout=5)
    return response.json() if response.status_code == 200 else {}


if __name__ == "__main__":
    # Entry point: This code is REACHABLE and will execute
    # Demonstrates reachability through direct dependency (requests) to transitive (urllib3/idna/werkzeug)
    
    # Example 1: Direct call path
    # Payload: Malicious URL could trigger vulnerable code in transitive dependencies
    result1 = fetch_data("https://httpbin.org/json")
    print(f"Fetched data: {result1}")
    
    # Example 2: Session-based call path (CVE-2024-35195)
    # Payload: First request with verify=False, then attacker-controlled URL
    result2 = fetch_with_session("https://httpbin.org/json", verify_ssl=False)
    print(f"Fetched with session: {result2}")

