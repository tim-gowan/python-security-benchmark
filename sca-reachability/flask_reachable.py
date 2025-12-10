"""
SCA Reachability Test: Flask library (CVE-2025-66221)

This file demonstrates REACHABLE code that calls vulnerable functions in Flask
and its transitive dependency werkzeug.

Call Path:
1. First-party code: main() → Flask app → route handler → send_static_file()
2. Direct dependency: flask.app.Flask.send_static_file() → flask.helpers.send_from_directory()
3. Transitive dependency: werkzeug.utils.send_from_directory() (vulnerable)
4. Transitive dependency: werkzeug.security.safe_join() (vulnerable)

CVE-2025-66221: Path traversal vulnerability in Flask's send_static_file() and
send_from_directory() functions, which transitively call vulnerable werkzeug functions.

Exploit Scenario:
- Attacker controls file path parameter in Flask route
- Route calls Flask.send_static_file() or send_from_directory()
- These functions call werkzeug.utils.send_from_directory() transitively
- Vulnerable werkzeug.security.safe_join() may allow path traversal
- This demonstrates reachability through Flask's routing system (inversion of control)
"""

from flask import Flask, send_from_directory, send_static_file


app = Flask(__name__)


@app.route('/static/<path:filename>')
def serve_static_file(filename: str) -> object:
    """
    Flask route that serves static files.
    
    This route calls Flask.send_static_file() which transitively calls vulnerable
    werkzeug functions.
    
    Call path:
    - HTTP request → Flask routing → this function
    - send_static_file() → flask.helpers.send_from_directory() (direct)
    - send_from_directory() → werkzeug.utils.send_from_directory() (transitive)
    - werkzeug.utils.send_from_directory() → werkzeug.security.safe_join() (transitive - vulnerable)
    
    Args:
        filename: File path to serve (could be attacker-controlled)
    
    Returns:
        Flask response with file content
    """
    # Direct call to vulnerable function in direct dependency
    # This transitively calls:
    # 1. flask.helpers.send_from_directory() (direct)
    # 2. werkzeug.utils.send_from_directory() (transitive)
    # 3. werkzeug.security.safe_join() (transitive - CVE-2025-66221)
    #
    # Payload: Attacker-controlled filename could exploit path traversal in werkzeug.safe_join()
    # The vulnerable safe_join() function may not properly sanitize paths
    return send_static_file(filename)


@app.route('/files/<path:filepath>')
def serve_file(filepath: str) -> object:
    """
    Flask route that serves files from a directory.
    
    This demonstrates another code path that reaches the vulnerable functions.
    
    Call path:
    - HTTP request → Flask routing → this function
    - send_from_directory() → werkzeug.utils.send_from_directory() (transitive)
    - werkzeug.utils.send_from_directory() → werkzeug.security.safe_join() (vulnerable)
    
    Args:
        filepath: Path to file in directory (could be attacker-controlled)
    
    Returns:
        Flask response with file content
    """
    # Direct call to flask.helpers.send_from_directory()
    # This transitively calls werkzeug functions (CVE-2025-66221)
    # Payload: Attacker-controlled filepath could trigger path traversal
    return send_from_directory('/tmp', filepath)


def serve_file_direct(filepath: str) -> object:
    """
    Direct function call (not through Flask route) for testing.
    
    This demonstrates the same vulnerable call path but without HTTP request.
    Useful for direct execution testing.
    
    Call path:
    - Direct call → send_from_directory()
    - send_from_directory() → werkzeug.utils.send_from_directory() (transitive)
    - werkzeug.utils.send_from_directory() → werkzeug.security.safe_join() (vulnerable)
    """
    # Direct call that reaches vulnerable werkzeug functions
    # Transitive path: send_from_directory() → werkzeug.send_from_directory() → safe_join()
    return send_from_directory('/tmp', filepath)


if __name__ == "__main__":
    """
    Entry point for Flask application.
    
    This demonstrates two execution modes:
    1. Direct execution: Calls serve_file_direct() (bypasses HTTP)
    2. Server mode: Starts Flask dev server (requires HTTP request to trigger routes)
    
    For reachability testing, both paths should be considered:
    - Direct call path: main() → serve_file_direct() → send_from_directory() → werkzeug
    - HTTP call path: HTTP request → Flask route → send_static_file() → werkzeug
    """
    
    # Mode 1: Direct function call (simpler for testing)
    # This directly calls the vulnerable function chain
    # Call path: serve_file_direct() → send_from_directory() → werkzeug.safe_join()
    print("Testing direct call path...")
    print("Call path: main() → serve_file_direct() → send_from_directory() → werkzeug.safe_join()")
    try:
        # This call reaches:
        # - flask.helpers.send_from_directory() (direct)
        # - werkzeug.utils.send_from_directory() (transitive)
        # - werkzeug.security.safe_join() (transitive - CVE-2025-66221)
        response = serve_file_direct("test.txt")
        print(f"Direct call successful. Response type: {type(response)}")
    except Exception as e:
        print(f"Direct call error (expected if file not found): {e}")
        print("Note: The vulnerable code path is still reachable even if file doesn't exist")
    
    # Mode 2: Start Flask server (demonstrates inversion of control)
    # To test: Run this file, then make HTTP request to http://localhost:5000/static/test.txt
    # This shows how Flask's routing makes code reachable through HTTP requests
    print("\nTo test HTTP path, start server and visit:")
    print("  - http://localhost:5000/static/<filename>")
    print("  - http://localhost:5000/files/<filepath>")
    print("Starting Flask development server...")
    print("Press Ctrl+C to stop")
    
    # Start Flask server
    # In production, this would be handled by WSGI server
    # For benchmarking, this demonstrates that routes are reachable via HTTP
    app.run(host='127.0.0.1', port=5000, debug=False)

