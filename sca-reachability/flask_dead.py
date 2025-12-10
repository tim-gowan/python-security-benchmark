"""
SCA Reachability Test: Flask library - DEAD CODE

This file contains UNREACHABLE/DEAD CODE that should NOT trigger reachability alerts.
All vulnerable function calls to Flask's send_static_file(), send_from_directory() and
their transitive dependencies (werkzeug) are in code paths that will never execute.
"""

from flask import Flask, send_from_directory, send_static_file


app = Flask(__name__)


def unused_flask_function(filename: str) -> None:
    """
    This function is defined but NEVER CALLED.
    
    Contains calls to Flask's send_static_file() and send_from_directory() which would
    transitively call vulnerable werkzeug functions, but since this function is never
    invoked, it should be considered dead code.
    """
    # Dead code: This function is never called from main or anywhere else
    send_static_file(filename)  # UNREACHABLE
    # Would transitively call werkzeug.security.safe_join() (CVE-2025-66221), but code is dead


def conditional_dead_code_flask(filename: str) -> None:
    """
    This function has unreachable code after an early return.
    """
    if True:  # Always returns here
        return
    
    # Dead code: This line is never reached
    send_static_file(filename)  # UNREACHABLE
    send_from_directory('/tmp', filename)  # UNREACHABLE


def exception_handler_dead_code_flask(filename: str) -> None:
    """
    This function has unreachable exception handler code.
    """
    try:
        # This will never raise an exception that reaches the except block
        x = 1 + 1
        return
    except Exception:
        # Dead code: This exception handler is never reached
        send_static_file(filename)  # UNREACHABLE
        send_from_directory('/tmp', filename)  # UNREACHABLE


def unreachable_after_false_condition_flask(filename: str) -> None:
    """
    Code after an if False condition is unreachable.
    """
    if False:
        # Dead code: This block never executes
        send_static_file(filename)  # UNREACHABLE
        send_from_directory('/tmp', filename)  # UNREACHABLE
        # Would transitively call werkzeug.security.safe_join(), but unreachable


@app.route('/dead/endpoint/<path:filename>')
def unused_flask_route(filename: str) -> object:
    """
    This Flask route is defined but NEVER ACCESSED.
    
    The route is registered but no HTTP requests will reach it during execution.
    All code in this route is dead code.
    """
    # Dead code: This route is never called (no requests to /dead/endpoint/)
    return send_static_file(filename)  # UNREACHABLE


@app.route('/another/dead/<path:filepath>')
def another_unused_route(filepath: str) -> object:
    """
    Another unused Flask route with dead code.
    """
    # Dead code: Route never accessed
    return send_from_directory('/tmp', filepath)  # UNREACHABLE
    # Would call werkzeug functions transitively, but route is never hit


class UnusedFlaskClass:
    """
    This class is defined but NEVER INSTANTIATED.
    All methods containing vulnerable calls are dead code.
    """
    
    def __init__(self, filename: str) -> None:
        """Dead code: Constructor never called."""
        self.filename = filename
        # Dead code: This is never executed
        send_static_file(filename)  # UNREACHABLE
    
    def serve(self) -> None:
        """Dead code: Method never called."""
        # Dead code: Unreachable since class is never instantiated
        send_static_file(self.filename)  # UNREACHABLE
        send_from_directory('/tmp', self.filename)  # UNREACHABLE


def imported_but_unused_flask() -> None:
    """
    This function references Flask functions but never uses them in reachable code.
    """
    # send_static_file and send_from_directory are imported at module level
    # but this function doesn't use them and is never called
    pass


def nested_unreachable_flask_code(filename: str) -> None:
    """
    Nested conditions that make code unreachable.
    """
    if False:
        if True:
            # Dead code: Outer condition is False
            send_static_file(filename)  # UNREACHABLE
    else:
        if False:
            # Dead code: Inner condition is False
            send_from_directory('/tmp', filename)  # UNREACHABLE
            # Would transitively call werkzeug.security.safe_join() (CVE-2025-66221)


if __name__ == "__main__":
    # Entry point: Only this code executes
    # None of the functions above are called, making all their Flask calls dead code
    # The unused routes are registered but never accessed via HTTP requests
    
    print("This file contains only dead code with Flask calls")
    print("No vulnerable functions should be flagged as reachable")
    print("Tools that don't understand Flask routing may incorrectly flag unused routes")
    print("Proper reachability analysis should identify these as dead code")
    
    # Note: The Flask app is created and routes are registered, but:
    # 1. The unused routes are never accessed
    # 2. The unused functions are never called
    # 3. All vulnerable code paths are unreachable
    
    # Example of what would be reachable (but we're not doing it):
    # @app.route('/active')
    # def active_route():
    #     return send_static_file("test.txt")  # This would be reachable if defined and accessed

