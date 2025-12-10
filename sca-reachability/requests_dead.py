"""
SCA Reachability Test: requests library - DEAD CODE

This file contains UNREACHABLE/DEAD CODE that should NOT trigger reachability alerts.
All vulnerable function calls in this file are in code paths that will never execute.
"""

import requests


def unused_function_with_requests(url: str) -> None:
    """
    This function is defined but NEVER CALLED.
    
    Contains calls to requests.get() which would transitively call vulnerable code,
    but since this function is never invoked, it should be considered dead code.
    """
    # Dead code: This function is never called from main or anywhere else
    response = requests.get(url)  # UNREACHABLE
    print(response.text)


def conditional_dead_code(url: str) -> None:
    """
    This function has unreachable code after an early return.
    """
    if True:  # Always returns here
        return
    
    # Dead code: This line is never reached
    response = requests.get(url)  # UNREACHABLE
    requests.Session().request("GET", url)  # UNREACHABLE


def exception_handler_dead_code(url: str) -> None:
    """
    This function has unreachable exception handler code.
    """
    try:
        # This will never raise an exception that reaches the except block
        x = 1 + 1
        return
    except Exception:
        # Dead code: This exception handler is never reached
        response = requests.get(url)  # UNREACHABLE
        session = requests.Session()
        session.send(None)  # UNREACHABLE


def unreachable_after_false_condition(url: str) -> None:
    """
    Code after an if False condition is unreachable.
    """
    if False:
        # Dead code: This block never executes
        response = requests.get(url)  # UNREACHABLE
        requests.api.request("GET", url)  # UNREACHABLE
        session = requests.Session()
        session.request("GET", url)  # UNREACHABLE


class UnusedClass:
    """
    This class is defined but NEVER INSTANTIATED.
    All methods containing vulnerable calls are dead code.
    """
    
    def __init__(self, url: str) -> None:
        """Dead code: Constructor never called."""
        self.url = url
        # Dead code: This is never executed
        response = requests.get(url)  # UNREACHABLE
    
    def fetch_data(self) -> None:
        """Dead code: Method never called."""
        # Dead code: Unreachable since class is never instantiated
        session = requests.Session()
        session.get(self.url)  # UNREACHABLE
        session.send(None)  # UNREACHABLE


def imported_but_unused() -> None:
    """
    This function imports requests but never uses it in reachable code.
    """
    # requests is imported at module level but this function doesn't use it
    # and is never called
    pass


if __name__ == "__main__":
    # Entry point: Only this code executes
    # None of the functions above are called, making all their requests calls dead code
    
    print("This file contains only dead code with requests calls")
    print("No vulnerable functions should be flagged as reachable")
    
    # Example of what would be reachable (but we're not doing it):
    # result = fetch_data("https://example.com")  # This would be reachable if uncommented

