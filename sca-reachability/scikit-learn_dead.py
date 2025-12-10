"""
SCA Reachability Test: scikit-learn library - DEAD CODE

This file contains UNREACHABLE/DEAD CODE that should NOT trigger reachability alerts.
All vulnerable function calls to CountVectorizer._limit_features() are in code paths
that will never execute.
"""

from sklearn.feature_extraction.text import CountVectorizer


def unused_sklearn_function(texts: list[str]) -> None:
    """
    This function is defined but NEVER CALLED.
    
    Contains calls to CountVectorizer that would trigger _limit_features(),
    but since this function is never invoked, it should be considered dead code.
    """
    # Dead code: This function is never called from main or anywhere else
    vectorizer = CountVectorizer(max_features=100)  # UNREACHABLE
    vectorizer.fit_transform(texts)  # UNREACHABLE - would call _limit_features()


def conditional_dead_code_sklearn(texts: list[str]) -> None:
    """
    This function has unreachable code after an early return.
    """
    if True:  # Always returns here
        return
    
    # Dead code: This line is never reached
    vectorizer = CountVectorizer()  # UNREACHABLE
    vectorizer._limit_features(None, None)  # UNREACHABLE - direct call to vulnerable method


def exception_handler_dead_code_sklearn(texts: list[str]) -> None:
    """
    This function has unreachable exception handler code.
    """
    try:
        # This will never raise an exception that reaches the except block
        x = 1 + 1
        return
    except Exception:
        # Dead code: This exception handler is never reached
        vectorizer = CountVectorizer(max_features=50)  # UNREACHABLE
        vectorizer.fit_transform(texts)  # UNREACHABLE


def unreachable_after_false_condition_sklearn(texts: list[str]) -> None:
    """
    Code after an if False condition is unreachable.
    """
    if False:
        # Dead code: This block never executes
        vectorizer = CountVectorizer()  # UNREACHABLE
        vectorizer.fit_transform(texts)  # UNREACHABLE
        # Direct call to vulnerable method (would be flagged by dumb regex)
        vectorizer._limit_features(None, None)  # UNREACHABLE


class UnusedSklearnClass:
    """
    This class is defined but NEVER INSTANTIATED.
    All methods containing vulnerable calls are dead code.
    """
    
    def __init__(self, texts: list[str]) -> None:
        """Dead code: Constructor never called."""
        self.texts = texts
        # Dead code: This is never executed
        self.vectorizer = CountVectorizer()  # UNREACHABLE
    
    def process(self) -> None:
        """Dead code: Method never called."""
        # Dead code: Unreachable since class is never instantiated
        self.vectorizer.fit_transform(self.texts)  # UNREACHABLE
        # Would call _limit_features() internally, but code is dead


def imported_but_unused_sklearn() -> None:
    """
    This function references sklearn but never uses it in reachable code.
    """
    # CountVectorizer is imported at module level but this function doesn't use it
    # and is never called
    pass


def nested_unreachable_code(texts: list[str]) -> None:
    """
    Nested conditions that make code unreachable.
    """
    if False:
        if True:
            # Dead code: Outer condition is False
            vectorizer = CountVectorizer()  # UNREACHABLE
            vectorizer.fit_transform(texts)  # UNREACHABLE
    else:
        if False:
            # Dead code: Inner condition is False
            vectorizer = CountVectorizer(max_features=10)  # UNREACHABLE
            vectorizer._limit_features(None, None)  # UNREACHABLE


if __name__ == "__main__":
    # Entry point: Only this code executes
    # None of the functions above are called, making all their sklearn calls dead code
    
    print("This file contains only dead code with scikit-learn calls")
    print("No vulnerable functions should be flagged as reachable")
    print("Tools that use regex or simple pattern matching may incorrectly flag these")
    
    # Example of what would be reachable (but we're not doing it):
    # vectorizer = CountVectorizer()
    # vectorizer.fit_transform(["sample text"])  # This would be reachable if uncommented

