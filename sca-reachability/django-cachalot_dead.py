"""
SCA Reachability Test: django-cachalot library - DEAD CODE

This file contains UNREACHABLE/DEAD CODE that should NOT trigger reachability alerts.
All vulnerable function calls to cachalot.utils._get_tables() and Django's SQLCompiler.as_sql()
are in code paths that will never execute.
"""

from django.conf import settings
from django.http import JsonResponse
from django.urls import path
from django.views import View


def unused_cachalot_function() -> None:
    """
    This function is defined but NEVER CALLED.
    
    Contains calls to cachalot.utils._get_tables() which would transitively call
    Django's vulnerable SQLCompiler.as_sql(), but since this function is never
    invoked, it should be considered dead code.
    """
    # Dead code: This function is never called from main or anywhere else
    from cachalot import utils as cachalot_utils
    tables = cachalot_utils._get_tables()  # UNREACHABLE
    # Would transitively call SQLCompiler.as_sql() (CVE-2022-28347), but code is dead


def conditional_dead_code_cachalot() -> None:
    """
    This function has unreachable code after an early return.
    """
    if True:  # Always returns here
        return
    
    # Dead code: This line is never reached
    from cachalot import utils as cachalot_utils
    cachalot_utils._get_tables()  # UNREACHABLE


def exception_handler_dead_code_cachalot() -> None:
    """
    This function has unreachable exception handler code.
    """
    try:
        # This will never raise an exception that reaches the except block
        x = 1 + 1
        return
    except Exception:
        # Dead code: This exception handler is never reached
        from cachalot import utils as cachalot_utils
        cachalot_utils._get_tables()  # UNREACHABLE


def unreachable_after_false_condition_cachalot() -> None:
    """
    Code after an if False condition is unreachable.
    """
    if False:
        # Dead code: This block never executes
        from cachalot import utils as cachalot_utils
        cachalot_utils._get_tables()  # UNREACHABLE
        # Would call SQLCompiler.as_sql() transitively, but unreachable


class UnusedDjangoView(View):
    """
    This Django view class is defined but NEVER REGISTERED in URL patterns.
    All methods containing vulnerable calls are dead code.
    """
    
    def get(self, request):
        """Dead code: View never registered, so never called by Django."""
        # Dead code: This view is never routed to, so never executed
        from cachalot import utils as cachalot_utils
        tables = cachalot_utils._get_tables()  # UNREACHABLE
        return JsonResponse({'tables': list(tables)})
    
    def post(self, request):
        """Dead code: Method never called."""
        from cachalot import utils as cachalot_utils
        cachalot_utils._get_tables()  # UNREACHABLE
        return JsonResponse({'status': 'ok'})


def unused_django_url_pattern() -> list:
    """
    This function returns URL patterns that are never used.
    """
    # Dead code: These patterns are returned but never registered
    return [
        path('dead/endpoint', UnusedDjangoView.as_view()),  # UNREACHABLE
    ]


def imported_but_unused_cachalot() -> None:
    """
    This function would import cachalot but never uses it in reachable code.
    """
    # cachalot is never imported at module level
    # This function is also never called
    pass


def nested_unreachable_django_code() -> None:
    """
    Nested conditions that make code unreachable.
    """
    if False:
        if True:
            # Dead code: Outer condition is False
            from cachalot import utils as cachalot_utils
            cachalot_utils._get_tables()  # UNREACHABLE
    else:
        if False:
            # Dead code: Inner condition is False
            from cachalot import utils as cachalot_utils
            cachalot_utils._get_tables()  # UNREACHABLE


if __name__ == "__main__":
    # Entry point: Only this code executes
    # None of the functions above are called, making all their cachalot/Django calls dead code
    
    print("This file contains only dead code with django-cachalot calls")
    print("No vulnerable functions should be flagged as reachable")
    print("Tools that don't understand Django's IoC may incorrectly flag UnusedDjangoView")
    
    # Example of what would be reachable (but we're not doing it):
    # from cachalot import utils as cachalot_utils
    # tables = cachalot_utils._get_tables()  # This would be reachable if uncommented

