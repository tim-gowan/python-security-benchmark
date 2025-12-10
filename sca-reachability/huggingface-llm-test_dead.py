"""
SCA Reachability Test: huggingface-llm-test library - DEAD CODE

This file contains UNREACHABLE/DEAD CODE that should NOT trigger reachability alerts.
All vulnerable function calls to huggingface_llm_test.load_and_use_model() and its
transitive dependencies (transformers, setuptools) are in code paths that will never execute.
"""

from huggingface_llm_test import load_and_use_model


def unused_huggingface_function(model_name: str) -> None:
    """
    This function is defined but NEVER CALLED.
    
    Contains calls to load_and_use_model() which would transitively call vulnerable
    functions in transformers and setuptools, but since this function is never
    invoked, it should be considered dead code.
    """
    # Dead code: This function is never called from main or anywhere else
    model = load_and_use_model(model_name)  # UNREACHABLE
    # Would transitively call:
    # - transformers.PreTrainedModel.to() (UNREACHABLE)
    # - setuptools.PackageIndex.download() (UNREACHABLE - CVE-2025-47273)


def conditional_dead_code_huggingface(model_name: str) -> None:
    """
    This function has unreachable code after an early return.
    """
    if True:  # Always returns here
        return
    
    # Dead code: This line is never reached
    load_and_use_model(model_name)  # UNREACHABLE
    # Would call transformers.to() and setuptools.download() transitively, but dead


def exception_handler_dead_code_huggingface(model_name: str) -> None:
    """
    This function has unreachable exception handler code.
    """
    try:
        # This will never raise an exception that reaches the except block
        x = 1 + 1
        return
    except Exception:
        # Dead code: This exception handler is never reached
        load_and_use_model(model_name)  # UNREACHABLE
        # Transitive calls to transformers and setuptools are also unreachable


def unreachable_after_false_condition_huggingface(model_name: str) -> None:
    """
    Code after an if False condition is unreachable.
    """
    if False:
        # Dead code: This block never executes
        load_and_use_model(model_name)  # UNREACHABLE
        # Would transitively call:
        # - transformers.modeling_utils.PreTrainedModel.to() (UNREACHABLE)
        # - transformers.feature_extraction_utils.BatchFeature.to() (UNREACHABLE)
        # - setuptools.package_index.PackageIndex.download() (UNREACHABLE)


class UnusedHuggingfaceClass:
    """
    This class is defined but NEVER INSTANTIATED.
    All methods containing vulnerable calls are dead code.
    """
    
    def __init__(self, model_name: str) -> None:
        """Dead code: Constructor never called."""
        self.model_name = model_name
        # Dead code: This is never executed
        self.model = load_and_use_model(model_name)  # UNREACHABLE
    
    def process(self, input_data: str) -> None:
        """Dead code: Method never called."""
        # Dead code: Unreachable since class is never instantiated
        model = load_and_use_model(self.model_name)  # UNREACHABLE
        # Would call transformers and setuptools transitively, but code is dead


def imported_but_unused_huggingface() -> None:
    """
    This function references huggingface_llm_test but never uses it in reachable code.
    """
    # load_and_use_model is imported at module level but this function doesn't use it
    # and is never called
    pass


def nested_unreachable_huggingface_code(model_name: str) -> None:
    """
    Nested conditions that make code unreachable.
    """
    if False:
        if True:
            # Dead code: Outer condition is False
            load_and_use_model(model_name)  # UNREACHABLE
    else:
        if False:
            # Dead code: Inner condition is False
            load_and_use_model(model_name)  # UNREACHABLE
            # Would transitively call setuptools.PackageIndex.download() (CVE-2025-47273)


def deep_unreachable_code(model_name: str) -> None:
    """
    Multiple levels of unreachable conditions.
    """
    if False:
        if True:
            if False:
                # Dead code: Multiple false conditions
                load_and_use_model(model_name)  # UNREACHABLE
                # Transitive chain would be: transformers → setuptools, but all dead


if __name__ == "__main__":
    # Entry point: Only this code executes
    # None of the functions above are called, making all their huggingface calls dead code
    
    print("This file contains only dead code with huggingface-llm-test calls")
    print("No vulnerable functions should be flagged as reachable")
    print("Tools that use simple regex may incorrectly flag these as reachable")
    print("Proper reachability analysis should identify these as dead code")
    
    # Example of what would be reachable (but we're not doing it):
    # model = load_and_use_model("test-model")  # This would be reachable if uncommented
    # This would transitively call transformers and setuptools vulnerable functions

