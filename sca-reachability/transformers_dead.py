"""
SCA Reachability Test: transformers library - DEAD CODE

This file contains UNREACHABLE/DEAD CODE that should NOT trigger reachability alerts.
All vulnerable function calls to transformers functions (PreTrainedModel.to(),
BatchFeature.to(), requires_backends(), load_video()) and their transitive
dependencies (setuptools) are in code paths that will never execute.
"""

from transformers import AutoModel
from transformers.modeling_utils import PreTrainedModel
from transformers.feature_extraction_utils import BatchFeature
from transformers.utils.import_utils import requires_backends
from transformers.video_utils import load_video


def unused_transformers_function(model_name: str) -> None:
    """
    This function is defined but NEVER CALLED.
    
    Contains calls to transformers functions which would transitively call vulnerable
    setuptools functions, but since this function is never invoked, it should be
    considered dead code.
    """
    # Dead code: This function is never called from main or anywhere else
    model = AutoModel.from_pretrained(model_name)  # UNREACHABLE
    model.to("cpu")  # UNREACHABLE - would call vulnerable PreTrainedModel.to()
    # Would transitively call setuptools.PackageIndex.download() (CVE-2025-47273), but dead


def conditional_dead_code_transformers(model_name: str) -> None:
    """
    This function has unreachable code after an early return.
    """
    if True:  # Always returns here
        return
    
    # Dead code: This line is never reached
    model = AutoModel.from_pretrained(model_name)  # UNREACHABLE
    model.to("cpu")  # UNREACHABLE
    # Would call setuptools.download() transitively, but dead


def exception_handler_dead_code_transformers(model_name: str) -> None:
    """
    This function has unreachable exception handler code.
    """
    try:
        # This will never raise an exception that reaches the except block
        x = 1 + 1
        return
    except Exception:
        # Dead code: This exception handler is never reached
        model = AutoModel.from_pretrained(model_name)  # UNREACHABLE
        model.to("cpu")  # UNREACHABLE
        # Transitive calls to setuptools are also unreachable


def unreachable_after_false_condition_transformers(model_name: str) -> None:
    """
    Code after an if False condition is unreachable.
    """
    if False:
        # Dead code: This block never executes
        model = AutoModel.from_pretrained(model_name)  # UNREACHABLE
        model.to("cpu")  # UNREACHABLE - would call vulnerable PreTrainedModel.to()
        # Would transitively call:
        # - setuptools.package_index.PackageIndex.download() (UNREACHABLE)
        # - setuptools.package_index.PackageIndex._download_url() (UNREACHABLE)


def unused_batch_feature_function(input_data: dict) -> None:
    """
    Unused function with BatchFeature.to() call.
    """
    if False:
        # Dead code: Never executes
        batch = BatchFeature(input_data)  # UNREACHABLE
        batch.to("cpu")  # UNREACHABLE - would call vulnerable BatchFeature.to()


def unused_requires_backends_function(backends: list[str]) -> None:
    """
    Unused function with requires_backends() call.
    """
    if False:
        # Dead code: Never executes
        requires_backends(backends)  # UNREACHABLE
        # Would transitively call setuptools for backend installation, but dead


def unused_load_video_function(video_path: str) -> None:
    """
    Unused function with load_video() call.
    """
    if False:
        # Dead code: Never executes
        load_video(video_path)  # UNREACHABLE
        # Would call vulnerable load_video() function, but unreachable


class UnusedTransformersClass:
    """
    This class is defined but NEVER INSTANTIATED.
    All methods containing vulnerable calls are dead code.
    """
    
    def __init__(self, model_name: str) -> None:
        """Dead code: Constructor never called."""
        self.model_name = model_name
        # Dead code: This is never executed
        self.model = AutoModel.from_pretrained(model_name)  # UNREACHABLE
    
    def load_and_move(self, device: str) -> None:
        """Dead code: Method never called."""
        # Dead code: Unreachable since class is never instantiated
        self.model.to(device)  # UNREACHABLE - would call PreTrainedModel.to()
        # Would call setuptools transitively, but code is dead
    
    def process_features(self, input_data: dict) -> None:
        """Dead code: Method never called."""
        batch = BatchFeature(input_data)  # UNREACHABLE
        batch.to("cpu")  # UNREACHABLE - would call BatchFeature.to()


def imported_but_unused_transformers() -> None:
    """
    This function references transformers but never uses it in reachable code.
    """
    # Transformers functions are imported at module level but this function doesn't use them
    # and is never called
    pass


def nested_unreachable_transformers_code(model_name: str) -> None:
    """
    Nested conditions that make code unreachable.
    """
    if False:
        if True:
            # Dead code: Outer condition is False
            model = AutoModel.from_pretrained(model_name)  # UNREACHABLE
            model.to("cpu")  # UNREACHABLE
    else:
        if False:
            # Dead code: Inner condition is False
            batch = BatchFeature({})  # UNREACHABLE
            batch.to("cpu")  # UNREACHABLE
            # Would transitively call setuptools.PackageIndex.download() (CVE-2025-47273)


def deep_unreachable_transformers_code(model_name: str) -> None:
    """
    Multiple levels of unreachable conditions.
    """
    if False:
        if True:
            if False:
                # Dead code: Multiple false conditions
                model = AutoModel.from_pretrained(model_name)  # UNREACHABLE
                model.to("cpu")  # UNREACHABLE
                requires_backends(["torch"])  # UNREACHABLE
                load_video("test.mp4")  # UNREACHABLE
                # Transitive chain would be: transformers → setuptools, but all dead


if __name__ == "__main__":
    # Entry point: Only this code executes
    # None of the functions above are called, making all their transformers calls dead code
    
    print("This file contains only dead code with transformers calls")
    print("No vulnerable functions should be flagged as reachable")
    print("Tools that use simple regex may incorrectly flag these as reachable")
    print("Proper reachability analysis should identify these as dead code")
    
    # Example of what would be reachable (but we're not doing it):
    # model = AutoModel.from_pretrained("bert-base-uncased")
    # model.to("cpu")  # This would be reachable if uncommented
    # This would transitively call setuptools vulnerable functions

