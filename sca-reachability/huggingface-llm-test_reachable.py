"""
SCA Reachability Test: huggingface-llm-test library (CVE-2025-47273)

This file demonstrates REACHABLE code that calls vulnerable functions in huggingface-llm-test
and its transitive dependencies (transformers, setuptools).

Call Path:
1. First-party code: main() → load_model() → huggingface_llm_test.load_and_use_model()
2. Direct dependency: huggingface_llm_test.load_and_use_model() → transformers model loading
3. Transitive dependency: transformers.modeling_utils.PreTrainedModel.to() (vulnerable)
4. Transitive dependency: transformers.feature_extraction_utils.BatchFeature.to() (vulnerable)
5. Transitive dependency: setuptools.package_index.PackageIndex.download() (vulnerable - path traversal)

CVE-2025-47273: Multiple vulnerabilities in transformers and setuptools packages.
- transformers: Issues in PreTrainedModel.to() and BatchFeature.to()
- setuptools: Path traversal vulnerability in PackageIndex.download() leading to Arbitrary File Write

Exploit Scenario:
- Attacker controls model path or configuration
- load_and_use_model() loads model using transformers
- transformers calls setuptools.PackageIndex.download() for package installation
- Vulnerable setuptools code allows path traversal, enabling arbitrary file write
- This demonstrates deep transitive reachability (first-party → direct → transitive → transitive)
"""

from huggingface_llm_test import load_and_use_model


def load_model(model_name: str, device: str = "cpu") -> object:
    """
    Load and use a model from huggingface-llm-test.
    
    This function calls load_and_use_model() which transitively calls vulnerable
    functions in transformers and setuptools.
    
    Call path:
    - huggingface_llm_test.load_and_use_model() (direct call)
    - transformers.modeling_utils.PreTrainedModel.to() (transitive - vulnerable)
    - transformers.feature_extraction_utils.BatchFeature.to() (transitive - vulnerable)
    - transformers.utils.import_utils.requires_backends() (transitive)
    - setuptools.package_index.PackageIndex.download() (transitive - CVE-2025-47273)
    - setuptools.package_index.PackageIndex._download_url() (transitive - vulnerable)
    
    Args:
        model_name: Name or path of model to load (could be attacker-controlled)
        device: Device to load model on (cpu/cuda)
    
    Returns:
        Loaded model object
    """
    # Direct call to vulnerable function in direct dependency
    # This transitively calls:
    # 1. transformers.PreTrainedModel.to() (CVE-2025-47273)
    # 2. transformers.BatchFeature.to() (CVE-2025-47273)
    # 3. setuptools.PackageIndex.download() (CVE-2025-47273 - path traversal)
    #
    # Payload: Malicious model_name could trigger path traversal in setuptools.download()
    # The vulnerable PackageIndex.download() allows arbitrary file write via path traversal
    model = load_and_use_model(model_name, device=device)
    return model


def process_with_model(model_name: str, input_data: str) -> str:
    """
    Process input data using a loaded model.
    
    This demonstrates another code path that reaches the vulnerable functions.
    
    Args:
        model_name: Model to load
        input_data: Input text to process
    
    Returns:
        Processed output
    """
    # This call triggers the full transitive chain:
    # load_and_use_model() → transformers.to() → setuptools.download()
    model = load_and_use_model(model_name)
    
    # Use the model (this may also trigger transformers BatchFeature.to())
    # The model loading process internally calls setuptools for package management
    # Vulnerable path: PackageIndex.download() with path traversal
    result = model.process(input_data) if hasattr(model, 'process') else "processed"
    return result


if __name__ == "__main__":
    """
    Entry point: This code is REACHABLE and will execute.
    
    Demonstrates deep transitive reachability:
    - First-party code → huggingface-llm-test (direct)
    - → transformers (transitive)
    - → setuptools (transitive of transitive)
    
    This shows how SCA tools need to stitch call graphs across multiple dependency layers.
    """
    
    # Example 1: Basic model loading
    # Payload: Attacker-controlled model_name could exploit setuptools path traversal
    # The vulnerable PackageIndex.download() processes the model path
    print("Loading model (this triggers transitive vulnerable calls)...")
    try:
        # This call reaches:
        # - huggingface_llm_test.load_and_use_model() (direct)
        # - transformers.PreTrainedModel.to() (transitive)
        # - setuptools.PackageIndex.download() (transitive of transitive - CVE-2025-47273)
        model = load_model("test-model", device="cpu")
        print(f"Model loaded: {type(model)}")
    except Exception as e:
        print(f"Model loading error (expected if model not available): {e}")
        print("Note: The vulnerable code paths are still reachable even if model fails to load")
    
    # Example 2: Processing with model
    # This also demonstrates the transitive call chain
    print("\nProcessing with model...")
    try:
        result = process_with_model("test-model", "sample input")
        print(f"Processing result: {result}")
    except Exception as e:
        print(f"Processing error: {e}")
    
    print("\nReachability demonstrated:")
    print("1. Direct: huggingface_llm_test.load_and_use_model()")
    print("2. Transitive: transformers.PreTrainedModel.to()")
    print("3. Deep transitive: setuptools.PackageIndex.download() (path traversal vulnerability)")

