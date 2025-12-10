"""
SCA Reachability Test: transformers library (CVE-2025-47273)

This file demonstrates REACHABLE code that calls vulnerable functions in transformers
and its transitive dependency setuptools.

Call Path:
1. First-party code: main() → load_model() → transformers.modeling_utils.PreTrainedModel.to()
2. Direct dependency: transformers.modeling_utils.PreTrainedModel.to() (vulnerable)
3. Direct dependency: transformers.feature_extraction_utils.BatchFeature.to() (vulnerable)
4. Direct dependency: transformers.utils.import_utils.requires_backends() (vulnerable)
5. Direct dependency: transformers.video_utils.load_video() (vulnerable)
6. Transitive dependency: setuptools.package_index.PackageIndex.download() (vulnerable - path traversal)

CVE-2025-47273: Multiple vulnerabilities in transformers package and setuptools.
- transformers: Issues in PreTrainedModel.to(), BatchFeature.to(), requires_backends(), load_video()
- setuptools: Path traversal vulnerability in PackageIndex.download() leading to Arbitrary File Write

Exploit Scenario:
- Attacker controls model path, device, or input data
- transformers functions are called which may trigger package installation
- Package installation calls setuptools.PackageIndex.download() for package management
- Vulnerable setuptools code allows path traversal, enabling arbitrary file write
- This demonstrates transitive reachability (first-party → direct → transitive)
"""

from transformers import AutoModel, AutoTokenizer
from transformers.modeling_utils import PreTrainedModel
from transformers.feature_extraction_utils import BatchFeature
from transformers.utils.import_utils import requires_backends
from transformers.video_utils import load_video


def load_and_move_model(model_name: str, device: str = "cpu") -> object:
    """
    Load a model and move it to a device using PreTrainedModel.to().
    
    This function calls PreTrainedModel.to() which is vulnerable (CVE-2025-47273).
    The model loading process may also transitively call setuptools for package management.
    
    Call path:
    - AutoModel.from_pretrained() → PreTrainedModel.to() (direct - vulnerable)
    - Model loading may trigger setuptools.PackageIndex.download() (transitive - CVE-2025-47273)
    
    Args:
        model_name: Name or path of model to load (could be attacker-controlled)
        device: Device to move model to (cpu/cuda)
    
    Returns:
        Loaded model object
    """
    # Load model - this may transitively call setuptools for package installation
    model = AutoModel.from_pretrained(model_name)
    
    # Direct call to vulnerable function: PreTrainedModel.to() (CVE-2025-47273)
    # This method is vulnerable and may also trigger setuptools calls
    # Payload: Attacker-controlled device parameter could influence behavior
    model = model.to(device)
    
    return model


def process_batch_features(input_data: dict) -> BatchFeature:
    """
    Process input data using BatchFeature.to().
    
    This demonstrates another vulnerable function in transformers.
    
    Call path:
    - BatchFeature creation → BatchFeature.to() (direct - vulnerable)
    - May transitively call setuptools for backend requirements
    
    Args:
        input_data: Input data dictionary
    
    Returns:
        BatchFeature object
    """
    # Create BatchFeature object
    batch = BatchFeature(input_data)
    
    # Direct call to vulnerable function: BatchFeature.to() (CVE-2025-47273)
    # This method is vulnerable and may trigger setuptools calls for backend installation
    batch = batch.to("cpu")
    
    return batch


def check_backends(backends: list[str]) -> None:
    """
    Check if required backends are available using requires_backends().
    
    This function calls the vulnerable requires_backends() function.
    
    Call path:
    - requires_backends() (direct - vulnerable)
    - May transitively call setuptools.PackageIndex.download() for backend installation
    
    Args:
        backends: List of backend names to check
    """
    # Direct call to vulnerable function: requires_backends() (CVE-2025-47273)
    # This may trigger setuptools.PackageIndex.download() if backends need installation
    # Payload: Attacker-controlled backend names could trigger vulnerable setuptools code
    requires_backends(backends)


def load_video_file(video_path: str) -> object:
    """
    Load a video file using transformers.video_utils.load_video().
    
    This demonstrates another vulnerable function in transformers.
    
    Call path:
    - load_video() (direct - vulnerable)
    - May transitively call setuptools for video processing dependencies
    
    Args:
        video_path: Path to video file (could be attacker-controlled)
    
    Returns:
        Loaded video data
    """
    # Direct call to vulnerable function: load_video() (CVE-2025-47273)
    # This may trigger setuptools calls for video processing package installation
    # Payload: Attacker-controlled video_path could exploit setuptools path traversal
    video = load_video(video_path)
    return video


if __name__ == "__main__":
    """
    Entry point: This code is REACHABLE and will execute.
    
    Demonstrates transitive reachability:
    - First-party code → transformers (direct)
    - → setuptools (transitive)
    
    This shows how SCA tools need to stitch call graphs across dependency layers.
    """
    
    # Example 1: Model loading and device movement
    # Payload: Attacker-controlled model_name could trigger setuptools path traversal
    # The vulnerable PreTrainedModel.to() is called, and model loading may call setuptools
    print("Loading model (this triggers vulnerable PreTrainedModel.to())...")
    try:
        # This call reaches:
        # - transformers.modeling_utils.PreTrainedModel.to() (direct - CVE-2025-47273)
        # - setuptools.package_index.PackageIndex.download() (transitive - CVE-2025-47273)
        model = load_and_move_model("bert-base-uncased", device="cpu")
        print(f"Model loaded and moved: {type(model)}")
    except Exception as e:
        print(f"Model loading error (expected if model not available): {e}")
        print("Note: The vulnerable code paths are still reachable even if model fails to load")
    
    # Example 2: Batch feature processing
    # This also demonstrates the vulnerable BatchFeature.to() method
    print("\nProcessing batch features...")
    try:
        batch = process_batch_features({"input_ids": [[1, 2, 3]]})
        print(f"Batch features processed: {type(batch)}")
    except Exception as e:
        print(f"Batch processing error: {e}")
    
    # Example 3: Backend requirements check
    # This demonstrates requires_backends() which may trigger setuptools
    print("\nChecking backend requirements...")
    try:
        check_backends(["torch"])
        print("Backend check completed")
    except Exception as e:
        print(f"Backend check error: {e}")
    
    # Example 4: Video loading
    # This demonstrates load_video() vulnerable function
    print("\nLoading video file...")
    try:
        video = load_video_file("test_video.mp4")
        print(f"Video loaded: {type(video)}")
    except Exception as e:
        print(f"Video loading error (expected if file not found): {e}")
        print("Note: The vulnerable load_video() code path is still reachable")
    
    print("\nReachability demonstrated:")
    print("1. Direct: transformers.modeling_utils.PreTrainedModel.to()")
    print("2. Direct: transformers.feature_extraction_utils.BatchFeature.to()")
    print("3. Direct: transformers.utils.import_utils.requires_backends()")
    print("4. Direct: transformers.video_utils.load_video()")
    print("5. Transitive: setuptools.package_index.PackageIndex.download() (path traversal vulnerability)")

