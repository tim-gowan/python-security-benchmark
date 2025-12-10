# Reachable Branch

## Purpose

This branch contains **only reachable code** designed to test **SIGNAL** (true positives) in SCA Reachability tools. All code in this branch should be flagged as reachable by proper reachability analysis tools.

## Contents

- `requirements.txt` - Python dependencies with known vulnerabilities
- `sca-reachability/*_reachable.py` - Test files demonstrating reachable vulnerable code paths

## Test Files

### `requests_reachable.py`
Demonstrates reachable calls to vulnerable functions in the requests library:
- Direct calls: `requests.get()`, `requests.Session().get()`
- Transitive calls: urllib3, idna, werkzeug (CVE-2023-32681, CVE-2024-35195)
- Entry point: `if __name__ == "__main__"` block executes all vulnerable paths

### `transformers_reachable.py`
Demonstrates reachable calls to vulnerable transformers functions:
- Direct calls: `PreTrainedModel.to()`, `BatchFeature.to()`, `requires_backends()`, `load_video()`
- Transitive calls: setuptools.PackageIndex.download() (CVE-2025-47273)
- Entry point: `if __name__ == "__main__"` block executes all vulnerable paths

### `flask_reachable.py`
Demonstrates reachable calls through Flask's routing system:
- Direct calls: `send_static_file()`, `send_from_directory()`
- Transitive calls: werkzeug.utils.send_from_directory(), werkzeug.security.safe_join() (CVE-2025-66221)
- Entry points: Both direct function calls and HTTP request routing (inversion of control)

## Expected Behavior

A proper SCA Reachability tool should:
1. ✅ Identify all vulnerable functions as **reachable**
2. ✅ Trace call paths from entry points to vulnerable code
3. ✅ Follow transitive dependency chains
4. ✅ Understand framework routing (Flask HTTP requests → views)
5. ✅ Report all CVEs associated with reachable code paths

## Testing

Run each test file to verify the code is actually executable:
```bash
python sca-reachability/requests_reachable.py
python sca-reachability/transformers_reachable.py
python sca-reachability/flask_reachable.py
```

Note: Some tests may fail due to missing dependencies or network issues, but the vulnerable code paths are still reachable even if execution fails.

