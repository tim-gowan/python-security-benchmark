# Unreachable Branch

## Purpose

This branch contains **only dead/unreachable code** designed to test **NOISE** (false positives) in SCA Reachability tools. No code in this branch should be flagged as reachable by proper reachability analysis tools.

## Contents

- `requirements.txt` - Python dependencies with known vulnerabilities
- `sca-reachability/*_dead.py` - Test files containing unreachable dead code

## Test Files

### `requests_dead.py`
Contains unreachable code with requests library calls:
- Functions defined but never called
- Code after `if False:` conditions
- Code after early returns (`if True: return`)
- Unused classes that are never instantiated
- Exception handlers that are never reached

### `transformers_dead.py`
Contains unreachable code with transformers library calls:
- Unused functions with vulnerable function calls
- Nested unreachable conditions
- Dead code in unused class methods
- Imported but unused functions

### `flask_dead.py`
Contains unreachable code with Flask calls:
- Unregistered/unused Flask routes (defined but never accessed)
- Dead code in unused route handlers
- Functions with unreachable code paths
- Unused classes with Flask method calls

## Dead Code Patterns

This branch demonstrates various patterns of dead code:
1. **Unused Functions**: Functions defined but never invoked
2. **Unreachable Conditions**: Code after `if False:` blocks
3. **Early Returns**: Code after unconditional returns
4. **Unused Classes**: Classes defined but never instantiated
5. **Unused Routes**: Framework routes registered but never accessed via HTTP
6. **Unreachable Exception Handlers**: Exception blocks that can never be reached

## Expected Behavior

A proper SCA Reachability tool should:
1. ✅ **NOT** flag any code in this branch as reachable
2. ✅ Perform static analysis to identify dead code
3. ✅ Understand control flow to detect unreachable paths
4. ✅ Recognize unused functions, classes, and routes
5. ✅ Avoid false positives from simple regex matching

## Testing

Tools that use simple pattern matching or regex searches may incorrectly flag code in this branch as reachable. Proper reachability analysis requires:
- Control flow analysis
- Dead code elimination
- Call graph construction
- Framework-aware analysis (understanding Flask routing)

## Quality Metrics

This branch helps measure:
- **False Positive Rate**: Tools should report 0% reachability for this branch
- **Precision**: High-quality tools won't flag dead code as reachable
- **Analysis Depth**: Tools that perform deep static analysis will correctly identify all code as unreachable
