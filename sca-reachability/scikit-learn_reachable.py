"""
SCA Reachability Test: scikit-learn library (CVE-2024-5206)

This file demonstrates REACHABLE code that calls the vulnerable function
CountVectorizer._limit_features() in scikit-learn.

Call Path:
1. First-party code: main() → process_text() → CountVectorizer.fit_transform()
2. Direct dependency: CountVectorizer.fit_transform() → CountVectorizer._limit_features()
3. Vulnerable function: _limit_features() has sensitive data leakage vulnerability

CVE-2024-5206: scikit-learn sensitive data leakage vulnerability in CountVectorizer._limit_features()

Exploit Scenario:
- Attacker provides malicious text input that gets processed by CountVectorizer
- The _limit_features() method may leak sensitive information during feature limiting
- Vulnerable code path is reached through normal CountVectorizer usage
"""

from sklearn.feature_extraction.text import CountVectorizer


def process_text(texts: list[str], max_features: int = 100) -> tuple:
    """
    Process text data using CountVectorizer.
    
    This function calls CountVectorizer.fit_transform() which internally calls
    the vulnerable _limit_features() method (CVE-2024-5206).
    
    Call path:
    - CountVectorizer.fit_transform() (direct call)
    - CountVectorizer._limit_features() (internal call - VULNERABLE)
    
    Args:
        texts: List of text strings to process (could be attacker-controlled)
        max_features: Maximum number of features to extract
    
    Returns:
        Tuple of (feature matrix, vectorizer object)
    """
    # Create vectorizer with max_features parameter
    # This will trigger _limit_features() internally when fitting
    vectorizer = CountVectorizer(max_features=max_features)
    
    # This call triggers the vulnerable _limit_features() method
    # Path: fit_transform() → _limit_features() (CVE-2024-5206)
    X = vectorizer.fit_transform(texts)
    
    return X, vectorizer


def extract_features_from_documents(documents: list[str]) -> dict:
    """
    Extract features from documents using CountVectorizer.
    
    This demonstrates another code path that reaches _limit_features().
    
    Args:
        documents: List of document strings
    
    Returns:
        Dictionary with feature matrix and vocabulary
    """
    # Direct call that will reach vulnerable _limit_features()
    vectorizer = CountVectorizer(max_features=50, ngram_range=(1, 2))
    
    # This triggers: fit_transform() → _limit_features() (vulnerable)
    # Payload: Attacker-controlled documents could exploit data leakage
    feature_matrix = vectorizer.fit_transform(documents)
    
    return {
        "features": feature_matrix,
        "vocabulary": vectorizer.vocabulary_
    }


if __name__ == "__main__":
    # Entry point: This code is REACHABLE and will execute
    # Demonstrates reachability to vulnerable _limit_features() method
    
    # Example 1: Basic text processing
    # Payload: Attacker could provide malicious text to trigger data leakage
    sample_texts = [
        "This is a sample document",
        "Another document with different words",
        "Third document for feature extraction"
    ]
    
    X, vectorizer = process_text(sample_texts, max_features=10)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Vocabulary size: {len(vectorizer.vocabulary_)}")
    
    # Example 2: Document feature extraction
    # This also reaches the vulnerable _limit_features() method
    documents = [
        "Machine learning is fascinating",
        "Natural language processing uses text analysis",
        "Feature extraction is important for ML models"
    ]
    
    result = extract_features_from_documents(documents)
    print(f"Extracted features from {len(documents)} documents")

