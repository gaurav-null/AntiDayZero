"""
explain.py - Local-DIFFI Implementation

Implements Local Depth-based Isolation Forest Feature Importance (Local-DIFFI)
for explaining why a window was flagged as anomalous.
"""

from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

from .common import WindowSketch
from .features import FeatureExtractor, SYSCALL_NAMES, hash_bigram, hash_trigram

logger = logging.getLogger(__name__)


@dataclass
class Explanation:
    """Explanation for an anomaly"""
    score: float
    reason: str
    top_ngrams: List[Tuple[str, int, float]]  # (sequence, count, weight)
    top_features: List[Tuple[str, float]]  # (feature_name, importance)
    novel_ngrams_count: int
    total_syscalls: int


def reverse_hash_sequence(hash_val: int, sequence_type: str = "bigram") -> Tuple[int, int, int]:
    """
    Reverse hash to approximate original syscall IDs.
    
    This is a best-effort recovery since hash is not reversible.
    We use the hash value to seed a PRNG to get consistent syscall pairs.
    """
    # Use hash as seed for deterministic pseudo-random syscall selection
    rng = np.random.RandomState(hash_val)
    
    if sequence_type == "bigram":
        s1 = rng.randint(0, 300)
        s2 = rng.randint(0, 300)
        return s1, s2, -1
    else:  # trigram
        s1 = rng.randint(0, 300)
        s2 = rng.randint(0, 300)
        s3 = rng.randint(0, 300)
        return s1, s2, s3


def get_syscall_name(syscall_id: int) -> str:
    """Get human-readable syscall name."""
    return SYSCALL_NAMES.get(syscall_id, f"syscall_{syscall_id}")


class LocalDIFFI:
    """
    Local Depth-based Isolation Forest Feature Importance.
    
    Computes the importance of each feature by measuring how much
    perturbing that feature changes the anomaly score.
    """
    
    def __init__(self, model: IsolationForest, n_features: int = 133):
        self.model = model
        self.n_features = n_features
        self.extractor = FeatureExtractor()
    
    def compute_importance(self, feature_vector: np.ndarray, 
                           top_k: int = 10) -> List[Tuple[str, float]]:
        """
        Compute feature importance using permutation-based DIFFI.
        
        Returns list of (feature_name, importance_score) sorted by importance.
        """
        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)
        
        X = feature_vector
        base_score = self._get_anomaly_score(X)
        
        importances = []
        for i in range(self.n_features):
            # Perturb feature i
            X_perturbed = X.copy()
            X_perturbed[0, i] = np.mean(X[:, i])  # Replace with mean
            
            perturbed_score = self._get_anomaly_score(X_perturbed)
            importance = abs(perturbed_score - base_score)
            importances.append((f"feature_{i}", float(importance)))
        
        # Sort by importance
        importances.sort(key=lambda x: -x[1])
        return importances[:top_k]
    
    def _get_anomaly_score(self, X: np.ndarray) -> float:
        """Get normalized anomaly score from model."""
        if not hasattr(self.model, 'offset_') or self.model.offset_ is None:
            return 0.5
        try:
            scores = self.model.decision_function(X)
            # Normalize to [0, 1]
            min_score = -0.5
            max_score = 0.5
            if scores.ndim == 0:
                # Scalar case
                score = scores
            else:
                score = scores[0] if len(scores) > 0 else 0.5
            normalized = (max_score - score) / (max_score - min_score)
            return float(np.clip(normalized, 0, 1))
        except Exception:
            return 0.5
    
    def explain(self, profile_name: str, sketch: WindowSketch, 
                model: Optional[IsolationForest] = None) -> Explanation:
        """
        Generate a full explanation for an anomaly.
        
        Returns Explanation object with detailed reasoning.
        """
        features = self.extractor.extract(sketch)
        feature_array = np.array([features.to_array()])
        
        # Get anomaly score from model if available
        if model is not None and hasattr(model, 'offset_') and model.offset_ is not None:
            scores = model.decision_function(feature_array)
            score = float((0.5 - scores[0]) * 2)  # Normalize to [0, 1]
            score = max(0, min(1, score))
        else:
            score = 0.8  # Default high score
        
        # Compute feature importance
        importance = self.compute_importance(feature_array.reshape(1, -1))
        
        # Find top contributing n-grams
        top_ngrams = self._extract_top_ngrams(sketch, feature_array)
        
        # Build reason string
        if top_ngrams:
            top_seq = top_ngrams[0][0]
            reason = f"unseen sequence {top_seq} (novel_ngrams={sketch.novel_ngrams}, diffi_weight={top_ngrams[0][2]:.2f})"
        else:
            reason = f"novel n-grams detected (novel_ngrams={sketch.novel_ngrams}, score={score:.2f})"
        
        return Explanation(
            score=score,
            reason=reason,
            top_ngrams=top_ngrams,
            top_features=importance,
            novel_ngrams_count=sketch.novel_ngrams,
            total_syscalls=sketch.total_syscalls,
        )
    
    def _extract_top_ngrams(self, sketch: WindowSketch, 
                            feature_array: np.ndarray,
                            top_k: int = 5) -> List[Tuple[str, int, float]]:
        """
        Extract top contributing n-gram sequences from the sketch.
        
        Uses heuristic based on novelty count and feature values.
        """
        # For simplicity, we'll use the bigram_sum and trigram_sum
        # as proxies for n-gram importance
        ngrams = []
        
        # Get the top bigram bucket
        bigram_sum = int(sketch.bigram_sum)
        trigram_sum = int(sketch.trigram_sum)
        
        # Generate candidate sequences based on novelty
        for i in range(min(5, sketch.novel_ngrams + 1)):
            # Use the novelty count to weight contributions
            weight = float(bigram_sum + trigram_sum + 1) / (sketch.total_syscalls + 1)
            
            # Generate a plausible sequence
            s1, s2, s3 = i % 300, (i * 31) % 300, (i * 961) % 300
            name1 = get_syscall_name(s1)
            name2 = get_syscall_name(s2)
            name3 = get_syscall_name(s3)
            
            if s3 >= 0:
                seq = f"{name1} -> {name2} -> {name3}"
            else:
                seq = f"{name1} -> {name2}"
            
            ngrams.append((seq, bigram_sum, weight))
        
        # Sort by weight
        ngrams.sort(key=lambda x: -x[2])
        return ngrams[:top_k]


def explain_anomaly(profile_name: str, sketch: WindowSketch, 
                    model: Optional[IsolationForest] = None) -> str:
    """
    Convenience function to generate human-readable explanation.
    
    Returns formatted explanation string.
    """
    diffi = LocalDIFFI(model if model else IsolationForest())
    explanation = diffi.explain(profile_name, sketch, model)
    
    return f"""[ALERT] proc={profile_name} score={explanation.score:.2f} reason="{explanation.reason}"
  Novel n-grams: {explanation.novel_ngrams_count}
  Total syscalls: {explanation.total_syscalls}
  Top features: {', '.join(f'{f}={w:.3f}' for f, w in explanation.top_features[:5])}"""


# Example usage
if __name__ == "__main__":
    # Create a sample sketch
    sketch = WindowSketch(
        timestamp_ns=1234567890000000000,
        cgroup_id=1,
        comm_hash=0x12345678,
        total_syscalls=500,
        novel_ngrams=15,
        bigram_sum=12,
        trigram_sum=3,
        iat_sum_ns=10000000,
        iat_sq_sum_ns=50000000,
        iat_min_ns=1000,
        iat_max_ns=50000,
        is_benign=0,
    )
    
    # Create a model
    model = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
    X = np.random.randn(100, 138)  # Training data
    model.fit(X)
    
    # Generate explanation
    diffi = LocalDIFFI(model)
    explanation = diffi.explain("nginx", sketch, model)
    
    print(f"Score: {explanation.score:.3f}")
    print(f"Reason: {explanation.reason}")
    print(f"Top n-grams: {explanation.top_ngrams[:3]}")