# preprocessing/__init__.py - FIXED
try:
    from .feature_engine import FeatureEngine
    from .normalizer import DataNormalizer
    __all__ = ['FeatureEngine', 'DataNormalizer']
except ImportError as e:
    print(f"Warning: Could not import preprocessing modules: {e}")
    __all__ = []