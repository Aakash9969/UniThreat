"""Feature extraction package."""
from src.features.schema import (  # noqa: F401
    BENIGN,
    CANONICAL_FEATURES,
    category_for,
    canonical_column_map,
    find_label_column,
    is_threat_label,
    normalize_label,
    severity_for,
)
