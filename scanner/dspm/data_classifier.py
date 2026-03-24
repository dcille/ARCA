"""DSPM content-based data classification module.

Classifies cloud resources based on their content (PII scan results),
existing cloud tags, and configurable classification rules. Detects
misclassifications where the tagged level does not match what the
content analysis reveals.

Classification levels (lowest to highest):
    public < internal < confidential < restricted
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
# Classification levels — ordered from lowest to highest sensitivity
# ═══════════════════════════════════════════════════════════════════════

CLASSIFICATION_LEVELS = ("public", "internal", "confidential", "restricted")

_LEVEL_ORDER = {level: idx for idx, level in enumerate(CLASSIFICATION_LEVELS)}

# ═══════════════════════════════════════════════════════════════════════
# PII type → category mapping (used by classification rules)
# ═══════════════════════════════════════════════════════════════════════

PII_CATEGORY_MAP = {
    # Financial / PCI
    "credit_card": "financial",
    "iban": "financial",
    "nss": "financial",
    "bank_account": "financial",
    # Personal ID / Government
    "dni": "personal_id",
    "nie": "personal_id",
    "nif": "personal_id",
    "passport": "government",
    "driver_license": "government",
    # Health
    "health_data": "health",
    "medical_record": "health",
    "health_insurance": "health",
    # Contact
    "email": "contact",
    "phone": "contact",
    "address": "contact",
}

# ═══════════════════════════════════════════════════════════════════════
# Classification rules — evaluated in order; first match wins
# ═══════════════════════════════════════════════════════════════════════

CLASSIFICATION_RULES = [
    {"pii_categories": ["financial"], "min_matches": 1, "level": "restricted", "confidence": 0.95},
    {"pii_categories": ["personal_id", "government"], "min_matches": 1, "level": "confidential", "confidence": 0.9},
    {"pii_categories": ["health"], "min_matches": 1, "level": "restricted", "confidence": 0.95},
    {"pii_categories": ["contact"], "min_matches": 5, "level": "internal", "confidence": 0.7},
    {"pii_categories": ["contact"], "min_matches": 1, "level": "internal", "confidence": 0.5},
]

# ═══════════════════════════════════════════════════════════════════════
# Tag conventions per cloud provider
# ═══════════════════════════════════════════════════════════════════════

TAG_MAPPING = {
    "aws": {
        "key": "DataClassification",
        "values": {
            "public": "Public",
            "internal": "Internal",
            "confidential": "Confidential",
            "restricted": "Restricted",
        },
    },
    "azure": {
        "key": "data-classification",
        "values": {
            "public": "public",
            "internal": "internal",
            "confidential": "confidential",
            "restricted": "restricted",
        },
    },
    "gcp": {
        "key": "data-classification",
        "values": {
            "public": "public",
            "internal": "internal",
            "confidential": "confidential",
            "restricted": "restricted",
        },
    },
    "oci": {
        "key": "DataClassification",
        "values": {
            "public": "Public",
            "internal": "Internal",
            "confidential": "Confidential",
            "restricted": "Restricted",
        },
    },
    "alibaba": {
        "key": "DataClassification",
        "values": {
            "public": "Public",
            "internal": "Internal",
            "confidential": "Confidential",
            "restricted": "Restricted",
        },
    },
}

# ═══════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class ClassificationResult:
    """Result of classifying a single cloud resource."""

    resource_id: str
    resource_name: str
    provider: str
    current_tag_classification: Optional[str]  # from existing cloud tags
    content_classification: str  # determined by content analysis
    confidence: float  # 0.0 – 1.0
    pii_types_found: list = field(default_factory=list)
    has_pci_data: bool = False
    has_health_data: bool = False
    has_financial_data: bool = False
    recommendation: str = ""  # suggested tag if mismatch detected
    is_misclassified: bool = False  # tag says 'public' but content is 'restricted', etc.
    risk_score: float = 0.0  # 0 – 100


# ═══════════════════════════════════════════════════════════════════════
# Classifier
# ═══════════════════════════════════════════════════════════════════════


class DataClassifier:
    """Content-based data classifier for cloud resources.

    Uses PII scan results and/or existing cloud tags to determine the
    appropriate classification level for a resource and detect
    misclassifications.
    """

    def __init__(self, pii_scanner=None):
        """Initialise the classifier.

        Args:
            pii_scanner: An optional PIIScanner instance that can be used
                         to scan content before classification.
        """
        self.pii_scanner = pii_scanner

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _categorise_pii_types(pii_types: list) -> dict:
        """Map a list of PII type strings to their categories with counts.

        Returns:
            dict mapping category name to the count of matching PII types.
        """
        counts: dict = {}
        for pii_type in pii_types:
            category = PII_CATEGORY_MAP.get(pii_type)
            if category:
                counts[category] = counts.get(category, 0) + 1
        return counts

    @staticmethod
    def _level_value(level: str) -> int:
        """Return the numeric order of a classification level (higher = more sensitive)."""
        return _LEVEL_ORDER.get(level, -1)

    @staticmethod
    def _compute_risk_score(
        classification: str,
        is_misclassified: bool,
        pii_types_found: list,
        has_pci_data: bool,
        has_health_data: bool,
    ) -> float:
        """Compute a 0-100 risk score for a classification result."""
        base_scores = {
            "public": 0.0,
            "internal": 20.0,
            "confidential": 50.0,
            "restricted": 80.0,
        }
        score = base_scores.get(classification, 0.0)

        # Bump for volume of PII types found
        score += min(len(pii_types_found) * 2.0, 10.0)

        # Extra weight for PCI and health data
        if has_pci_data:
            score += 5.0
        if has_health_data:
            score += 5.0

        # Major bump if the resource is misclassified (under-tagged)
        if is_misclassified:
            score += 15.0

        return min(score, 100.0)

    # ── main classification methods ───────────────────────────────────

    def classify_from_pii_results(
        self,
        pii_results: list,
        resource_id: str = "",
        resource_name: str = "",
        provider: str = "",
        current_tag: Optional[str] = None,
    ) -> ClassificationResult:
        """Classify a resource based on PII scan results.

        Args:
            pii_results: List of PII type strings found in the resource
                         (e.g. ``['credit_card', 'email', 'dni']``).
            resource_id: Cloud resource identifier.
            resource_name: Human-readable resource name.
            provider: Cloud provider (aws, azure, gcp, oci, alibaba).
            current_tag: The existing classification tag value (if any).

        Returns:
            A :class:`ClassificationResult` with the determined level.
        """
        pii_types = list(pii_results)
        category_counts = self._categorise_pii_types(pii_types)

        # Determine flags
        has_pci = category_counts.get("financial", 0) > 0
        has_health = category_counts.get("health", 0) > 0
        has_financial = has_pci  # financial category covers PCI

        # Walk through rules in priority order
        classification = "public"
        confidence = 1.0  # default confidence for "public" (no PII)

        for rule in CLASSIFICATION_RULES:
            matching_count = sum(
                category_counts.get(cat, 0) for cat in rule["pii_categories"]
            )
            if matching_count >= rule["min_matches"]:
                # Only upgrade, never downgrade
                if self._level_value(rule["level"]) > self._level_value(classification):
                    classification = rule["level"]
                    confidence = rule["confidence"]

        # Detect misclassification
        tag_lower = current_tag.lower().strip() if current_tag else None
        is_misclassified = False
        recommendation = ""
        if tag_lower:
            is_misclassified, explanation = self.detect_misclassification(
                tag_lower, classification
            )
            if is_misclassified:
                recommendation = (
                    f"Update tag to '{classification}'. {explanation}"
                )
        else:
            recommendation = f"Add classification tag: '{classification}'"

        risk_score = self._compute_risk_score(
            classification, is_misclassified, pii_types, has_pci, has_health
        )

        logger.debug(
            "Classified resource %s as '%s' (confidence=%.2f, risk=%.1f)",
            resource_id or resource_name or "<unknown>",
            classification,
            confidence,
            risk_score,
        )

        return ClassificationResult(
            resource_id=resource_id,
            resource_name=resource_name,
            provider=provider,
            current_tag_classification=current_tag,
            content_classification=classification,
            confidence=confidence,
            pii_types_found=pii_types,
            has_pci_data=has_pci,
            has_health_data=has_health,
            has_financial_data=has_financial,
            recommendation=recommendation,
            is_misclassified=is_misclassified,
            risk_score=risk_score,
        )

    def classify_by_tags(
        self,
        tags: dict,
        resource_id: str = "",
        provider: str = "",
    ) -> ClassificationResult:
        """Classify a resource based on its existing cloud resource tags.

        Looks for a known classification tag key for the given provider
        (or scans all known keys) and returns the level indicated by the
        tag value.

        Args:
            tags: Dictionary of tag key/value pairs from the cloud resource.
            resource_id: Cloud resource identifier.
            provider: Cloud provider name.

        Returns:
            A :class:`ClassificationResult` derived from the tags.
        """
        detected_level = None
        tag_key_found = None

        # Determine which tag keys to look for
        if provider and provider in TAG_MAPPING:
            search_keys = {TAG_MAPPING[provider]["key"]}
        else:
            search_keys = {m["key"] for m in TAG_MAPPING.values()}

        # Normalise tag keys for case-insensitive lookup
        normalised = {k.lower(): (k, v) for k, v in tags.items()}

        for search_key in search_keys:
            entry = normalised.get(search_key.lower())
            if entry:
                tag_key_found = entry[0]
                raw_value = entry[1].lower().strip()
                if raw_value in _LEVEL_ORDER:
                    detected_level = raw_value
                break

        classification = detected_level or "public"
        confidence = 0.8 if detected_level else 0.1

        recommendation = ""
        if not tag_key_found:
            recommendation = "No classification tag found; add one based on content analysis."

        return ClassificationResult(
            resource_id=resource_id,
            resource_name="",
            provider=provider,
            current_tag_classification=detected_level,
            content_classification=classification,
            confidence=confidence,
            pii_types_found=[],
            has_pci_data=False,
            has_health_data=False,
            has_financial_data=False,
            recommendation=recommendation,
            is_misclassified=False,
            risk_score=0.0,
        )

    # ── misclassification detection ───────────────────────────────────

    @staticmethod
    def detect_misclassification(
        tag_classification: str,
        content_classification: str,
    ) -> tuple:
        """Detect whether a resource is misclassified.

        A resource is considered misclassified when its tagged level is
        *lower* than what the content analysis determined.

        Args:
            tag_classification: The classification level from the tag.
            content_classification: The classification level from content
                                   analysis.

        Returns:
            Tuple of ``(is_misclassified: bool, explanation: str)``.
        """
        tag_val = _LEVEL_ORDER.get(tag_classification.lower().strip(), -1)
        content_val = _LEVEL_ORDER.get(content_classification.lower().strip(), -1)

        if tag_val < content_val:
            explanation = (
                f"Resource is tagged as '{tag_classification}' but content "
                f"analysis indicates '{content_classification}'. The tag "
                f"under-represents the actual sensitivity of the data."
            )
            return (True, explanation)

        if tag_val > content_val:
            explanation = (
                f"Resource is tagged as '{tag_classification}' but content "
                f"analysis indicates '{content_classification}'. The tag may "
                f"be over-classified (not a security risk, but may restrict "
                f"access unnecessarily)."
            )
            return (False, explanation)

        return (False, "Tag classification matches content analysis.")

    # ── tag recommendation ────────────────────────────────────────────

    @staticmethod
    def generate_tag_recommendation(classification: str, provider: str) -> dict:
        """Generate the recommended tag key/value pair for a cloud provider.

        Args:
            classification: The classification level to tag with.
            provider: Cloud provider name (aws, azure, gcp, oci, alibaba).

        Returns:
            Dict with ``key`` and ``value`` entries, e.g.
            ``{"key": "DataClassification", "value": "Restricted"}``.
            Returns a generic recommendation if the provider is unknown.
        """
        level = classification.lower().strip()
        mapping = TAG_MAPPING.get(provider)

        if mapping:
            value = mapping["values"].get(level, classification.capitalize())
            return {"key": mapping["key"], "value": value}

        # Fallback for unknown providers
        return {"key": "DataClassification", "value": classification.capitalize()}

    # ── bulk classification ───────────────────────────────────────────

    def bulk_classify(self, items: list) -> list:
        """Classify multiple items in one call.

        Each item is a dict with at least a ``pii_results`` key (list of
        PII type strings). Optional keys: ``resource_id``,
        ``resource_name``, ``provider``, ``current_tag``.

        Args:
            items: List of dicts describing resources to classify.

        Returns:
            List of :class:`ClassificationResult` objects.
        """
        results = []
        for item in items:
            try:
                result = self.classify_from_pii_results(
                    pii_results=item.get("pii_results", []),
                    resource_id=item.get("resource_id", ""),
                    resource_name=item.get("resource_name", ""),
                    provider=item.get("provider", ""),
                    current_tag=item.get("current_tag"),
                )
                results.append(result)
            except Exception:
                logger.exception(
                    "Failed to classify item %s",
                    item.get("resource_id", "<unknown>"),
                )
        return results
