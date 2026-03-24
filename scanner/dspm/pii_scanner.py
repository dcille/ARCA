"""DSPM PII Detection Engine - Comprehensive PII scanner for data classification.

Detects Personally Identifiable Information (PII) across text, files, and
structured data. Focused on Spanish/European identifiers with international
coverage for GDPR compliance.

Supported PII categories:
- Spanish identifiers: DNI, NIE, NIF empresa, NSS, pasaporte
- Financial: credit cards (Luhn-validated), IBAN, SWIFT/BIC
- Contact: email, Spanish phone numbers
- International: US SSN, UK NINO, German ID, French NIR, Italian CF,
  Portuguese NIF, IP addresses, dates of birth

All matches are redacted by default to prevent secondary data exposure.
"""

import logging
import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Callable

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# HELPER / VALIDATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def luhn_validate(number: str) -> bool:
    """Validate a number string using the Luhn algorithm (ISO/IEC 7812-1).

    Args:
        number: Digit-only string to validate.

    Returns:
        True if the number passes the Luhn check.
    """
    digits = re.sub(r"\D", "", number)
    if not digits or len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def dni_validate(dni: str) -> bool:
    """Validate a Spanish DNI number (8 digits + control letter).

    The letter is computed as ``number % 23`` mapped to a fixed alphabet.

    Args:
        dni: String matching the pattern ``\\d{8}[A-Z]``.

    Returns:
        True if the control letter is correct.
    """
    dni = dni.strip().upper()
    match = re.fullmatch(r"(\d{8})([A-Z])", dni)
    if not match:
        return False
    num, letter = match.groups()
    return _DNI_LETTERS[int(num) % 23] == letter


def nie_validate(nie: str) -> bool:
    """Validate a Spanish NIE (Numero de Identidad de Extranjero).

    The initial letter (X, Y, Z) is replaced by 0, 1, or 2 respectively,
    then the same DNI letter algorithm is applied.

    Args:
        nie: String matching the pattern ``[XYZ]\\d{7}[A-Z]``.

    Returns:
        True if the control letter is correct.
    """
    nie = nie.strip().upper()
    match = re.fullmatch(r"([XYZ])(\d{7})([A-Z])", nie)
    if not match:
        return False
    prefix, digits, letter = match.groups()
    prefix_map = {"X": "0", "Y": "1", "Z": "2"}
    full_number = prefix_map[prefix] + digits
    return _DNI_LETTERS[int(full_number) % 23] == letter


def iban_validate(iban: str) -> bool:
    """Basic IBAN validation: length check and mod-97 verification (ISO 13616).

    Args:
        iban: IBAN string, optionally containing spaces.

    Returns:
        True if the IBAN passes structural and check-digit validation.
    """
    iban = re.sub(r"\s", "", iban).upper()
    if len(iban) < 15 or len(iban) > 34:
        return False
    # Spanish IBANs must be exactly 24 characters
    if iban.startswith("ES") and len(iban) != 24:
        return False
    # Move first 4 chars to end and convert letters to numbers (A=10..Z=35)
    rearranged = iban[4:] + iban[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def redact_match(match: str) -> str:
    """Redact a PII match, showing only the first 2 and last 2 characters.

    Examples:
        >>> redact_match("12345678Z")
        '12*****8Z'
        >>> redact_match("AB")
        '**'

    Args:
        match: The raw matched string.

    Returns:
        Redacted string with middle characters replaced by asterisks.
    """
    if len(match) <= 4:
        return "*" * len(match)
    return match[:2] + "*" * (len(match) - 4) + match[-2:]


# ═══════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PIIPattern:
    """Definition of a single PII detection pattern.

    Attributes:
        pattern_id: Unique identifier for the pattern (e.g. ``pii_es_dni``).
        name: Human-readable name (e.g. ``DNI espanol``).
        regex: Compiled regular expression for detection.
        category: Broad category — one of ``personal_id``, ``financial``,
            ``contact``, ``health``, ``government``.
        gdpr_category: GDPR Art. 4 data category (e.g. ``identification``,
            ``financial``, ``contact``, ``online_identifier``, ``health``).
        severity: Risk severity — ``critical``, ``high``, ``medium``, or ``low``.
        validator: Optional callable for secondary validation (e.g. Luhn).
            Receives the matched string and returns True if valid.
    """
    pattern_id: str
    name: str
    regex: "re.Pattern[str]"
    category: str          # personal_id | financial | contact | health | government
    gdpr_category: str     # GDPR Art. 4 categories
    severity: str          # critical | high | medium | low
    validator: Optional[Callable[[str], bool]] = None


@dataclass
class PIIScanResult:
    """Result of scanning for a single PII pattern.

    Attributes:
        pattern_id: Which pattern produced this result.
        pattern_name: Human-readable pattern name.
        category: PII category (personal_id, financial, etc.).
        severity: Severity level of the finding.
        match_count: Total number of matches found.
        sample_matches: Up to 5 redacted sample matches.
        locations: Line numbers (1-based) or byte offsets of matches.
        confidence: ``high`` if a validator confirmed the match, ``medium``
            if no validator exists, ``low`` if the validator rejected it.
    """
    pattern_id: str
    pattern_name: str
    category: str
    severity: str
    match_count: int = 0
    sample_matches: list[str] = field(default_factory=list)
    locations: list[int] = field(default_factory=list)
    confidence: str = "medium"  # high | medium | low


# ═══════════════════════════════════════════════════════════════════════════
# DEFAULT PII PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_PATTERNS: list[PIIPattern] = [
    # ── Spanish / European identifiers ─────────────────────────────────
    PIIPattern(
        pattern_id="pii_es_dni",
        name="DNI espanol",
        regex=re.compile(r"\b\d{8}[A-HJ-NP-TV-Z]\b"),
        category="personal_id",
        gdpr_category="identification",
        severity="critical",
        validator=dni_validate,
    ),
    PIIPattern(
        pattern_id="pii_es_nie",
        name="NIE",
        regex=re.compile(r"\b[XYZ]\d{7}[A-Z]\b"),
        category="personal_id",
        gdpr_category="identification",
        severity="critical",
        validator=nie_validate,
    ),
    PIIPattern(
        pattern_id="pii_es_nif_empresa",
        name="NIF empresa",
        regex=re.compile(r"\b[A-HJNP-SUVW]\d{7}[0-9A-J]\b"),
        category="personal_id",
        gdpr_category="identification",
        severity="high",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_credit_card",
        name="Tarjeta de credito",
        regex=re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}"
            r"|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}"
            r"|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        category="financial",
        gdpr_category="financial",
        severity="critical",
        validator=luhn_validate,
    ),
    PIIPattern(
        pattern_id="pii_es_iban",
        name="IBAN espanol",
        regex=re.compile(r"\bES\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{2}[ ]?\d{10}\b"),
        category="financial",
        gdpr_category="financial",
        severity="critical",
        validator=iban_validate,
    ),
    PIIPattern(
        pattern_id="pii_es_phone",
        name="Telefono espanol",
        regex=re.compile(r"\b(?:\+34|0034)?[ -]?[6789]\d{2}[ -]?\d{3}[ -]?\d{3}\b"),
        category="contact",
        gdpr_category="contact",
        severity="medium",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_email",
        name="Email",
        regex=re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        category="contact",
        gdpr_category="contact",
        severity="medium",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_swift_bic",
        name="SWIFT/BIC",
        regex=re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b"),
        category="financial",
        gdpr_category="financial",
        severity="high",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_es_nss",
        name="NSS (Numero Seguridad Social)",
        regex=re.compile(r"\b\d{2}/\d{8}/\d{2}\b"),
        category="government",
        gdpr_category="identification",
        severity="critical",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_es_passport",
        name="Pasaporte espanol",
        regex=re.compile(r"\b[A-Z]{2}\d{6}\b"),
        category="personal_id",
        gdpr_category="identification",
        severity="high",
        validator=None,
    ),

    # ── International patterns ─────────────────────────────────────────
    PIIPattern(
        pattern_id="pii_us_ssn",
        name="US Social Security Number",
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        category="government",
        gdpr_category="identification",
        severity="critical",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_uk_nino",
        name="UK National Insurance Number",
        regex=re.compile(
            r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b"
        ),
        category="government",
        gdpr_category="identification",
        severity="critical",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_de_id",
        name="German ID Number (Personalausweis)",
        regex=re.compile(r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\d\b"),
        category="personal_id",
        gdpr_category="identification",
        severity="high",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_fr_nir",
        name="French NIR (Numero de Securite Sociale)",
        regex=re.compile(r"\b[12]\d{2}(?:0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b"),
        category="government",
        gdpr_category="identification",
        severity="critical",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_it_cf",
        name="Italian Codice Fiscale",
        regex=re.compile(
            r"\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b"
        ),
        category="personal_id",
        gdpr_category="identification",
        severity="critical",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_pt_nif",
        name="Portuguese NIF",
        regex=re.compile(r"\b[12356789]\d{8}\b"),
        category="personal_id",
        gdpr_category="identification",
        severity="high",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_ip_address",
        name="IP Address (v4)",
        regex=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        category="contact",
        gdpr_category="online_identifier",
        severity="low",
        validator=None,
    ),
    PIIPattern(
        pattern_id="pii_dob",
        name="Date of Birth",
        regex=re.compile(
            r"\b(?:"
            # DD/MM/YYYY or DD-MM-YYYY (European)
            r"(?:0[1-9]|[12]\d|3[01])[/\-](?:0[1-9]|1[0-2])[/\-](?:19|20)\d{2}"
            r"|"
            # YYYY-MM-DD (ISO 8601)
            r"(?:19|20)\d{2}[/\-](?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])"
            r")\b"
        ),
        category="personal_id",
        gdpr_category="identification",
        severity="medium",
        validator=None,
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# PII SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════════

class PIIScanner:
    """Comprehensive PII detection engine for DSPM data classification.

    Scans text, file content, and structured data for PII patterns, returning
    redacted results with confidence levels based on optional validators.

    Usage::

        scanner = PIIScanner()
        results = scanner.scan_text("Mi DNI es 12345678Z")
        for r in results:
            print(f"{r.pattern_name}: {r.match_count} matches ({r.confidence})")

    Args:
        patterns: Override the default pattern list. If ``None``, uses
            ``DEFAULT_PATTERNS``.
        custom_patterns: Additional patterns as dicts with keys matching
            :class:`PIIPattern` fields. The ``regex`` value should be a
            string that will be compiled automatically.
    """

    MAX_SAMPLES = 5  # Maximum redacted samples per pattern

    def __init__(
        self,
        patterns: Optional[list[PIIPattern]] = None,
        custom_patterns: Optional[list[dict]] = None,
    ) -> None:
        self._patterns: list[PIIPattern] = list(patterns or DEFAULT_PATTERNS)

        if custom_patterns:
            for cp in custom_patterns:
                regex_value = cp.get("regex", "")
                compiled = (
                    regex_value
                    if isinstance(regex_value, re.Pattern)
                    else re.compile(regex_value)
                )
                pattern = PIIPattern(
                    pattern_id=cp["pattern_id"],
                    name=cp["name"],
                    regex=compiled,
                    category=cp.get("category", "personal_id"),
                    gdpr_category=cp.get("gdpr_category", "identification"),
                    severity=cp.get("severity", "medium"),
                    validator=cp.get("validator"),
                )
                self._patterns.append(pattern)
                logger.info("Registered custom PII pattern: %s", pattern.pattern_id)

    # ── Core scanning ──────────────────────────────────────────────────

    def scan_text(
        self,
        text: str,
        max_matches: int = 1000,
    ) -> list[PIIScanResult]:
        """Scan a text string for PII patterns.

        Args:
            text: The text to scan.
            max_matches: Stop collecting matches per pattern after this limit.

        Returns:
            List of :class:`PIIScanResult` for each pattern that matched.
        """
        results: list[PIIScanResult] = []

        for pattern in self._patterns:
            matches_raw: list[str] = []
            locations: list[int] = []
            validated_count = 0
            rejected_count = 0

            # Build line offset map for location tracking
            lines = text.split("\n")
            line_offset = 0

            for line_num, line in enumerate(lines, start=1):
                if len(matches_raw) >= max_matches:
                    break
                for m in pattern.regex.finditer(line):
                    match_text = m.group(0)

                    if pattern.validator:
                        if pattern.validator(match_text):
                            validated_count += 1
                        else:
                            rejected_count += 1
                            continue  # Skip invalid matches

                    matches_raw.append(match_text)
                    locations.append(line_num)

                    if len(matches_raw) >= max_matches:
                        break

            if not matches_raw:
                continue

            # Determine confidence
            if pattern.validator:
                confidence = "high" if validated_count > 0 else "low"
            else:
                confidence = "medium"

            # Build redacted samples (up to MAX_SAMPLES)
            samples = [redact_match(m) for m in matches_raw[: self.MAX_SAMPLES]]

            results.append(PIIScanResult(
                pattern_id=pattern.pattern_id,
                pattern_name=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                match_count=len(matches_raw),
                sample_matches=samples,
                locations=locations,
                confidence=confidence,
            ))

        logger.debug(
            "scan_text completed: %d pattern(s) matched, %d total findings",
            len(results),
            sum(r.match_count for r in results),
        )
        return results

    def scan_file_content(
        self,
        content: bytes,
        filename: str = "",
        max_size: int = 1_048_576,
    ) -> list[PIIScanResult]:
        """Scan raw file content (bytes) for PII.

        Only the first ``max_size`` bytes are scanned to bound memory and
        CPU usage on large files.

        Args:
            content: Raw bytes of the file content.
            filename: Optional filename for logging context.
            max_size: Maximum number of bytes to scan (default 1 MB).

        Returns:
            List of :class:`PIIScanResult`.
        """
        if len(content) > max_size:
            logger.warning(
                "File %s exceeds max_size (%d bytes); truncating to %d bytes",
                filename or "<unnamed>",
                len(content),
                max_size,
            )
            content = content[:max_size]

        # Attempt UTF-8 decode, fall back to latin-1 (never fails)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = content.decode("latin-1")
            except Exception:
                logger.error(
                    "Cannot decode file %s; skipping PII scan",
                    filename or "<unnamed>",
                )
                return []

        logger.info(
            "Scanning file content: %s (%d bytes)",
            filename or "<unnamed>",
            len(content),
        )
        return self.scan_text(text)

    def scan_structured_data(
        self,
        data: list[dict],
        column_names: Optional[list[str]] = None,
    ) -> list[PIIScanResult]:
        """Scan structured data (e.g. CSV/JSON rows) for PII.

        Each row is a dict. If ``column_names`` is provided, only those
        columns are scanned; otherwise all columns are inspected.

        Column names themselves are also checked for PII-suggestive keywords
        (e.g. ``dni``, ``email``, ``ssn``), which raises the confidence of
        any findings in those columns.

        Args:
            data: List of row dicts (e.g. from ``csv.DictReader``).
            column_names: Restrict scanning to these column keys.

        Returns:
            List of :class:`PIIScanResult`.
        """
        if not data:
            return []

        # Determine columns to scan
        if column_names:
            cols = column_names
        else:
            cols = list(data[0].keys()) if data else []

        # Concatenate all cell values into a single scannable text,
        # preserving row numbers for location tracking.
        text_lines: list[str] = []
        for row_idx, row in enumerate(data):
            row_parts: list[str] = []
            for col in cols:
                val = row.get(col)
                if val is not None:
                    row_parts.append(str(val))
            text_lines.append(" ".join(row_parts))

        combined_text = "\n".join(text_lines)

        logger.info(
            "Scanning structured data: %d rows, %d columns",
            len(data),
            len(cols),
        )
        return self.scan_text(combined_text)

    # ── Classification helpers ─────────────────────────────────────────

    @staticmethod
    def get_sensitivity_level(results: list[PIIScanResult]) -> str:
        """Determine the overall data sensitivity level based on PII findings.

        Classification levels (highest to lowest):
        - ``restricted``: Critical severity PII found (national IDs, credit cards).
        - ``confidential``: High severity PII found (passports, corporate IDs).
        - ``internal``: Medium severity PII found (emails, phone numbers).
        - ``public``: No PII found or only low-severity matches.

        Args:
            results: Scan results to evaluate.

        Returns:
            Sensitivity level string.
        """
        if not results:
            return "public"

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(
            severity_rank.get(r.severity, 0) for r in results
        )

        if max_severity >= 4:
            return "restricted"
        elif max_severity >= 3:
            return "confidential"
        elif max_severity >= 2:
            return "internal"
        return "public"

    @staticmethod
    def generate_report(results: list[PIIScanResult]) -> dict:
        """Generate a summary report from scan results.

        The report includes counts by category and severity, the overall
        sensitivity level, and a sha256 fingerprint of the findings for
        audit traceability.

        Args:
            results: Scan results to summarize.

        Returns:
            Dict with keys: ``total_findings``, ``total_patterns_matched``,
            ``sensitivity_level``, ``by_category``, ``by_severity``,
            ``findings``, ``fingerprint``.
        """
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        findings: list[dict] = []

        for r in results:
            by_category[r.category] = by_category.get(r.category, 0) + r.match_count
            by_severity[r.severity] = by_severity.get(r.severity, 0) + r.match_count
            findings.append({
                "pattern_id": r.pattern_id,
                "pattern_name": r.pattern_name,
                "category": r.category,
                "severity": r.severity,
                "match_count": r.match_count,
                "confidence": r.confidence,
                "sample_matches": r.sample_matches,
            })

        total_findings = sum(r.match_count for r in results)

        # Deterministic fingerprint for audit trail
        fingerprint_data = "|".join(
            f"{r.pattern_id}:{r.match_count}" for r in sorted(results, key=lambda x: x.pattern_id)
        )
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        sensitivity = PIIScanner.get_sensitivity_level(results)

        return {
            "total_findings": total_findings,
            "total_patterns_matched": len(results),
            "sensitivity_level": sensitivity,
            "by_category": by_category,
            "by_severity": by_severity,
            "findings": findings,
            "fingerprint": fingerprint,
        }
