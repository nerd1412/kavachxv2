"""
KavachX PII Scanner — Prompt-Level Personally Identifiable Information Detection

Scans raw prompt/output text for government-issued identifiers, financial data,
and biometric references.  Produces structured violation signals that are injected
into the governance pipeline BEFORE policy evaluation.

Legal basis for detections:
  India
  ─────
  • Aadhaar Act 2016, Section 29   — prohibition on disclosure of identity information
  • DPDP Act 2023, Section 9       — special category personal data
  • IT Act 2000, Section 43A       — sensitive personal data & information
  • RBI KYC Master Directions 2016 — banking secrecy obligations
  • PMLA 2002 / UIDAI Circular 2019 — Aadhaar-linked financial fraud
  • Income Tax Act 1961, S.138A    — PAN confidentiality
  • ABDM / NHA Framework           — ABHA health data
  • MoRTH Rules 2017               — driving licence data
  Global
  ──────
  • PCI-DSS v4.0 Req 3.2.1        — primary account number (card data)
  • GDPR Articles 9–10             — special category & criminal data
  • CCPA §1798.140                 — sensitive personal information
  • UK DPA 2018 / NHS Data Security Standard
  • PIPEDA (Canada) Schedule 1    — national identifiers
  • PDPA Thailand / Singapore 2021
  • POPIA South Africa Chapter 3
  • EU PSD2                        — IBAN / payment data
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PIIScanResult:
    pii_detected: bool = False
    third_party_access: bool = False
    financial_access_intent: bool = False
    health_access_intent: bool = False
    biometric_mention: bool = False
    pii_types: List[str] = field(default_factory=list)
    matched_patterns: List[Dict] = field(default_factory=list)
    risk_boost: float = 0.0
    should_block: bool = False
    should_human_review: bool = False
    should_alert: bool = False
    violations: List[Dict] = field(default_factory=list)

    # Convenience signals for governance_service injection
    @property
    def personal_data_used(self) -> bool:
        return self.pii_detected

    @property
    def consent_likely_absent(self) -> bool:
        return self.third_party_access or (self.pii_detected and self.financial_access_intent)


# ──────────────────────────────────────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────────────────────────────────────

class PIIScanner:
    """
    Regex + intent-signal based PII scanner.  No ML dependency — pure pattern
    matching suitable for high-throughput governance pipelines.

    Design principles:
      • Indian documents first — highest legal exposure in KavachX's jurisdiction
      • Global coverage for multinational compliance (GDPR, PCI-DSS, etc.)
      • Intent overlay — accidental mention vs deliberate third-party access
        produce different violation severities
      • No false-negative tolerated on Aadhaar / credit-card / SSN
      • Prefer false-positive (human_review) over false-negative (pass) for BLOCK patterns
    """

    # ══════════════════════════════════════════════════════════════
    # INDIAN STATUTORY DOCUMENT PATTERNS
    # ══════════════════════════════════════════════════════════════

    # Aadhaar (UIDAI) — 12 digits, first digit MUST be 2-9 (0 and 1 never issued)
    # Official formats: XXXX XXXX XXXX  |  XXXX-XXXX-XXXX  |  XXXXXXXXXXXX (12 contiguous)
    _AADHAAR = re.compile(
        r'(?<!\d)'
        r'(\d{4})[\s\-]?(\d{4})[\s\-]?(\d{4})'   # dashed, spaced, or contiguous (0-9 allowed for safety/test cases)
        r'(?!\d)',
        re.ASCII,
    )
    # Also catch virtual IDs (VID) — 16 digits in same family
    _AADHAAR_VID = re.compile(
        r'(?<!\d)([2-9]\d{15})(?!\d)',
        re.ASCII,
    )

    # PAN Card — AAAAA9999A  (10 chars)
    # 4th char encodes entity type: A=individual, B=HUF, C=Company, F=Firm,
    # G=Govt, H=AOP, J=BOI, L=Local body, P=person, T=AOP/Trust, K=Krishi
    _PAN = re.compile(
        r'(?<![A-Z\d])([A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z])(?![A-Z\d])',
        re.IGNORECASE,
    )

    # Indian Passport — Letter + 7 digits  (e.g. A1234567)
    # Valid first letters: A-P, R-W, Y  (excludes O, Q, X, Z)
    _PASSPORT_IN = re.compile(
        r'(?<!\w)([A-PR-WY]\d{7})(?!\d)',
        re.IGNORECASE,
    )

    # Voter ID / EPIC — State(3 alpha) + ID(7 digits)  e.g. GJX1234567
    # Require near-context keyword to avoid false positives
    _VOTER_ID = re.compile(
        r'(?<!\w)([A-Z]{3}\d{7})(?!\d)',
        re.IGNORECASE,
    )
    _VOTER_ID_CONTEXT = re.compile(
        r'\b(voter\s+id|epic|election\s+card|electoral\s+card|election\s+commission)\b',
        re.IGNORECASE,
    )

    # Indian Driving Licence — State(2) + RTO(2) + Year(4) + Serial(7)
    # e.g. MH02-2013-0123456 | KA0520100012345
    _DL_IN = re.compile(
        r'(?<!\w)([A-Z]{2}\d{2}[\s\-]?\d{4}[\s\-]?\d{7})(?!\d)',
        re.IGNORECASE,
    )
    _DL_CONTEXT = re.compile(
        r'\b(driving\s+licen[cs]e|dl\s+number|dl\s+no|motor\s+vehicle|licence\s+number)\b',
        re.IGNORECASE,
    )

    # ABHA (Ayushman Bharat Health Account) — 14 digits  XX-XXXX-XXXX-XXXX
    _ABHA = re.compile(
        r'(?<!\d)(\d{2})[\-\s](\d{4})[\-\s](\d{4})[\-\s](\d{4})(?!\d)',
    )
    _ABHA_CONTEXT = re.compile(
        r'\b(abha|health\s+id|ayushman|ayushman\s+bharat|health\s+account|abdm)\b',
        re.IGNORECASE,
    )

    # UAN (Universal Account Number, EPFO) — 12 digits starting 10
    _UAN = re.compile(
        r'(?<!\d)(10\d{10})(?!\d)',
    )

    # GST Identification Number — 15 chars: 2-digit state FIPS + 10-char PAN + 1 + Z + 1
    _GSTIN = re.compile(
        r'(?<!\w)(\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d])(?!\w)',
        re.IGNORECASE,
    )

    # IFSC Code — BBBB0CCCCCC  (4 alpha + 0 + 6 alphanumeric)
    _IFSC = re.compile(
        r'(?<!\w)([A-Z]{4}0[A-Z0-9]{6})(?!\w)',
        re.IGNORECASE,
    )

    # Indian Bank Account Number — 9 to 18 digits (require financial context)
    _BANK_ACCOUNT_IN = re.compile(
        r'(?<!\d)(\d{9,18})(?!\d)',
    )
    _BANK_ACCOUNT_CONTEXT = re.compile(
        r'\b(account\s+number|ac(?:count)?\s+no|bank\s+a/c|saving[s]?\s+account|'
        r'current\s+account|a/c\s+no)\b',
        re.IGNORECASE,
    )

    # CIN (Company Identification Number) — L/U + 5 digits + 2 state + 4 year + 3 type + 6 seq
    _CIN = re.compile(
        r'(?<!\w)([LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6})(?!\w)',
        re.IGNORECASE,
    )

    # Indian Mobile Number — [6-9]\d{9}  (with/without +91 or 0 prefix)
    _PHONE_IN = re.compile(
        r'(?<!\d)(?:\+91[\s\-]?|0)?([6-9]\d{9})(?!\d)',
    )

    # Ration Card — State prefix + digits (loose, context-required)
    _RATION_CARD = re.compile(
        r'(?<!\w)([A-Z]{2}[\s\-]?\d{7,14})(?!\w)',
        re.IGNORECASE,
    )
    _RATION_CONTEXT = re.compile(
        r'\b(ration\s+card|ration\s+no|pds|public\s+distribution)\b',
        re.IGNORECASE,
    )

    # ══════════════════════════════════════════════════════════════
    # GLOBAL PII PATTERNS
    # ══════════════════════════════════════════════════════════════

    # US Social Security Number — XXX-XX-XXXX  (excludes 000, 666, 900-999 in first group)
    _SSN_US = re.compile(
        r'(?<!\d)(?!000|666|9\d\d)(\d{3})[\-\s](?!00)(\d{2})[\-\s](?!0000)(\d{4})(?!\d)',
    )
    _SSN_CONTEXT = re.compile(
        r'\b(ssn|social\s+security|social\s+security\s+number)\b',
        re.IGNORECASE,
    )

    # UK NHS Number — 10 digits (3-3-4 with spaces/dashes)
    _NHS_UK = re.compile(
        r'(?<!\d)(\d{3}[\s\-]\d{3}[\s\-]\d{4})(?!\d)',
    )
    _NHS_CONTEXT = re.compile(
        r'\b(nhs|national\s+health\s+service|nhs\s+number)\b',
        re.IGNORECASE,
    )

    # UK National Insurance Number — AANNNNNA  (2 alpha + 6 digits + 1 alpha)
    _NINO_UK = re.compile(
        r'(?<!\w)([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D])(?!\w)',
        re.IGNORECASE,
    )

    # Canadian SIN — 9 digits  (3-3-3 with optional separator)
    _SIN_CA = re.compile(
        r'(?<!\d)(\d{3}[\s\-]\d{3}[\s\-]\d{3})(?!\d)',
    )
    _SIN_CONTEXT = re.compile(
        r'\b(sin|social\s+insurance\s+number|canada\s+social)\b',
        re.IGNORECASE,
    )

    # Australian TFN — 9 digits (with or without separators)
    _TFN_AU = re.compile(
        r'(?<!\d)(\d{3}[\s\-]\d{3}[\s\-]\d{3})(?!\d)',
    )
    _TFN_CONTEXT = re.compile(
        r'\b(tfn|tax\s+file\s+number|australia[n]?\s+tax)\b',
        re.IGNORECASE,
    )

    # South African ID — 13 digits  YYMMDD + 4 digits + citizen + checksum
    _SA_ID = re.compile(
        r'(?<!\d)([0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}[01]\d{2})(?!\d)',
    )
    _SA_CONTEXT = re.compile(
        r'\b(sa\s+id|south\s+african\s+id|rsa\s+id|popia|south\s+africa)\b',
        re.IGNORECASE,
    )

    # Singapore / Malaysia NRIC — S/T/F/G + 7 digits + letter
    _NRIC_SG = re.compile(
        r'(?<!\w)([STFG]\d{7}[A-Z])(?!\w)',
        re.IGNORECASE,
    )

    # Payment Card Numbers (PCI-DSS Cardholder Data Environment)
    _CREDIT_CARD = re.compile(
        r'(?<!\d)'
        r'('
        r'4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'          # Visa 16-digit
        r'|4\d{3}[\s\-]?\d{4}[\s\-]?\d{5}'                       # Visa 13-digit (old)
        r'|5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'     # Mastercard 51-55
        r'|2(?:2[2-9]\d|[3-6]\d\d|7(?:[01]\d|20))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'  # Mastercard 2221-2720
        r'|3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}'                   # Amex 15-digit
        r'|6(?:011|5\d{2}|4[4-9]\d|22(?:12[6-9]|1[3-9]\d|[2-8]\d\d|9[01]\d|92[0-5]))'
        r'[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'                  # Discover
        r'|(?:2131|1800|35\d{3})\d{11}'                           # JCB
        r'|6304[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'             # Maestro
        r')'
        r'(?!\d)',
    )

    # IBAN — International Bank Account Number  CC + 2 check + 4-30 alphanumeric
    _IBAN = re.compile(
        r'(?<!\w)((?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DJ|DK|DO|EE|EG|'
        r'ES|FI|FK|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IR|IS|IT|JO|KW|KZ|LB|LC|'
        r'LI|LT|LU|LV|LY|MA|MC|MD|ME|MK|MR|MT|MU|MZ|NL|NO|PK|PL|PS|PT|QA|RO|RS|'
        r'SA|SC|SD|SE|SI|SK|SM|SO|ST|SV|TL|TN|TR|UA|VA|VG|XK)\d{2}[A-Z0-9]{4,30})(?!\w)',
        re.IGNORECASE,
    )

    # Generic International Passport — broad catch (1-2 alpha + 6-9 digits)
    _PASSPORT_GLOBAL = re.compile(
        r'(?<!\w)([A-Z]{1,2}\d{6,9})(?!\w)',
        re.IGNORECASE,
    )
    _PASSPORT_CONTEXT = re.compile(
        r'\b(passport|passport\s+number|passport\s+no|travel\s+document)\b',
        re.IGNORECASE,
    )

    # Email address
    _EMAIL = re.compile(
        r'(?<![^\s,;])'
        r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})'
        r'(?!\w)',
    )

    # IPv4 — flag private IPs only when combined with sensitive context
    _IPV4 = re.compile(
        r'(?<!\d)((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)',
    )

    # ══════════════════════════════════════════════════════════════
    # BIOMETRIC / HEALTH KEYWORDS (no number pattern needed)
    # ══════════════════════════════════════════════════════════════

    _BIOMETRIC = re.compile(
        r'\b(fingerprint|retina\s+scan|iris\s+scan|face\s+recognition|facial\s+recognition|'
        r'voice\s+print|dna\s+sample|biometric[s]?|thumb\s+impression|finger\s+impression)\b',
        re.IGNORECASE,
    )

    # ══════════════════════════════════════════════════════════════
    # INTENT SIGNALS
    # ══════════════════════════════════════════════════════════════

    # Third-party possessives — "my neighbor's", "their Aadhaar", "someone else's"
    _THIRD_PARTY = re.compile(
        r'\b('
        r"neighbor'?s?|neighbour'?s?|colleague'?s?|coworker'?s?|friend'?s?|"
        r"stranger'?s?|employee'?s?|tenant'?s?|customer'?s?|client'?s?|"
        r"wife'?s?|husband'?s?|partner'?s?|relative'?s?|parent'?s?|"
        r"brother'?s?|sister'?s?|their\s+(?:aadhaar|aadhar|pan|account|balance|details|"
        r"data|id|number|bank|credit|financial|personal|information|record|passport)|"
        r"someone\s+else'?s?|another\s+person'?s?|other\s+person'?s?|"
        r"third[\s\-]party|without\s+(?:their|his|her)\s+(?:consent|knowledge|permission)"
        r')\b',
        re.IGNORECASE,
    )

    # Unauthorized access / exfiltration verbs
    _ACCESS_VERBS = re.compile(
        r'\b(look\s*up|look-up|lookup|find\s+out|check|fetch|retrieve|access|extract|'
        r'pull|get\s+(?:their|his|her|the)|hack|intercept|spy\s+on|snoop|steal|phish|'
        r'scrape|dump|exfiltrat[e]?|harvest|mine|expose|leak|share\s+(?:their|someone))\b',
        re.IGNORECASE,
    )

    # Financial data targets
    _FINANCIAL_TARGETS = re.compile(
        r'\b(bank\s+balance|account\s+balance|credit\s+score|loan\s+detail|'
        r'transaction\s+history|financial\s+record|account\s+number|upi\s+id|'
        r'card\s+number|card\s+detail|cvv|cvc|card\s+pin|atm\s+pin|net\s+banking|'
        r'mobile\s+banking|payment\s+detail|salary\s+slip|income\s+detail)\b',
        re.IGNORECASE,
    )

    # Health / medical data targets
    _HEALTH_TARGETS = re.compile(
        r'\b(medical\s+record|health\s+record|prescription|diagnosis|test\s+report|'
        r'patient\s+data|clinical\s+data|health\s+history|discharge\s+summary)\b',
        re.IGNORECASE,
    )

    # Aadhaar-specific context keywords
    _AADHAAR_KEYWORDS = re.compile(
        r'\b(aadhaar|aadhar|uid\s+(?:number|no)|unique\s+(?:identification|id)|uidai)\b',
        re.IGNORECASE,
    )

    # ══════════════════════════════════════════════════════════════
    # Pattern registry — (compiled_regex, pii_type, jurisdiction, severity, context_check)
    # context_check: if not None, the pattern only fires if a context keyword is present
    # ══════════════════════════════════════════════════════════════
    _PATTERNS: list  # defined in __init_subclass__ / assigned after class body

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    def scan(self, text: str) -> PIIScanResult:
        """
        Scan *text* (prompt or output) for PII patterns and intent signals.
        Returns a :class:`PIIScanResult` with structured violation records.
        """
        result = PIIScanResult()
        if not text or len(text.strip()) < 4:
            return result

        # ── Pattern detection ──────────────────────────────────────
        detections = self._run_patterns(text)
        if detections:
            result.pii_detected = True
            result.pii_types = [d["type"] for d in detections]
            result.matched_patterns = detections

        # ── Intent signal extraction ───────────────────────────────
        has_third_party    = bool(self._THIRD_PARTY.search(text))
        has_access_verb    = bool(self._ACCESS_VERBS.search(text))
        has_financial_tgt  = bool(self._FINANCIAL_TARGETS.search(text))
        has_health_tgt     = bool(self._HEALTH_TARGETS.search(text))
        has_aadhaar_kw     = bool(self._AADHAAR_KEYWORDS.search(text))
        has_biometric      = bool(self._BIOMETRIC.search(text))

        result.third_party_access     = has_third_party
        result.financial_access_intent = has_financial_tgt
        result.health_access_intent   = has_health_tgt
        result.biometric_mention      = has_biometric

        pii_set = set(result.pii_types)

        # ── VIOLATION RULES ────────────────────────────────────────
        # Priority: BLOCK > HUMAN_REVIEW > ALERT

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-01  Aadhaar Act 2016 S.29 — Third-party Aadhaar disclosure
        # └─────────────────────────────────────────────────────────────────────
        if ("aadhaar_number" in pii_set or has_aadhaar_kw) and has_third_party:
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.97)
            result.violations.append(_v(
                "aadhaar-act-s29",
                "Aadhaar Act 2016 — S.29 Unauthorized Disclosure",
                "aadhaar-s29-001", "critical", "block", "IN",
                "Aadhaar Act 2016 S.29 Violation: Collecting, sharing or processing "
                "another person's Aadhaar identity information without UIDAI authorization "
                "is a criminal offence — up to 3 years imprisonment (S.38) and ₹10 lakh fine. "
                "Prompt blocked.",
                "aadhaar_number",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-02  PMLA + UIDAI — Aadhaar-linked financial access
        # └─────────────────────────────────────────────────────────────────────
        if ("aadhaar_number" in pii_set or has_aadhaar_kw) and has_financial_tgt and has_third_party:
            result.should_block = True
            result.risk_boost = 1.0
            result.violations.append(_v(
                "pmla-uidai-financial-fraud",
                "PMLA — Aadhaar + Financial Data Access Attempt",
                "pmla-001", "critical", "block", "IN",
                "Prevention of Money Laundering Act 2002 + UIDAI Circular 11020/69/2019: "
                "Combining Aadhaar identity with unauthorized financial data access indicates "
                "potential identity fraud / KYC exploitation. Prompt blocked immediately.",
                "aadhaar_financial_correlation",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-03  IT Act 2000 S.43A — Sensitive PII of a third party
        # └─────────────────────────────────────────────────────────────────────
        indian_pii = pii_set & {
            "aadhaar_number", "pan_card", "passport_india", "voter_id",
            "driving_license", "abha_health_id", "uan_epf",
        }
        if indian_pii and has_third_party:
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.93)
            result.violations.append(_v(
                "it-act-s43a-pii",
                "IT Act 2000 S.43A — Sensitive Personal Data of Third Party",
                "it-act-s43a-001", "critical", "block", "IN",
                f"IT Act 2000 S.43A & Information Technology (Reasonable Security Practices) "
                f"Rules 2011: Unauthorized handling of sensitive personal data — "
                f"{', '.join(sorted(indian_pii))} — of a third party constitutes a data breach "
                f"exposing the organisation to civil liability and regulatory action.",
                "sensitive_pii",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-04  DPDP 2023 S.9 — Special category data (any PII third-party)
        # └─────────────────────────────────────────────────────────────────────
        if result.pii_detected and has_third_party and not any(
            v["rule_id"] == "dpdp-s9-001" for v in result.violations
        ):
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.90)
            result.violations.append(_v(
                "dpdp-2023-s9-special",
                "DPDP Act 2023 — S.9 Special Category Personal Data",
                "dpdp-s9-001", "critical", "block", "IN",
                f"Digital Personal Data Protection Act 2023 S.9: Special category personal data "
                f"({', '.join(result.pii_types[:3])}) of a third party detected without "
                f"verifiable consent of the data principal. Processing blocked.",
                "special_category_data",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-05  RBI KYC MD 2016 — Third-party financial data
        # └─────────────────────────────────────────────────────────────────────
        if has_third_party and (has_financial_tgt or has_access_verb) and not any(
            v["policy_id"] == "rbi-kyc-financial-secrecy" for v in result.violations
        ):
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.88)
            result.violations.append(_v(
                "rbi-kyc-financial-secrecy",
                "RBI KYC Master Directions 2016 — Banking Secrecy",
                "rbi-kyc-001", "critical", "block", "IN",
                "RBI KYC Master Directions 2016 (Updated 2023): Banking secrecy obligations "
                "prohibit sharing account balance, transaction history or financial details of "
                "a third party without their explicit written consent. Unauthorized access "
                "attempt blocked.",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-06  PAN Card third-party (Income Tax Act S.138A)
        # └─────────────────────────────────────────────────────────────────────
        if "pan_card" in pii_set and has_third_party:
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.92)
            result.violations.append(_v(
                "it-act-pan-s138a",
                "Income Tax Act 1961 S.138A — PAN Confidentiality",
                "ita-pan-001", "critical", "block", "IN",
                "Income Tax Act 1961 S.138A & PAN Rules 1962: PAN card data is confidential "
                "taxpayer information. Unauthorized sharing/access of another person's PAN "
                "number is prohibited and may attract criminal prosecution.",
                "pan_card",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-07  ABHA Health data (ABDM / NHA Framework)
        # └─────────────────────────────────────────────────────────────────────
        if "abha_health_id" in pii_set and has_third_party:
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.94)
            result.violations.append(_v(
                "abdm-nha-health-data",
                "ABDM / NHA — ABHA Health Data Protection",
                "abdm-001", "critical", "block", "IN",
                "Ayushman Bharat Digital Mission + NHA Health Data Management Policy: "
                "Accessing ABHA-linked health identity data of a third party without "
                "their explicit consent violates ABDM principles and DPDP Act 2023.",
                "abha_health_id",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-01  PCI-DSS v4.0 — Payment card number (always block)
        # └─────────────────────────────────────────────────────────────────────
        if "credit_card" in pii_set:
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.98)
            result.violations.append(_v(
                "pci-dss-v4-pan-exposure",
                "PCI-DSS v4.0 — Payment Card PAN Exposure",
                "pci-dss-001", "critical", "block", "GLOBAL",
                "PCI-DSS v4.0 Requirement 3.2.1: Full Primary Account Number (card PAN) "
                "detected in plain text. AI systems must NEVER store, process or transmit "
                "full card numbers. Exposure constitutes a PCI Level-1 violation and triggers "
                "mandatory breach notification.",
                "credit_card",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-02  SSN (US) — always high risk
        # └─────────────────────────────────────────────────────────────────────
        if "ssn_us" in pii_set:
            if has_third_party:
                result.should_block = True
                result.risk_boost = max(result.risk_boost, 0.96)
                action, sev = "block", "critical"
            else:
                result.should_human_review = True
                result.risk_boost = max(result.risk_boost, 0.60)
                action, sev = "human_review", "high"
            result.violations.append(_v(
                "us-identity-theft-ssn",
                "US Identity Protection — Social Security Number",
                "ssn-001", sev, action, "US",
                "US Identity Theft Enforcement and Restitution Act + CCPA §1798.140: "
                "Social Security Number detected. SSN exposure is a federal offence. "
                f"{'Third-party access blocked.' if has_third_party else 'Human review required.'}",
                "ssn_us",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-03  UK NINO / NHS — GDPR + UK DPA 2018
        # └─────────────────────────────────────────────────────────────────────
        if "nino_uk" in pii_set or "nhs_uk" in pii_set:
            gb_types = [t for t in ("nino_uk", "nhs_uk") if t in pii_set]
            if has_third_party:
                result.should_block = True
                result.risk_boost = max(result.risk_boost, 0.92)
                action, sev = "block", "critical"
            else:
                result.should_human_review = True
                result.risk_boost = max(result.risk_boost, 0.55)
                action, sev = "human_review", "high"
            result.violations.append(_v(
                "gdpr-uk-dpa-national-id",
                "GDPR Art.9 / UK DPA 2018 — National Identifier",
                "gdpr-uk-001", sev, action, "UK",
                f"UK Data Protection Act 2018 + GDPR Article 9: National identifiers "
                f"({', '.join(gb_types)}) are special category data requiring explicit lawful "
                f"basis. {'Third-party access blocked.' if has_third_party else 'Human review required.'}",
                ", ".join(gb_types),
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-04  Canadian SIN — PIPEDA Schedule 1
        # └─────────────────────────────────────────────────────────────────────
        if "sin_ca" in pii_set:
            action = "block" if has_third_party else "human_review"
            if has_third_party:
                result.should_block = True
                result.risk_boost = max(result.risk_boost, 0.90)
            else:
                result.should_human_review = True
                result.risk_boost = max(result.risk_boost, 0.55)
            result.violations.append(_v(
                "pipeda-sin-canada",
                "PIPEDA — Canadian Social Insurance Number",
                "pipeda-001", "critical" if has_third_party else "high",
                action, "CA",
                "PIPEDA Schedule 1 Principle 4.3: Social Insurance Number is a designated "
                "sensitive identifier. Collection and use is restricted to specific statutory "
                "purposes (CRA, EI, CPP).",
                "sin_ca",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-05  South African ID — POPIA Chapter 3
        # └─────────────────────────────────────────────────────────────────────
        if "sa_id" in pii_set:
            action = "block" if has_third_party else "human_review"
            if has_third_party:
                result.should_block = True
                result.risk_boost = max(result.risk_boost, 0.90)
            else:
                result.should_human_review = True
                result.risk_boost = max(result.risk_boost, 0.55)
            result.violations.append(_v(
                "popia-za-national-id",
                "POPIA Chapter 3 — South African Identity Number",
                "popia-001", "critical" if has_third_party else "high",
                action, "ZA",
                "POPIA (South Africa) Chapter 3: South African ID number is special personal "
                "information requiring explicit consent for processing.",
                "sa_id",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-06  IBAN — EU PSD2 / GDPR
        # └─────────────────────────────────────────────────────────────────────
        if "iban" in pii_set and has_third_party:
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.88)
            result.violations.append(_v(
                "eu-psd2-iban-exposure",
                "EU PSD2 / GDPR — IBAN Financial Data",
                "psd2-001", "critical", "block", "EU",
                "EU PSD2 Article 94 + GDPR Article 9: IBAN combined with third-party "
                "access intent constitutes unauthorized financial data processing.",
                "iban",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-07  Singapore / Malaysia NRIC — PDPA 2021
        # └─────────────────────────────────────────────────────────────────────
        if "nric_sg" in pii_set and has_third_party:
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.90)
            result.violations.append(_v(
                "pdpa-sg-nric",
                "PDPA Singapore 2021 — NRIC Number",
                "pdpa-sg-001", "critical", "block", "SG",
                "PDPA Singapore (Amendment) Act 2020: NRIC number cannot be collected or "
                "used for verification without specific legal authority. Third-party access blocked.",
                "nric_sg",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-GLOBAL-08  Biometric data with access intent
        # └─────────────────────────────────────────────────────────────────────
        if has_biometric and (has_third_party or has_access_verb):
            result.should_block = True
            result.risk_boost = max(result.risk_boost, 0.95)
            result.violations.append(_v(
                "dpdp-2023-biometric-s9",
                "DPDP 2023 / GDPR Art.9 — Biometric Data",
                "biometric-001", "critical", "block", "IN/GLOBAL",
                "DPDP Act 2023 S.9(1) + GDPR Article 9: Biometric data is special category — "
                "collection, processing or access attempt requires explicit consent and "
                "documented lawful basis. Prompt blocked.",
                "biometric",
            ))

        # ┌─────────────────────────────────────────────────────────────────────
        # │ R-IN-08  PII minimisation (self-disclosure, no third-party)
        #   Only alert — user may have legitimate self-service purpose
        # └─────────────────────────────────────────────────────────────────────
        if result.pii_detected and not has_third_party and not result.should_block:
            result.should_alert = True
            result.risk_boost = max(result.risk_boost, 0.30)
            result.violations.append(_v(
                "dpdp-2023-minimisation",
                "DPDP 2023 — Data Minimisation in AI Prompts",
                "dpdp-min-001", "medium", "alert", "IN",
                f"DPDP Act 2023 S.6 (Data Minimisation): Personal identifier(s) — "
                f"{', '.join(result.pii_types[:3])} — detected in prompt. "
                f"AI systems should not process government identifiers unless strictly necessary. "
                f"Logged for compliance review.",
            ))

        return result

    # ──────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────

    # Map from pii_type to (pattern, redaction_label) pairs used for masking.
    # Only patterns that don't require context are included (safe to mask
    # unconditionally).  Context-required patterns are masked when detected.
    _MASK_MAP: List[tuple] = []  # populated in mask()

    def mask(self, text: str) -> str:
        """
        Replace detected PII tokens in *text* with safe placeholders.
        Returns the redacted string suitable for audit-log storage.

        Examples:
          "5566-7788-9900" → "[AADHAAR_REDACTED]"
          "ABCDE1234F"     → "[PAN_REDACTED]"
          "4111111111111111" → "[CARD_REDACTED]"
        """
        if not text:
            return text

        result = text

        # Order matters: longer / more-specific patterns first to avoid partial overwrites
        subs: List[tuple] = [
            (self._AADHAAR,         r"[AADHAAR_REDACTED]"),
            (self._AADHAAR_VID,     r"[AADHAAR_VID_REDACTED]"),
            (self._PAN,             r"[PAN_REDACTED]"),
            (self._CREDIT_CARD,     r"[CARD_REDACTED]"),
            (self._IBAN,            r"[IBAN_REDACTED]"),
            (self._SSN_US,          r"[SSN_REDACTED]"),
            (self._ABHA,            r"[ABHA_REDACTED]"),
            (self._NINO_UK,         r"[NINO_REDACTED]"),
            (self._NHS_UK,          r"[NHS_REDACTED]"),
            (self._SIN_CA,          r"[SIN_REDACTED]"),
            (self._TFN_AU,          r"[TFN_REDACTED]"),
            (self._SA_ID,           r"[SA_ID_REDACTED]"),
            (self._NRIC_SG,         r"[NRIC_REDACTED]"),
            (self._GSTIN,           r"[GSTIN_REDACTED]"),
            (self._UAN,             r"[UAN_REDACTED]"),
            (self._PASSPORT_IN,     r"[PASSPORT_REDACTED]"),
            (self._PASSPORT_GLOBAL, r"[PASSPORT_REDACTED]"),
            (self._VOTER_ID,        r"[VOTER_ID_REDACTED]"),
            (self._DL_IN,           r"[DL_REDACTED]"),
            (self._BANK_ACCOUNT_IN, r"[BANK_ACCT_REDACTED]"),
            (self._PHONE_IN,        r"[PHONE_REDACTED]"),
            (self._RATION_CARD,     r"[RATION_REDACTED]"),
            (self._EMAIL,           r"[EMAIL_REDACTED]"),
        ]
        for pattern, label in subs:
            result = pattern.sub(label, result)

        return result

    def _run_patterns(self, text: str) -> List[Dict]:
        """Apply all regex patterns and return detections list."""
        found: List[Dict] = []

        def _check(
            pattern: re.Pattern,
            pii_type: str,
            jurisdiction: str,
            severity: str,
            context_pattern: Optional[re.Pattern] = None,
        ) -> None:
            if context_pattern and not context_pattern.search(text):
                return
            matches = pattern.findall(text)
            if not matches:
                return
            # Don't double-report the same pii_type
            if any(d["type"] == pii_type for d in found):
                return
            found.append({
                "type": pii_type,
                "jurisdiction": jurisdiction,
                "severity": severity,
                "count": len(matches),
            })

        # ── Indian ────────────────────────────────────────────────
        _check(self._AADHAAR,       "aadhaar_number",   "IN",     "critical")
        _check(self._AADHAAR_VID,   "aadhaar_vid",      "IN",     "critical")
        _check(self._PAN,           "pan_card",         "IN",     "critical")
        _check(self._PASSPORT_IN,   "passport_india",   "IN",     "high",
               context_pattern=re.compile(r'\b(passport)\b', re.I))
        _check(self._VOTER_ID,      "voter_id",         "IN",     "high",
               context_pattern=self._VOTER_ID_CONTEXT)
        _check(self._DL_IN,         "driving_license",  "IN",     "medium",
               context_pattern=self._DL_CONTEXT)
        _check(self._ABHA,          "abha_health_id",   "IN",     "critical",
               context_pattern=self._ABHA_CONTEXT)
        _check(self._UAN,           "uan_epf",          "IN",     "medium")
        _check(self._GSTIN,         "gstin",            "IN",     "medium")
        _check(self._CIN,           "company_cin",      "IN",     "low")
        _check(self._BANK_ACCOUNT_IN, "bank_account_in", "IN",    "high",
               context_pattern=self._BANK_ACCOUNT_CONTEXT)
        _check(self._PHONE_IN,      "indian_mobile",    "IN",     "low")
        _check(self._RATION_CARD,   "ration_card",      "IN",     "medium",
               context_pattern=self._RATION_CONTEXT)

        # ── Global ────────────────────────────────────────────────
        _check(self._CREDIT_CARD,   "credit_card",      "GLOBAL", "critical")
        _check(self._IBAN,          "iban",             "EU",     "high")
        _check(self._SSN_US,        "ssn_us",           "US",     "critical",
               context_pattern=self._SSN_CONTEXT)
        _check(self._NHS_UK,        "nhs_uk",           "UK",     "high",
               context_pattern=self._NHS_CONTEXT)
        _check(self._NINO_UK,       "nino_uk",          "UK",     "high")
        _check(self._SIN_CA,        "sin_ca",           "CA",     "high",
               context_pattern=self._SIN_CONTEXT)
        _check(self._TFN_AU,        "tfn_au",           "AU",     "high",
               context_pattern=self._TFN_CONTEXT)
        _check(self._SA_ID,         "sa_id",            "ZA",     "high",
               context_pattern=self._SA_CONTEXT)
        _check(self._NRIC_SG,       "nric_sg",          "SG",     "high")
        _check(self._PASSPORT_GLOBAL, "passport_intl",  "GLOBAL", "high",
               context_pattern=self._PASSPORT_CONTEXT)
        _check(self._EMAIL,         "email_address",    "GLOBAL", "low")

        return found


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _v(
    policy_id: str,
    policy_name: str,
    rule_id: str,
    severity: str,
    action: str,
    jurisdiction: str,
    message: str,
    pii_type: str = "",
) -> Dict:
    v: Dict = {
        "policy_id":   policy_id,
        "policy_name": policy_name,
        "rule_id":     rule_id,
        "severity":    severity,
        "action":      action,
        "message":     message,
        "jurisdiction": jurisdiction,
    }
    if pii_type:
        v["pii_type"] = pii_type
    return v


# Module-level singleton
pii_scanner = PIIScanner()
