"""Project-wide paths, labels and defaults.

Keep this module dependency-free so it can be imported by scripts, tests and
the eventual mobile-export tooling.
"""

from __future__ import annotations

from pathlib import Path

# The curated checkout ships sms_detection directly under python/, not src/.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
INTERIM_DIR = DATA_DIR / "interim"
PROCESSED_DIR = DATA_DIR / "processed"
SAMPLES_DIR = DATA_DIR / "samples"
INDIAN_DIR = DATA_DIR / "indian"

ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
MODEL_DIR = ARTIFACTS_DIR / "model"
REPORTS_DIR = ARTIFACTS_DIR / "reports"
SCHEMA_DIR = ARTIFACTS_DIR / "schema"
EXPORT_DIR = ARTIFACTS_DIR / "mobile"

DOCS_DIR = PROJECT_ROOT / "docs"

MODULE_NAME = "sms_detector"
SCHEMA_VERSION = "1.0"
MODEL_VERSION = "sms-model-0.1"
POLICY_VERSION = "policy-0.2-review"

LABELS = ("ham", "spam", "smishing")
RISK_LEVELS = ("low", "suspicious", "high")

# Scores are only treated as probabilities after calibration has been measured.
# These defaults are provisional; train_baseline.py selects operating points on
# the validation split and records the trade-off in the evaluation report.
DEFAULT_HIGH_THRESHOLD = 0.80
DEFAULT_SUSPICIOUS_THRESHOLD = 0.45
# A high-risk interruption normally needs a strong evidence cue. A very high
# model score can stand alone; this keeps text-only smishing detectable without
# letting a weak 0.4-score message alarm the user.
DEFAULT_EVIDENCE_FREE_HIGH = 0.80

# Asymmetric cost defaults: a missed smishing message is 10x as costly as a
# legitimate message being escalated to review. This is a policy decision to be
# agreed with the team; it is configurable and must be documented.
DEFAULT_COST_FN = 10.0
DEFAULT_COST_FP = 1.0

RANDOM_STATE = 42

# Sender IDs that are plausibly transactional short codes / verified alpha
# senders. This is a weak local heuristic, not a reputation database.
TRANSACTIONAL_SENDER_RE = r"^[A-Z]{2}-[A-Z0-9]{3,}$|^[A-Z]{5,9}$"

# Datasets that may be redistributed as part of this repository. Raw data is
# still kept out of Git by default; only acquisition instructions and checksums
# are committed.
SOURCE_LICENSES = {
    "uci_sms_spam": "UCI SMS Spam Collection; see dataset page/readme for attribution and reuse terms",
    "lsdst_2022": "CC BY 4.0 (Mishra & Soni, Mendeley Data, DOI 10.17632/f45bkkt8pr.1)",
    "ncsu_sms_phishing": "Repository MIT; verify data-level provenance/third-party constraints",
    "hinglish_scam": "CC BY 4.0 (bolewara/hinglish-scam-text-dataset)",
    "india_spam_sms": (
        "MIT repository license (Kaggle: junioralive/india-spam-sms-classification); "
        "data contributed by users; verify data-level consent/privacy before redistribution"
    ),
    "synthetic_seed": "Project-generated synthetic seed; CC BY 4.0",
}
