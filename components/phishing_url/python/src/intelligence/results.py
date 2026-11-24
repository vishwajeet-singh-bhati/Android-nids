"""What a threat-intelligence lookup returns.

status
  "match"        at least one feed lists this URL / host (see `matches`)
  "no_match"     no feed lists it. This is NOT evidence that the URL is safe:
                 feeds only know what was reported, and new phishing appears
                 every minute. The decision engine must treat it as "no info".
  "unavailable"  the lookup could not run (database missing, damaged, ...).
                 Also "no info", and worth reporting as a health problem.
  "pending"      an online check was started in the background and has not
                 answered yet; asking again later gives its answer. "No info".

Match levels, strongest first
  "exact_url"          this exact page is listed (scheme and #fragment ignored)
  "hostname"           another page on the same host is listed, and the host
                       is not a popular or shared site
  "registered_domain"  a different host under the same registered domain is
                       listed (e.g. a.evil.example vs b.evil.example), with
                       the same restriction
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

MATCH, NO_MATCH, UNAVAILABLE, PENDING = "match", "no_match", "unavailable", "pending"
EXACT_URL, HOSTNAME, REGISTERED_DOMAIN = "exact_url", "hostname", "registered_domain"
LEVELS = (EXACT_URL, HOSTNAME, REGISTERED_DOMAIN)


PHISHING_THREAT, MALWARE_THREAT = "phishing", "malware"
UNWANTED_SOFTWARE_THREAT, HARMFUL_APP_THREAT = "unwanted_software", "harmful_application"


@dataclass(frozen=True)
class IntelMatch:
    level: str                    # one of LEVELS
    source: str                   # feed / provider name ("phishtank", "google_safe_browsing", ...)
    count: int                    # listed URLs (or matching expressions) behind this match
    first_seen: str               # ISO-8601 UTC
    last_seen: str
    expires_at: str
    source_ids: tuple[str, ...]   # a few feed IDs (e.g. PhishTank phish_id), may be empty
    threat_types: tuple[str, ...] = ()   # "phishing", "malware", ... (never mixed up)
    attribution: str = ""         # text the provider requires next to a warning


@dataclass(frozen=True)
class IntelResult:
    status: str
    matches: tuple[IntelMatch, ...] = ()
    feeds_updated_at: str | None = None   # newest feed snapshot in the database
    stale: bool = False                   # feeds older than the configured limit
    reason: str = ""                      # why the lookup was unavailable

    @property
    def strongest_level(self) -> str | None:
        levels = {m.level for m in self.matches}
        return next((lvl for lvl in LEVELS if lvl in levels), None)

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(sorted({m.source for m in self.matches}))

    def to_dict(self) -> dict:
        out = asdict(self)
        out["matches"] = [dict(m, source_ids=list(m["source_ids"]), threat_types=list(m["threat_types"]))
                          for m in out["matches"]]
        out["strongest_level"] = self.strongest_level
        return out
