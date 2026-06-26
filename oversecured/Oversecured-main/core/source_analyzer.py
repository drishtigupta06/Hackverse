import os
import math
import re
import yaml
import logging
logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ENTROPY HELPERS  (false-positive reduction)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Minimum Shannon entropy a matched secret string must have.
# Real secrets (API keys, tokens) are high-entropy; dummy/doc strings are not.
MIN_SECRET_ENTROPY = 3.2


def _shannon_entropy(s: str) -> float:
    """Return Shannon entropy (bits) for string s."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ln = len(s)
    return -sum((cnt / ln) * math.log2(cnt / ln) for cnt in freq.values())


# Known placeholder / documentation patterns that always trigger false positives.
_KNOWN_FALSE_POSITIVE_PATTERNS = re.compile(
    r"(?i)("
    # AWS documentation examples
    r"AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY|EXAMPLE.?KEY"
    # Generic test/placeholder strings
    r"|YOUR[_\-]?(API[_\-]?KEY|SECRET|TOKEN|KEY|CLIENT[_\-]?ID|CLIENT_SECRET|APP_ID)[_\-]?HERE"
    r"|REPLACE[_\-]?WITH[_\-]?YOUR"
    r"|<YOUR[_\s].*?>"
    r"|insert[_\s]?your[_\s]?key"
    r"|example[A-Z]|placeholder|changeme|change_me|todo"
    r"|dummy|fake|test[A-Z]|sample|demo|default|override|tempKey"
    # Very common weak passwords / fixture passwords used in tests
    r"|password123|admin123|secret123|qwerty|letmein|welcome1|12345678"
    r"|test_key|test_token|test_secret|test_password|test_api"
    r"|com\.example|com\.sample|com\.test|com\.demo"
    r"|\"key\"\s*[:=]\s*\"value\""
    r"|\"password\"\s*[:=]\s*\"password\""
    r"|\"token\"\s*[:=]\s*\"token\""
    r"|gitignored|\.gitignore"
    r")",
    re.IGNORECASE,
)

# Rules where entropy checking makes sense (secret/credential rules).
_ENTROPY_RULE_IDS = {
    "SRC-001",  # Generic hardcoded secrets
    "SRC-002",  # AWS Access Key ID
    "SRC-003",  # AWS Secret Access Key
    "SRC-004",  # Google API Key
    "SRC-008",  # JWT
    "SRC-009",  # Crypto key/IV
    "SRC-011",  # Stripe live key
    "SRC-012",  # GitHub / GitLab PAT
    "SRC-019",  # Generic token
    "SRC-020",  # Bearer token
    "SRC-021",  # Slack token
    "SRC-022",  # Discord token
    "SRC-077",  # Generic API key
    "SRC-090",  # Auth token
    "SRC-100",  # OAuth token
}


def _extract_secret_value(match_text: str) -> str:
    """
    Try to pull the actual secret value out of a match string so we can
    check its entropy.  Falls back to the full match if we can't parse it.
    """
    # Pattern:  key = "VALUE"  or  key: "VALUE"
    m = re.search(r"""[=:]\s*['"]([^'"]{4,})['"]""", match_text)
    if m:
        return m.group(1)
    return match_text


def _is_likely_false_positive(rule_id: str, match_text: str) -> bool:
    """
    Return True when the match looks like a placeholder / test value.
    Checks are applied only to secret-detection rules to avoid
    accidentally filtering out real vulnerability findings.
    """
    if rule_id not in _ENTROPY_RULE_IDS:
        return False

    # 1. Known placeholder pattern check
    if _KNOWN_FALSE_POSITIVE_PATTERNS.search(match_text):
        return True

    # 2. Entropy check on the secret value itself
    secret = _extract_secret_value(match_text)
    if len(secret) >= 8:
        entropy = _shannon_entropy(secret)
        if entropy < MIN_SECRET_ENTROPY:
            return True

    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SOURCE ANALYZER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SourceAnalyzer:
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = self._load_rules()

    def _load_rules(self):
        rules = []
        if not os.path.exists(self.rules_dir):
            return rules
        for filename in os.listdir(self.rules_dir):
            if not (filename.endswith(".yml") or filename.endswith(".yaml")):
                continue
            filepath = os.path.join(self.rules_dir, filename)
            with open(filepath, "r") as f:
                try:
                    data = yaml.safe_load(f)
                    if data and "rules" in data:
                        for rule in data["rules"]:
                            if "regex" in rule:
                                rules.append(rule)
                except Exception as e:
                    print(f"[-] Error loading rule file {filename}: {e}")
        return rules

    def analyze(self, source_dir):
        findings = []

        compiled_normal = []
        compiled_inverted = []
        for r in self.rules:
            try:
                c = re.compile(r["regex"], re.DOTALL)
                if r.get("inverted"):
                    compiled_inverted.append((r, c))
                else:
                    compiled_normal.append((r, c))
            except Exception as e:
                print(f"[-] Invalid regex in rule {r.get('id')}: {e}")

        if not compiled_normal and not compiled_inverted:
            return findings

        found_inverted_anywhere = {r["id"]: False for r, _ in compiled_inverted}

        for root, _, files in os.walk(source_dir):
            for filename in files:
                if not filename.endswith(".java"):
                    continue
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    if not content:
                        continue
                    lines = content.splitlines()
                    self._scan_file(
                        file_path, content, lines, source_dir,
                        compiled_normal, findings
                    )
                    for rule, cregex in compiled_inverted:
                        if not found_inverted_anywhere[rule["id"]] and cregex.search(content):
                            found_inverted_anywhere[rule["id"]] = True
                except Exception:
                    logger.debug("Silent exception caught", exc_info=True)

        for rule, _ in compiled_inverted:
            if not found_inverted_anywhere[rule["id"]]:
                finding = self._get_or_create_finding(rule, findings)
                match_text = "APK-wide: no matching patterns found across all source files"
                if match_text not in finding["matches"]:
                    finding["matches"].append(match_text)

        return findings

    # ── per-file scan ──────────────────────────────────────────────────────

    def _scan_file(self, file_path, content, lines, source_dir, compiled_rules, findings):
        rel_path = os.path.relpath(file_path, source_dir)

        for rule, compiled_regex in compiled_rules:
            rule_id = rule.get("id", "")

            for match in compiled_regex.finditer(content):
                match_text = match.group(0)

                # ── False-positive filter ──────────────────────────────
                if _is_likely_false_positive(rule_id, match_text):
                    continue

                finding = self._get_or_create_finding(rule, findings)
                if len(finding["matches"]) >= 50:
                    continue

                line_num = content[: match.start()].count("\n") + 1
                line_text = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                finding["matches"].append(f"{rel_path}:{line_num} -> {line_text}")

                # Code context: ±5 lines
                ctx_before = [
                    {"num": i + 1, "code": lines[i]}
                    for i in range(max(0, line_num - 6), line_num - 1)
                    if i < len(lines)
                ]
                ctx_after = [
                    {"num": i + 1, "code": lines[i]}
                    for i in range(line_num, min(len(lines), line_num + 5))
                    if i < len(lines)
                ]
                code_ctx = {
                    "file": rel_path,
                    "line": line_num,
                    "code": lines[line_num - 1] if line_num <= len(lines) else "",
                    "before": ctx_before,
                    "after": ctx_after,
                    "match_start": match.start(),
                    "match_end": match.end(),
                    "match_text": match_text,
                    # Attach entropy info for secret rules (useful in report)
                    "entropy": round(
                        _shannon_entropy(_extract_secret_value(match_text)), 2
                    ) if rule.get("id") in _ENTROPY_RULE_IDS else None,
                }
                if "_code_context" not in finding:
                    finding["_code_context"] = []
                finding["_code_context"].append(code_ctx)

    @staticmethod
    def _get_or_create_finding(rule, findings):
        rule_id = rule.get("id")
        for f in findings:
            if f["id"] == rule_id:
                return f
        finding = {
            "id": rule_id,
            "name": rule.get("name"),
            "description": rule.get("description"),
            "severity": rule.get("severity", "INFO"),
            "recommendation": rule.get("recommendation", ""),
            "type": "source",
            "matches": [],
        }
        findings.append(finding)
        return finding
