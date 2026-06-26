"""
Confidence Scoring — Dynamic verification distinguishes generated vs validated
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Levels:
  EXPLOIT     (100) — Exploit validated on live device
  DYNAMIC      (85) — Dynamic analysis confirmed (Frida hook hit)
  TAINT        (70) — Taint flow confirmed (source → sink)
  DATAFLOW     (55) — Dataflow analysis confirms path
  STATIC       (40) — Pattern/regex match only
  POC_GEN      (75) — PoC generated but not yet validated

Weights:
  Static match:        40
  Dataflow confirmed:  55
  PoC generated:       75
  Taint confirmed:     70
  Dynamic confirmed:   85
  Exploit validated:  100
"""

from collections import defaultdict


LEVELS = {
    "STATIC":     {"score": 40,  "label": "Pattern/Regex Match Only"},
    "DATAFLOW":   {"score": 55,  "label": "Dataflow Confirmed"},
    "TAINT":      {"score": 70,  "label": "Taint Flow Confirmed"},
    "POC_GEN":    {"score": 75,  "label": "Exploit PoC Generated"},
    "DYNAMIC":    {"score": 85,  "label": "Dynamic Analysis Confirmed"},
    "EXPLOIT":    {"score": 100, "label": "Exploit Verified"},
}

STATIC     = 0.40
DATAFLOW   = 0.55
TAINT      = 0.70
POC_GEN    = 0.75
DYNAMIC    = 0.85
EXPLOIT    = 1.00

# Heuristic boosters — when finding is in app's own code or targets exported component
APP_CODE_BOOST    = 0.10   # +10 if finding class is from app's own package
EXPORTED_BOOST    = 0.05   # +5  if finding involves an exported component

IGNORED_LIBRARIES_FOR_SCORE = [
    "androidx.", "com.google.", "org.apache.", "org.json.",
    "kotlin.", "kotlinx.", "com.squareup.", "io.reactivex.",
    "com.fasterxml.", "org.slf4j.", "okhttp3.", "okio.",
    "android.", "com.google.android.material.",
    "com.google.common.", "com.google.firebase.",
]

def _is_app_code(class_name, app_package):
    """Returns True if class_name is part of the app (not a library).
    If no class_name or package is available, assume it's app-level (manifest finding)."""
    if not class_name or not app_package:
        return True  # no class info → likely manifest/app-level finding
    # Handle both Java (com.foo.bar) and Dalvik (Lcom/foo/bar; ->method(...)) formats
    normalized = class_name.replace("/", ".").replace("\\", ".")
    if normalized.startswith("L") and ";" in normalized:
        normalized = normalized[1:].split(";")[0]
    if ";->" in normalized:
        normalized = normalized.split(";->")[0]
    if normalized.startswith(app_package):
        return True
    for lib in IGNORED_LIBRARIES_FOR_SCORE:
        lib_norm = lib.replace("/", ".")
        if normalized.startswith(lib_norm):
            return False
    # Default: if it doesn't match any known library, treat as app code
    return True


class ConfidenceScorer:
    def __init__(self, app_package=""):
        self.scores = {}
        self.app_package = app_package

    def score_finding(self, finding, has_dataflow=False, has_taint=False,
                      has_dynamic=False, has_exploit=False, has_validated=False,
                      is_exported=False, is_app_code=True):
        base = STATIC
        if has_dataflow:
            base = max(base, DATAFLOW)
        if has_taint:
            base = max(base, TAINT)
        if has_exploit and not has_validated:
            base = max(base, POC_GEN)
        if has_dynamic:
            base = max(base, DYNAMIC)
        if has_validated:
            base = max(base, EXPLOIT)

        # Heuristic: boost for app-own-code findings
        if is_app_code:
            base = min(base + APP_CODE_BOOST, 1.0)
        # Heuristic: boost for exported components (more exploitable)
        if is_exported:
            base = min(base + EXPORTED_BOOST, 1.0)

        level = "STATIC"
        if has_validated:
            level = "EXPLOIT"
        elif has_dynamic:
            level = "DYNAMIC"
        elif has_exploit:
            level = "POC_GEN"
        elif has_taint:
            level = "TAINT"
        elif has_dataflow:
            level = "DATAFLOW"

        return {
            "score": round(base * 100),
            "level": level,
            "confidence_pct": round(base * 100),
            "static": True,
            "dataflow": has_dataflow,
            "taint": has_taint,
            "poc_generated": has_exploit,
            "dynamic": has_dynamic,
            "validated": has_validated,
        }

    def score_all_findings(self, findings, taint_findings=None,
                           dynamic_findings=None, exploit_results=None,
                           bb_mode=False):
        scored = []

        taint_sigs = set()
        if taint_findings:
            for tf in taint_findings:
                taint_sigs.add(tf.get("method", ""))

        dynamic_ids = set()
        if dynamic_findings:
            for df in dynamic_findings:
                dynamic_ids.add(df.get("id", ""))

        exploit_ids = set()
        validated_ids = set()
        if exploit_results:
            for er in exploit_results:
                eid = er.get("finding_id", "")
                exploit_ids.add(eid)
                vectors = er.get("vectors", {})
                for vec, vdata in vectors.items():
                    val = vdata.get("validation", {})
                    if val.get("validated") is True:
                        validated_ids.add(eid)
                        break

        EXPORTED_KEYWORDS = ["exported", "MF-007", "MF-008", "MF-009", "MF-010",
                             "ADV-EXP", "ADV-001", "ADV-002", "ADV-008"]

        LOW_PRIORITY_RULES = {
            "MF-004", "MF-005", "MF-006", "MF-024", "MF-025", "MF-043", "MF-044",
            "MF-048", "MF-049", "MF-050", "MF-054", "MF-060", "MF-061", "MF-062",
            "MF-063", "MF-068", "MF-070", "MF-071", "MF-109", "MF-120", "MF-122",
            "MF-139", "MF-157", "MF-161", "MF-169", "MF-171", "MF-172", "MF-173",
            "MF-185", "MF-198", "MF-200", "MF-205", "MF-210",
        }

        for f in findings:
            fid = f.get("id", "")

            # In BB mode, skip low-priority manifest rules
            if bb_mode and fid in LOW_PRIORITY_RULES and f.get("severity") in ("LOW", "MEDIUM"):
                continue

            has_taint = fid in taint_sigs or any(
                tf.get("sink_type") and tf["sink_type"] in str(f).lower()
                for tf in (taint_findings or [])
            )
            has_dynamic = fid in dynamic_ids
            has_exploit = fid in exploit_ids
            has_validated = fid in validated_ids
            has_dataflow = has_taint

            class_name = (f.get("class_name", "") or f.get("source", "") or f.get("file", "") or
                          f.get("location", "") or "")
            is_app = _is_app_code(class_name, self.app_package)

            finding_str = str(f)
            is_exported = any(kw in finding_str for kw in EXPORTED_KEYWORDS)

            score = self.score_finding(
                f, has_dataflow, has_taint, has_dynamic, has_exploit, has_validated,
                is_exported=is_exported, is_app_code=is_app
            )
            scored.append({
                "finding": f,
                "confidence": score,
            })

        return scored

    def get_summary(self, scored_findings):
        if not scored_findings:
            return {"average_confidence": 0, "by_level": {}}

        by_level = defaultdict(int)
        total_score = 0
        for sf in scored_findings:
            level = sf["confidence"]["level"]
            by_level[level] += 1
            total_score += sf["confidence"]["score"]

        return {
            "average_confidence": round(total_score / len(scored_findings), 1),
            "by_level": dict(by_level),
            "total_scored": len(scored_findings),
            "verified": by_level.get("EXPLOIT", 0),
            "dynamic_confirmed": by_level.get("DYNAMIC", 0),
            "poc_generated": by_level.get("POC_GEN", 0),
            "high_confidence": by_level.get("DYNAMIC", 0) + by_level.get("TAINT", 0),
            "low_confidence": by_level.get("STATIC", 0),
        }
