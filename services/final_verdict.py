"""
Final Verdict Aggregation Engine
================================
ML is the **primary base signal** (40% weight): label + confidence → normalized risk 0–100.
Supporting **rule_score** (60% weight): permissions, unknown perms, externals, custom rules,
behavior, cert, Play trust.

Hard overrides: dropper → CRITICAL; strong external detections → floor HIGH/CRITICAL.
"""

from __future__ import annotations

from typing import Any

_THREAT_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

ML_WEIGHT = 0.4
RULE_WEIGHT = 0.6


def _merge_levels(*levels: str) -> str:
    return max(levels, key=lambda x: _THREAT_ORDER.get(x, 0))


def _permission_threat_floor(perm_analysis: dict) -> str:
    """Minimum threat implied by permission / combo analysis (danger risk_score 0–100)."""
    rs = float(perm_analysis.get("risk_score") or 0)
    crit = len(perm_analysis.get("critical") or [])
    combos = perm_analysis.get("suspicious_combos") or []
    n_combos = len(combos)
    high = len(perm_analysis.get("high") or [])

    if rs >= 90 or n_combos >= 2:
        return "critical"
    if rs >= 75 or n_combos >= 1 or crit >= 4:
        return "high"
    if rs >= 55 or crit >= 2 or (crit >= 1 and high >= 2):
        return "medium"
    if rs >= 35 or crit >= 1:
        return "medium"
    return "low"


def _external_threat_floor(vt_result: Any, ha_result: Any, md_result: Any) -> str:
    """Strong external detections → at least HIGH/CRITICAL (hard override)."""
    lvl = "low"
    if vt_result and not vt_result.get("error"):
        mal = vt_result.get("malicious")
        if isinstance(mal, int) and mal >= 10:
            return "critical"
        if isinstance(mal, int) and mal >= 3:
            lvl = _merge_levels(lvl, "high")
        elif isinstance(mal, int) and mal > 0:
            lvl = _merge_levels(lvl, "medium")
    if ha_result and not ha_result.get("error") and ha_result.get("found"):
        if ha_result.get("malicious"):
            lvl = _merge_levels(lvl, "high")
    if md_result and not md_result.get("error") and md_result.get("found"):
        pos = int(md_result.get("positives") or 0)
        if pos >= 5:
            lvl = _merge_levels(lvl, "high")
        elif pos > 0:
            lvl = _merge_levels(lvl, "medium")
    return lvl


def _external_rule_contribution(
    vt_result: Any, ha_result: Any, md_result: Any
) -> tuple[float, list[dict[str, str]]]:
    """External scanners → rule_score component (0–100 scale), capped chunk + reasons."""
    add = 0.0
    reasons: list[dict[str, str]] = []

    if vt_result and not vt_result.get("error") and vt_result.get("found"):
        mal = vt_result.get("malicious")
        if isinstance(mal, int) and mal > 0:
            chunk = min(40.0, 12.0 + float(mal) * 2.5)
            add += chunk
            reasons.append(
                {
                    "code": "EXTERNAL_VIRUSTOTAL",
                    "label": "VirusTotal detections",
                    "detail": f"{mal} engine(s) flagged this sample ({vt_result.get('detection_ratio', '?')}).",
                }
            )

    if ha_result and not ha_result.get("error") and ha_result.get("found"):
        if ha_result.get("malicious"):
            add += min(35.0, 28.0)
            reasons.append(
                {
                    "code": "EXTERNAL_HYBRID_ANALYSIS",
                    "label": "Hybrid Analysis",
                    "detail": f"Report verdict: {ha_result.get('verdict', 'malicious')}.",
                }
            )

    if md_result and not md_result.get("error") and md_result.get("found"):
        pos = int(md_result.get("positives") or 0)
        if pos > 0:
            chunk = min(30.0, 8.0 + float(pos) * 3.0)
            add += chunk
            reasons.append(
                {
                    "code": "EXTERNAL_METADEFENDER",
                    "label": "MetaDefender detections",
                    "detail": f"{pos} engine(s) reported threats ({md_result.get('detection_ratio', '?')}).",
                }
            )

    return min(45.0, add), reasons


def _normalized_ml_risk(ml_result: dict) -> float:
    """
    Map ML label + confidence → risk 0–100 (higher = more dangerous).

    * Malware → 60–100 (scales with malware confidence)
    * Suspicious → 40–70
    * Benign / Likely Safe → 10–25 (high benign confidence → lower risk)
    """
    label = (ml_result.get("label") or "").strip().lower()
    conf = float(ml_result.get("confidence") or 0)
    conf = max(0.0, min(1.0, conf))

    if label == "malware":
        return 60.0 + conf * 40.0
    if label == "suspicious":
        return 40.0 + conf * 30.0
    if label in ("benign", "likely safe"):
        return 25.0 - conf * 15.0
    return 35.0


def _compute_rule_score(
    perm_analysis: dict,
    behavior: dict,
    vt_result: Any,
    ha_result: Any,
    md_result: Any,
    cert_info: dict,
    play_store_metadata: dict | None,
) -> tuple[float, list[dict[str, str]]]:
    """
    Supporting signals only (no ML). Returns rule_score 0–100 and reason rows.
    """
    reasons: list[dict[str, str]] = []
    risk = 0.0

    if behavior.get("is_rooted_device"):
        risk += 10.0
        reasons.append(
            {
                "code": "ROOTED_DEVICE",
                "label": "Rooted device",
                "detail": "Scan environment may reduce reliability.",
            }
        )

    if play_store_metadata:
        installs = int(play_store_metadata.get("installs") or 0)
        rating = float(play_store_metadata.get("rating") or 0)
        ratings = int(play_store_metadata.get("ratings") or 0)
        bonus = 0.0
        if installs >= 1_000_000:
            bonus += 8.0
        if rating >= 4.0 and ratings >= 1000:
            bonus += 6.0
        if not play_store_metadata.get("contains_ads"):
            bonus += 4.0
        risk -= bonus
        if bonus > 0:
            reasons.append(
                {
                    "code": "PLAY_STORE_TRUST",
                    "label": "Play Store trust signals",
                    "detail": "Reduced risk contribution from installs/ratings/ads profile.",
                }
            )

    pr = float(perm_analysis.get("risk_score") or 0)
    risk += min(48.0, pr * 0.48)
    if pr >= 50:
        reasons.append(
            {
                "code": "PERMISSION_RISK",
                "label": "Permission & pattern risk",
                "detail": f"Catalog + combo score {pr:.0f}/100.",
            }
        )

    unknown = perm_analysis.get("unknown") or []
    n_unk = len(unknown)
    risk += min(28.0, float(n_unk) * 4.0)
    if n_unk > 0:
        reasons.append(
            {
                "code": "UNKNOWN_PERMISSIONS",
                "label": "Unreviewed permissions",
                "detail": f"{n_unk} permission(s) outside our risk catalog.",
            }
        )

    ext_add, ext_reasons = _external_rule_contribution(vt_result, ha_result, md_result)
    risk += ext_add
    reasons.extend(ext_reasons)

    combos = perm_analysis.get("suspicious_combos") or []
    custom_hits = [c for c in combos if c.get("custom_rule")]
    if custom_hits:
        risk += min(32.0, 16.0 + 8.0 * len(custom_hits))
        for c in custom_hits:
            name = c.get("rule_name") or c.get("threat", "Rule")
            reasons.append(
                {
                    "code": "CUSTOM_RULE",
                    "label": "Custom threat rule matched",
                    "detail": f"{name}: {c.get('threat', '')}",
                }
            )

    if cert_info.get("debug_signed"):
        risk += 12.0
        reasons.append(
            {
                "code": "DEBUG_SIGNED",
                "label": "Debug-signed build",
                "detail": "Signed with a debug certificate.",
            }
        )

    risk = max(0.0, min(100.0, risk))
    return risk, reasons


def _risk_numeric_to_level(risk: float) -> str:
    if risk >= 78:
        return "critical"
    if risk >= 55:
        return "high"
    if risk >= 28:
        return "medium"
    return "low"


def _top_reasons(
    ml_risk: float,
    ml_label: str,
    final_risk: float,
    rule_risk: float,
    rule_reasons: list[dict[str, str]],
    max_items: int = 10,
) -> list[dict[str, str]]:
    """Ordered: ML primary, then strongest supporting signals."""
    out: list[dict[str, str]] = [
        {
            "code": "ML_PRIMARY",
            "label": "AI risk assessment",
            "detail": (
                f"Model: {ml_label} → normalized risk {ml_risk:.0f}/100 "
                f"({ML_WEIGHT:.0%} of aggregate)."
            ),
        },
        {
            "code": "AGGREGATE",
            "label": "Combined risk",
            "detail": (
                f"Final risk {final_risk:.0f}/100 = {ML_WEIGHT:.0%}×AI + {RULE_WEIGHT:.0%}×supporting "
                f"(supporting raw {rule_risk:.0f}/100)."
            ),
        },
    ]
    for r in rule_reasons:
        if len(out) >= max_items:
            break
        out.append(r)
    return out[:max_items]


def compute_final_verdict(
    ml_result: dict,
    perm_analysis: dict,
    behavior: dict | None,
    vt_result: Any,
    ha_result: Any,
    md_result: Any,
    cert_info: dict | None = None,
    play_store_metadata: dict | None = None,
) -> dict[str, Any]:
    """
    Weighted aggregate: final_risk = 0.4 * ml_risk + 0.6 * rule_risk,
    then apply hard overrides (dropper, externals, permission floors).
    """
    behavior = behavior or {}
    cert_info = cert_info or {}

    ml_label = (ml_result.get("label") or "Unknown").strip()
    ml_conf = float(ml_result.get("confidence") or 0)

    ml_signal: dict[str, Any] = {
        "label": ml_label,
        "confidence": ml_conf,
        "role": "primary",
        "ml_risk_score": None,
        "note": "Primary AI signal (40% weight in the final risk score).",
    }
    if ml_result.get("source") == "play_store_metadata":
        ml_signal["note"] = (
            "Heuristic from Play Store metadata (40% weight); no APK binary was scanned."
        )
    if ml_result.get("demo_mode"):
        ml_signal["note"] = (ml_signal.get("note") or "") + " Demo mode."

    # --- Hard gate: dropper -------------------------------------------------
    if behavior.get("dropper_detected"):
        ml_risk = _normalized_ml_risk(ml_result)
        ml_signal["ml_risk_score"] = round(ml_risk, 1)
        reasons = [
            {
                "code": "DROPPER",
                "label": "Dropper behavior detected",
                "detail": "Override: immediate CRITICAL.",
            }
        ]
        return {
            "level": "critical",
            "risk_score": 100,
            "safety_score": 0,
            "reasons": reasons,
            "ml_signal": ml_signal,
        }

    ml_risk = _normalized_ml_risk(ml_result)
    ml_signal["ml_risk_score"] = round(ml_risk, 1)

    rule_risk, rule_reasons = _compute_rule_score(
        perm_analysis,
        behavior,
        vt_result,
        ha_result,
        md_result,
        cert_info,
        play_store_metadata,
    )

    final_risk = ML_WEIGHT * ml_risk + RULE_WEIGHT * rule_risk
    final_risk = max(0.0, min(100.0, final_risk))

    reasons = _top_reasons(
        ml_risk,
        ml_label,
        final_risk,
        rule_risk,
        rule_reasons,
    )

    level = _risk_numeric_to_level(final_risk)
    level = _merge_levels(
        level,
        _permission_threat_floor(perm_analysis),
        _external_threat_floor(vt_result, ha_result, md_result),
    )
    combos = perm_analysis.get("suspicious_combos") or []
    if any(c.get("custom_rule") for c in combos):
        level = _merge_levels(level, "medium")

    safety = 100.0 - final_risk
    if level == "critical":
        safety = min(safety, 25.0)
    elif level == "high":
        safety = min(safety, 45.0)
    elif level == "medium":
        safety = min(safety, 65.0)

    return {
        "level": level,
        "risk_score": int(round(final_risk)),
        "safety_score": int(round(max(0.0, min(100.0, safety)))),
        "reasons": reasons,
        "ml_signal": ml_signal,
    }


def verdict_summary_text(final_verdict: dict, perm_analysis: dict) -> str:
    """One-line summary aligned with ML-primary + supporting signals."""
    n_unk = len(perm_analysis.get("unknown") or [])
    unk_note = (
        f" {n_unk} permission(s) not in our catalog." if n_unk else ""
    )
    level = final_verdict.get("level", "low")
    if level == "critical":
        return (
            f"Final risk: CRITICAL — do not install.{unk_note} "
            "Based on AI assessment (40%) plus supporting signals (60%); critical overrides apply."
        )
    if level == "high":
        return (
            f"Final risk: HIGH — treat as unsafe until reviewed.{unk_note} "
            "AI assessment is weighted with permissions, rules, and external scans."
        )
    if level == "medium":
        return (
            f"Final risk: ELEVATED — review carefully.{unk_note} "
            "AI assessment combined with supporting signals."
        )
    return (
        f"Final risk: Lower from combined signals.{unk_note} "
        "AI assessment (40%) plus supporting analysis (60%)."
    )
