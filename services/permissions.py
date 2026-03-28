"""
Permissions Analysis Service
=============================
Handles Android manifest parsing and permission risk analysis.
"""

import os
import re
import xml.etree.ElementTree as ET

from models.permissions_db import DANGEROUS_PERMISSIONS, SUSPICIOUS_COMBOS


def parse_android_manifest(extract_dir):
    """Parse AndroidManifest.xml to extract metadata and permissions using androguard"""
    manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")

    result = {
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "uses_features": [],
    }

    if not os.path.exists(manifest_path):
        return result

    try:
        # Try using androguard for proper AXML parsing
        # androguard 4.x path; fall back to 3.x path on ImportError
        try:
            from androguard.core.axml import AXMLPrinter  # androguard >= 4.0
        except ImportError:
            from androguard.core.bytecodes.axml import AXMLPrinter  # androguard 3.x

        with open(manifest_path, "rb") as f:
            axml = AXMLPrinter(f.read())
            # get_xml() returns bytes; get_xml_obj() returns an lxml element
            manifest_xml = axml.get_xml()

        # Parse the XML tree
        root = ET.fromstring(manifest_xml)

        # Extract package name
        result["package_name"] = root.get("package")

        # Extract version info
        result["version_name"] = root.get(
            "{http://schemas.android.com/apk/res/android}versionName"
        )
        result["version_code"] = root.get(
            "{http://schemas.android.com/apk/res/android}versionCode"
        )

        # Extract SDK versions
        for uses_sdk in root.findall(".//uses-sdk"):
            result["min_sdk"] = uses_sdk.get(
                "{http://schemas.android.com/apk/res/android}minSdkVersion"
            )
            result["target_sdk"] = uses_sdk.get(
                "{http://schemas.android.com/apk/res/android}targetSdkVersion"
            )

        # Extract permissions
        for uses_permission in root.findall(".//uses-permission"):
            perm = uses_permission.get(
                "{http://schemas.android.com/apk/res/android}name"
            )
            if perm and perm not in result["permissions"]:
                result["permissions"].append(perm)

        print(
            f"✅ Extracted {len(result['permissions'])} permissions from {result['package_name']}"
        )

        return result

    except ImportError:
        print("⚠️ androguard not installed, falling back to basic string extraction")
        # Fallback to basic string extraction if androguard not available
        try:
            with open(manifest_path, "rb") as f:
                content = f.read()

            strings = _extract_strings_from_binary(content)

            for s in strings:
                if s.startswith("android.permission."):
                    if s not in result["permissions"]:
                        result["permissions"].append(s)
                elif re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", s, re.I):
                    if len(s) > 5 and "." in s:
                        if result["package_name"] is None:
                            result["package_name"] = s

            return result
        except Exception as e:
            print(f"Error parsing manifest: {e}")
            return result

    except Exception as e:
        print(f"Error parsing manifest with androguard: {e}")
        return result


def _extract_strings_from_binary(content):
    """Extract readable strings from binary content"""
    strings = []
    current = []

    for byte in content:
        if 32 <= byte < 127:  # Printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= 5:  # Minimum string length
                strings.append("".join(current))
            current = []

    if len(current) >= 5:
        strings.append("".join(current))

    return strings


def analyze_permissions(permissions):
    """Analyze permissions for risk assessment and return structured analysis"""
    analysis = {
        "total_count": len(permissions),
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "unknown": [],
        "suspicious_combos": [],
        "risk_score": 0,
    }

    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            perm_info = DANGEROUS_PERMISSIONS[perm]
            level = perm_info["level"]
            entry = {
                "permission": perm,
                "description": perm_info["description"],
                "risk": perm_info["risk"],
            }
            analysis[level].append(entry)
        else:
            # Check if it's a custom permission
            if perm.startswith("android.permission."):
                analysis["unknown"].append({"permission": perm})

    # Check for suspicious combinations
    for combo in SUSPICIOUS_COMBOS:
        if all(p in permissions for p in combo["permissions"]):
            analysis["suspicious_combos"].append(
                {
                    "threat": combo["threat"],
                    "description": combo["description"],
                    "permissions": combo["permissions"],
                }
            )

    # Evaluate user-defined custom threat rules from the database
    try:
        import json as _json
        from models.database import ThreatRule

        active_rules = ThreatRule.query.filter_by(is_active=True).all()
        for rule in active_rules:
            rule_perms = _json.loads(rule.permissions) if rule.permissions else []
            if rule_perms and all(p in permissions for p in rule_perms):
                analysis["suspicious_combos"].append(
                    {
                        "threat": rule.threat,
                        "description": rule.description,
                        "permissions": rule_perms,
                        "custom_rule": True,
                        "rule_id": rule.id,
                    }
                )
    except Exception:
        # Outside app context or DB not available — skip custom rules silently
        pass

    # Calculate risk score (0-100)
    score = 0
    score += len(analysis["critical"]) * 20
    score += len(analysis["high"]) * 10
    score += len(analysis["medium"]) * 5
    score += len(analysis["low"]) * 1
    score += len(analysis["suspicious_combos"]) * 25

    analysis["risk_score"] = min(100, score)

    return analysis
