#!/usr/bin/env python3
"""
GQLRecon Stage 5: Risk Scoring and Report Generation (Part 1: Aggregation)

Loads the JSON output files produced by Stages 1 through 4 and combines
them into a single structured summary with a risk score and severity
rating per finding. This module only handles aggregation and scoring; HTML
rendering is handled separately in stage5_report.py's second half, added
once this part is validated.

Severity scale used throughout: INFO, LOW, MEDIUM, HIGH, CRITICAL.

Usage (as a library, imported by the report generator):
    from stage5_aggregate import aggregate_findings
    summary = aggregate_findings(stage1_path, stage2_path, stage3_path, stage4_path)
"""

import json
import os


def _load_json(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def score_stage1(data):
    """Stage 1 is informational, schema discovery itself isn't a
    vulnerability, but an exposed introspection endpoint in production
    is worth flagging at LOW severity since it aids further attacks."""
    if not data:
        return []
    findings = []
    if data.get("introspection_enabled"):
        findings.append({
            "stage": 1,
            "title": "GraphQL introspection is enabled",
            "severity": "LOW",
            "detail": (
                f"The schema was fully mapped via introspection: "
                f"{len(data.get('schema_summary', {}).get('queries', []))} queries, "
                f"{len(data.get('schema_summary', {}).get('mutations', []))} mutations, "
                f"{data.get('schema_summary', {}).get('total_types', 0)} total types. "
                f"Introspection is often disabled in production APIs to reduce "
                f"attack surface reconnaissance."
            ),
        })
    return findings


def score_stage2(data):
    """Stage 2 findings: batching and alias abuse both indicate the
    server has no per-operation rate limiting, MEDIUM severity since it
    enables rate limit bypass and brute force amplification."""
    if not data:
        return []
    findings = []

    batching = data.get("batching") or {}
    if batching.get("supported"):
        findings.append({
            "stage": 2,
            "title": "Query batching is accepted with no apparent limit",
            "severity": "MEDIUM",
            "detail": (
                f"Sent {batching.get('batch_size_sent')} queries in a single HTTP "
                f"request; {batching.get('responses_returned')} were processed. "
                f"This can be used to bypass request-based rate limiting."
            ),
        })

    alias = data.get("alias_abuse") or {}
    if alias.get("supported"):
        findings.append({
            "stage": 2,
            "title": "Field alias abuse is accepted with no apparent limit",
            "severity": "MEDIUM",
            "detail": (
                f"A single query repeating one field {alias.get('alias_count_sent')} "
                f"times via aliases was fully resolved "
                f"({alias.get('aliases_returned')} aliases returned). This can be "
                f"used to hide many operations inside what looks like one request."
            ),
        })
    elif alias.get("possible_resource_exhaustion"):
        findings.append({
            "stage": 2,
            "title": "Alias repetition caused a request timeout",
            "severity": "MEDIUM",
            "detail": (
                f"Repeating field '{alias.get('field_used')}' "
                f"{alias.get('alias_count_sent')} times caused the server to stop "
                f"responding. Worth manual follow up as a possible resource "
                f"exhaustion vector."
            ),
        })

    return findings


def score_stage3(data):
    """Stage 3 findings: lack of depth limiting is HIGH severity since it
    is a direct denial of service vector, especially when response time
    grows sharply with depth as observed."""
    if not data:
        return []
    findings = []

    depth_test = data.get("depth_test") or {}
    depths_tested = depth_test.get("depths_tested") or []
    max_accepted = depth_test.get("max_accepted_depth", 0)
    limit_enforced = depth_test.get("server_enforces_depth_limit", False)

    timed_out = any(d.get("outcome") == "timeout" for d in depths_tested)

    if not limit_enforced and (max_accepted >= 20 or timed_out):
        severity = "HIGH" if timed_out else "MEDIUM"
        findings.append({
            "stage": 3,
            "title": "No query depth or complexity limit enforced",
            "severity": severity,
            "detail": (
                f"Queries nesting '{data.get('entry_field')}' through "
                f"{' -> '.join(data.get('repeat_fields', []))} were accepted up to "
                f"depth {max_accepted}"
                + (
                    ", and a deeper query caused a request timeout, indicating a "
                    "genuine resource exhaustion risk."
                    if timed_out else
                    " with no rejection observed in the tested range."
                )
            ),
        })
    elif limit_enforced:
        findings.append({
            "stage": 3,
            "title": "Query depth limit appears enforced",
            "severity": "INFO",
            "detail": f"Server began rejecting queries at or before depth {max_accepted + 1}.",
        })

    return findings


def score_stage4(data):
    """Stage 4 findings: confirmed broken access control on a
    sensitive-looking field is CRITICAL, since Stage 4 already filters to
    fields that look sensitive by name before testing."""
    if not data:
        return []
    findings = []

    for entry in data.get("findings") or []:
        unauth = entry.get("unauthenticated") or {}
        field_name = entry.get("field")

        if unauth.get("flag") == "potential_broken_access_control":
            raw_response = unauth.get("raw_response") or {}
            findings.append({
                "stage": 4,
                "title": f"Unauthenticated access to sensitive field '{field_name}'",
                "severity": "CRITICAL",
                "detail": (
                    f"Field '{field_name}' returned data with no authentication "
                    f"and no errors. Sample response: "
                    f"{json.dumps(raw_response.get('data', {}))[:200]}"
                ),
            })

        auth_note = entry.get("auth_comparison_note")
        if auth_note:
            findings.append({
                "stage": 4,
                "title": f"Auth header does not appear enforced on '{field_name}'",
                "severity": "HIGH",
                "detail": auth_note,
            })

    return findings


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def aggregate_findings(stage1_path=None, stage2_path=None, stage3_path=None, stage4_path=None):
    stage1_data = _load_json(stage1_path)
    stage2_data = _load_json(stage2_path)
    stage3_data = _load_json(stage3_path)
    stage4_data = _load_json(stage4_path)

    all_findings = []
    all_findings.extend(score_stage1(stage1_data))
    all_findings.extend(score_stage2(stage2_data))
    all_findings.extend(score_stage3(stage3_data))
    all_findings.extend(score_stage4(stage4_data))

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        severity_counts[f["severity"]] += 1

    if severity_counts["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        overall_risk = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
    elif severity_counts["LOW"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    target_url = None
    for data in (stage1_data, stage2_data, stage3_data, stage4_data):
        if data and data.get("target_url"):
            target_url = data["target_url"]
            break

    return {
        "target_url": target_url,
        "overall_risk": overall_risk,
        "severity_counts": severity_counts,
        "findings": all_findings,
        "stages_included": {
            "stage1": stage1_data is not None,
            "stage2": stage2_data is not None,
            "stage3": stage3_data is not None,
            "stage4": stage4_data is not None,
        },
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GQLRecon Stage 5: Aggregate findings (part 1, no HTML yet)")
    parser.add_argument("--stage1", default=None)
    parser.add_argument("--stage2", default=None)
    parser.add_argument("--stage3", default=None)
    parser.add_argument("--stage4", default=None)
    args = parser.parse_args()

    summary = aggregate_findings(args.stage1, args.stage2, args.stage3, args.stage4)
    print(json.dumps(summary, indent=2))
