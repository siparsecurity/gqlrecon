#!/usr/bin/env python3
"""
GQLRecon Stage 4: Field Level Authorization Testing

Checks whether fields that look sensitive by name (passwords, tokens,
emails, admin/internal fields, etc.) return real data without proper
authentication. This is the GraphQL equivalent of IDOR: instead of an
insecure REST endpoint, it's an insecure field inside an otherwise normal
looking query.

Two checks are performed for each candidate field:

1. Unauthenticated access: is the field queryable and does it return real
   data with no auth headers at all?
2. Authenticated comparison (only if --auth-header is supplied): does an
   authenticated request return meaningfully different data than the
   unauthenticated one? If the two responses are identical, the auth
   header may not actually be enforced on that field.

This stage does not attempt to guess or brute force credentials. It only
tests the difference between "no auth" and "the auth you provide it".

Usage:
    python3 stage4_auth.py --url http://localhost:5013/graphql --schema ../output/stage1_dvga_test.json
    python3 stage4_auth.py --url http://localhost:5013/graphql --schema ../output/stage1_dvga_test.json --auth-header "Authorization: Bearer eyJ..."
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import requests

TIMEOUT = 10

SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "key", "email", "ssn", "credit", "card", "cvv", "admin",
    "private", "internal", "session", "auth", "credential",
    "salary", "ip", "address", "phone", "diagnostic", "debug",
]


def looks_sensitive(field_name):
    lowered = field_name.lower()
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)


def load_candidate_fields(schema_path):
    """Load Stage 1's schema summary and return query fields that look
    sensitive by name, based on a keyword list."""
    if not schema_path or not os.path.exists(schema_path):
        return []

    with open(schema_path, "r") as f:
        stage1_data = json.load(f)

    schema_summary = stage1_data.get("schema_summary") or {}
    all_fields = (schema_summary.get("queries") or []) + (schema_summary.get("mutations") or [])

    candidates = []
    for field in all_fields:
        name = field.get("name")
        if name and looks_sensitive(name):
            candidates.append(field)

    return candidates


def parse_auth_header(header_str):
    """Parse a 'Header-Name: value' string into a dict entry."""
    if not header_str or ":" not in header_str:
        return {}
    name, value = header_str.split(":", 1)
    return {name.strip(): value.strip()}


def build_probe_query(field, use_subselection=False):
    """Build a minimal query for a candidate field. GraphQL fields that
    return a scalar (String, Int, Boolean, etc.) must be queried as a bare
    leaf with no sub-selection, while fields returning an object type
    require a sub-selection like { __typename }. Stage 1's schema summary
    does not record which kind each field returns, so we default to the
    bare leaf form first and let the caller retry with a sub-selection if
    the server reports one is required."""
    name = field.get("name")
    if use_subselection:
        return f"{{ {name} {{ __typename }} }}"
    return f"{{ {name} }}"


def probe_field(url, field, headers=None):
    """Send a probe query for a field and classify the outcome. Tries the
    bare leaf form first (correct for scalar return types), and retries
    with a { __typename } sub-selection if the server specifically reports
    that a sub-selection is required (correct for object return types)."""
    headers = headers or {}
    headers.setdefault("Content-Type", "application/json")

    query_str = build_probe_query(field, use_subselection=False)
    entry = {
        "field": field.get("name"),
        "args_expected": field.get("args", []),
        "query_sent": query_str,
    }

    resp_data, http_status, request_error = _send_probe(url, query_str, headers)

    if request_error:
        entry["outcome"] = "request_failed"
        entry["notes"] = request_error
        return entry

    entry["http_status"] = http_status

    if resp_data is None:
        entry["outcome"] = "non_json_response"
        return entry

    # If the server says this field needs a sub-selection, it's an object
    # type, retry once with { __typename } instead of treating this as a
    # real rejection.
    error_text_lower = json.dumps(resp_data.get("errors", "")).lower()
    if "errors" in resp_data and "must have a sub selection" in error_text_lower:
        query_str = build_probe_query(field, use_subselection=True)
        entry["query_sent"] = query_str
        resp_data, http_status, request_error = _send_probe(url, query_str, headers)
        if request_error:
            entry["outcome"] = "request_failed"
            entry["notes"] = request_error
            return entry
        entry["http_status"] = http_status
        if resp_data is None:
            entry["outcome"] = "non_json_response"
            return entry

    entry["raw_response"] = resp_data
    _classify_outcome(entry, resp_data)
    return entry


def _send_probe(url, query_str, headers):
    """Send a single GraphQL POST and return (json_data, http_status, error_str)."""
    try:
        resp = requests.post(url, json={"query": query_str}, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return None, None, str(exc)

    try:
        return resp.json(), resp.status_code, None
    except ValueError:
        return None, resp.status_code, None


def _classify_outcome(entry, data):
    """Set entry['outcome'] and related fields based on the response body."""
    has_data = bool(data.get("data")) and any(v is not None for v in (data.get("data") or {}).values())
    has_errors = "errors" in data

    if has_data and not has_errors:
        entry["outcome"] = "data_returned_no_errors"
    elif has_data and has_errors:
        entry["outcome"] = "partial_data_with_errors"
    elif has_errors:
        error_text = json.dumps(data.get("errors"))[:300].lower()
        if "auth" in error_text or "permission" in error_text or "forbidden" in error_text or "unauthorized" in error_text:
            entry["outcome"] = "rejected_auth_required"
        elif "argument" in error_text or "required" in error_text:
            entry["outcome"] = "rejected_missing_arguments"
        else:
            entry["outcome"] = "rejected_other_error"
        entry["error_sample"] = json.dumps(data.get("errors"))[:300]
    else:
        entry["outcome"] = "no_data_no_errors"


def run(url, schema_path, auth_header=None, output_path=None):
    candidates = load_candidate_fields(schema_path)

    print(f"[*] Loaded {len(candidates)} sensitive-looking field(s) from schema to test")
    for c in candidates:
        print(f"    - {c.get('name')} (args: {c.get('args', [])})")

    auth_headers = parse_auth_header(auth_header) if auth_header else None

    findings = []

    for field in candidates:
        field_name = field.get("name")
        print(f"\n[*] Testing field: {field_name}")

        unauth_result = probe_field(url, field, headers=None)
        outcome = unauth_result["outcome"]

        if outcome == "data_returned_no_errors":
            print(f"    [!] UNAUTHENTICATED request returned data with no errors. "
                  f"Potential broken access control on '{field_name}'.")
            unauth_result["flag"] = "potential_broken_access_control"
        elif outcome == "rejected_auth_required":
            print(f"    [+] Correctly rejected unauthenticated request (auth required)")
        elif outcome == "rejected_missing_arguments":
            print(f"    [?] Rejected due to missing arguments, cannot fully assess without valid args")
        else:
            print(f"    [?] Outcome: {outcome}")

        entry = {
            "field": field_name,
            "unauthenticated": unauth_result,
        }

        if auth_headers:
            auth_result = probe_field(url, field, headers=auth_headers)
            entry["authenticated"] = auth_result

            unauth_data = unauth_result.get("raw_response", {}).get("data")
            auth_data = auth_result.get("raw_response", {}).get("data")

            if unauth_data == auth_data and unauth_result["outcome"] == "data_returned_no_errors":
                entry["auth_comparison_note"] = (
                    "Authenticated and unauthenticated responses are identical. "
                    "The provided auth header does not appear to change access to this field."
                )
                print(f"    [!] Authenticated and unauthenticated responses match, "
                      f"auth header may not be enforced on this field.")

        findings.append(entry)

    result = {
        "tool": "gqlrecon",
        "stage": 4,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": url,
        "auth_header_used": bool(auth_headers),
        "candidate_field_count": len(candidates),
        "findings": findings,
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Stage 4 output saved to {output_path}")

    return result


def main():
    parser = argparse.ArgumentParser(description="GQLRecon Stage 4: Field Level Authorization Testing")
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL to test")
    parser.add_argument("--schema", required=True, help="Path to Stage 1 JSON output")
    parser.add_argument("--auth-header", default=None,
                         help="Optional auth header to test as 'Header-Name: value', e.g. 'Authorization: Bearer eyJ...'")
    parser.add_argument("--output", default="../output/stage4_auth.json", help="Path to save JSON output")
    args = parser.parse_args()

    run(url=args.url, schema_path=args.schema, auth_header=args.auth_header, output_path=args.output)


if __name__ == "__main__":
    main()
