#!/usr/bin/env python3
"""
GQLRecon Stage 2: Batching and Alias Abuse Testing

Tests whether a GraphQL endpoint is vulnerable to two common rate limit
bypass techniques:

1. Batching abuse: sending an array of multiple queries in a single HTTP
   POST request. Many rate limiters count HTTP requests, not the number of
   operations inside them, so batching can let an attacker execute many
   queries while only "using up" one rate limit slot.

2. Alias abuse: using GraphQL aliases to repeat the same field many times
   inside a single query. Like batching, this can let an attacker fetch or
   trigger a field many times in what looks like one normal request.

This stage does not exploit anything, it only measures whether the server
accepts and executes these patterns, which indicates the underlying risk.

Usage:
    python3 stage2_batching.py --url http://localhost:5013/graphql
    python3 stage2_batching.py --schema ../output/stage1_schema.json --url http://localhost:5013/graphql
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

TIMEOUT = 10
DEFAULT_BATCH_SIZE = 10
DEFAULT_ALIAS_COUNT = 20


def pick_safe_query_field(schema_summary):
    """
    Pick a simple, low risk query field from Stage 1's schema output to use
    as the probe field for batching and alias tests. Prefers fields with no
    required-looking args so the probe doesn't fail purely on missing args.
    """
    if not schema_summary:
        return None
    queries = schema_summary.get("queries") or []
    if not queries:
        return None

    # Prefer a field with zero args, since we don't know which args are
    # required vs optional from this summary alone.
    no_arg_fields = [q for q in queries if not q.get("args")]
    if no_arg_fields:
        return no_arg_fields[0]["name"]

    # Fall back to the first query field even if it has args; the probe
    # may return an error, but that still tells us whether the request
    # itself was processed (batching/alias accepted) vs rejected outright.
    return queries[0]["name"]


def test_batching(url, field_name, batch_size, headers=None):
    """
    Send a JSON array of `batch_size` identical simple queries in a single
    HTTP POST. If the server returns an array of `batch_size` results, it
    supports batching.
    """
    headers = headers or {}
    headers.setdefault("Content-Type", "application/json")

    query = {"query": "{ __typename }"}
    if field_name:
        query = {"query": "{ __typename }"}  # keep probe minimal and safe

    batch_payload = [query for _ in range(batch_size)]

    result = {
        "test": "batching",
        "batch_size_sent": batch_size,
        "supported": False,
        "notes": [],
    }

    try:
        resp = requests.post(url, json=batch_payload, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as exc:
        result["notes"].append(f"request_failed: {exc}")
        return result

    result["http_status"] = resp.status_code

    if resp.status_code != 200:
        result["notes"].append(f"non_200_status: {resp.status_code}")
        return result

    try:
        data = resp.json()
    except ValueError:
        result["notes"].append("non_json_response")
        return result

    if isinstance(data, list):
        result["supported"] = True
        result["responses_returned"] = len(data)
        if len(data) == batch_size:
            result["notes"].append("server_processed_full_batch")
        else:
            result["notes"].append("server_processed_partial_batch")
    else:
        result["notes"].append("server_did_not_return_array_likely_no_batching_support")

    return result


def test_alias_abuse(url, field_name, alias_count, headers=None):
    """
    Send a single query that repeats `field_name` (or __typename as a safe
    default) using GraphQL aliases `f0` through `fN`. If the server returns
    that many aliased results, it processed all of them in one request,
    which is the alias abuse pattern.
    """
    headers = headers or {}
    headers.setdefault("Content-Type", "application/json")

    # __typename is always safe and lightweight, it exists on every type and
    # does no real work server side. Prefer it for the alias test regardless
    # of what Stage 1 picked as the general probe field, since alias abuse
    # tests repeat the field many times and a heavy field would give a
    # misleading result (timeout instead of a clean signal).
    target_field = "__typename"

    aliased_fields = "\n  ".join(
        f"f{i}: {target_field}" for i in range(alias_count)
    )
    query_str = f"{{\n  {aliased_fields}\n}}"

    result = {
        "test": "alias_abuse",
        "alias_count_sent": alias_count,
        "field_used": target_field,
        "supported": False,
        "notes": [],
    }

    try:
        resp = requests.post(
            url,
            json={"query": query_str},
            headers=headers,
            timeout=TIMEOUT,
        )
    except requests.exceptions.Timeout:
        result["notes"].append("request_timed_out")
        result["possible_resource_exhaustion"] = True
        result["notes"].append(
            f"server_did_not_respond_within_{TIMEOUT}s_when_repeating_"
            f"'{target_field}'_{alias_count}_times_this_may_indicate_a_"
            f"resource_exhaustion_risk_rather_than_lack_of_alias_support"
        )
        return result
    except requests.RequestException as exc:
        result["notes"].append(f"request_failed: {exc}")
        return result

    result["http_status"] = resp.status_code

    if resp.status_code != 200:
        result["notes"].append(f"non_200_status: {resp.status_code}")
        return result

    try:
        data = resp.json()
    except ValueError:
        result["notes"].append("non_json_response")
        return result

    returned_data = data.get("data")
    if isinstance(returned_data, dict):
        aliases_returned = len(returned_data.keys())
        result["aliases_returned"] = aliases_returned
        if aliases_returned == alias_count:
            result["supported"] = True
            result["notes"].append("server_resolved_all_aliases_in_one_request")
        elif aliases_returned > 0:
            result["supported"] = True
            result["notes"].append("server_resolved_some_aliases_partial_support")
    if "errors" in data and not returned_data:
        result["notes"].append("server_rejected_query_outright")

    return result


def run(url, schema_path=None, batch_size=DEFAULT_BATCH_SIZE,
        alias_count=DEFAULT_ALIAS_COUNT, headers=None, output_path=None):

    schema_summary = None
    if schema_path and os.path.exists(schema_path):
        with open(schema_path, "r") as f:
            stage1_data = json.load(f)
        schema_summary = stage1_data.get("schema_summary")

    probe_field = pick_safe_query_field(schema_summary)

    print(f"[*] Using probe field: {probe_field or '__typename (default)'}")

    print(f"[*] Testing batching with {batch_size} queries in one request")
    batching_result = test_batching(url, probe_field, batch_size, headers)
    if batching_result["supported"]:
        print(f"    [+] Batching appears SUPPORTED "
              f"({batching_result.get('responses_returned')} of {batch_size} responses returned)")
    else:
        print(f"    [-] Batching does not appear supported ({', '.join(batching_result['notes'])})")

    print(f"[*] Testing alias abuse with {alias_count} aliased fields in one query")
    alias_result = test_alias_abuse(url, probe_field, alias_count, headers)
    if alias_result["supported"]:
        print(f"    [+] Alias abuse appears SUPPORTED "
              f"({alias_result.get('aliases_returned')} of {alias_count} aliases resolved)")
    elif alias_result.get("possible_resource_exhaustion"):
        print(f"    [!] Request timed out repeating '{alias_result.get('field_used')}' "
              f"{alias_count} times. This may indicate a RESOURCE EXHAUSTION risk, "
              f"not simply an unsupported feature. Worth manual follow up.")
    else:
        print(f"    [-] Alias abuse does not appear supported ({', '.join(alias_result['notes'])})")

    result = {
        "tool": "gqlrecon",
        "stage": 2,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": url,
        "probe_field_used": probe_field,
        "batching": batching_result,
        "alias_abuse": alias_result,
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[*] Stage 2 output saved to {output_path}")

    return result


def main():
    parser = argparse.ArgumentParser(description="GQLRecon Stage 2: Batching and Alias Abuse Testing")
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL to test")
    parser.add_argument("--schema", default="../output/stage1_schema.json",
                         help="Path to Stage 1 JSON output, used to pick a safe probe field")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                         help="Number of queries to send in one batched request")
    parser.add_argument("--alias-count", type=int, default=DEFAULT_ALIAS_COUNT,
                         help="Number of aliased fields to send in one query")
    parser.add_argument("--output", default="../output/stage2_batching.json", help="Path to save JSON output")
    args = parser.parse_args()

    run(
        url=args.url,
        schema_path=args.schema,
        batch_size=args.batch_size,
        alias_count=args.alias_count,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
