#!/usr/bin/env python3
"""
GQLRecon Stage 3: Depth and Complexity Fuzzing

Tests whether a GraphQL endpoint enforces a query depth limit. It does this
by finding a field that refers back to its own type (directly or through a
short cycle), then building queries that nest that field increasingly
deeply, sending each one and recording whether the server accepts it,
errors out, or times out.

A server with no depth limiting will keep accepting deeper and deeper
queries until it times out or crashes, which is the resource exhaustion
risk this stage is measuring.

Usage:
    python3 stage3_depth.py --url http://localhost:5013/graphql
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

TIMEOUT = 10
DEFAULT_DEPTHS = [5, 10, 20, 35, 50, 75, 100]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    types {
      kind
      name
      fields {
        name
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType { kind name }
            }
          }
        }
      }
    }
  }
}
"""


def fetch_full_schema(url, headers=None):
    headers = headers or {}
    headers.setdefault("Content-Type", "application/json")
    try:
        resp = requests.post(
            url,
            json={"query": INTROSPECTION_QUERY, "operationName": "IntrospectionQuery"},
            headers=headers,
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, f"request_failed: {exc}"

    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"

    try:
        data = resp.json()
    except ValueError:
        return None, "non_json_response"

    schema = data.get("data", {}).get("__schema")
    if not schema:
        return None, "introspection_disabled_or_errors"

    return schema, None


def unwrap_type_name(type_obj):
    """Peel NON_NULL and LIST wrappers off a GraphQL type reference to get
    the actual named type underneath."""
    current = type_obj
    depth_guard = 0
    while current and current.get("name") is None and depth_guard < 10:
        current = current.get("ofType")
        depth_guard += 1
    return current.get("name") if current else None


def build_field_graph(raw_schema):
    """
    Build a mapping of type_name -> {field_name: return_type_name} for all
    object types, so we can find fields that create a cycle back to their
    own type or an ancestor type.
    """
    graph = {}
    for t in raw_schema.get("types", []) or []:
        if t.get("kind") != "OBJECT":
            continue
        name = t.get("name")
        if not name or name.startswith("__"):
            continue
        fields = t.get("fields") or []
        field_map = {}
        for f in fields:
            return_type = unwrap_type_name(f.get("type") or {})
            if return_type:
                field_map[f.get("name")] = return_type
        graph[name] = field_map
    return graph


def find_self_referencing_field(raw_schema):
    """
    Search starting from the Query type for a nesting path that eventually
    cycles back to a type it already visited. Checks direct self loops
    first (type X has a field returning X), then two hop cycles (type A
    has a field returning B, and B has a field returning A), since many
    real schemas model relationships this way (e.g. Paste -> owner -> User,
    User -> pastes -> Paste) rather than a single type referencing itself.

    Returns a tuple of (query_field_name, [repeat_field_names]) where
    repeat_field_names is the list of field names to cycle through when
    building the nested query, or (None, None) if nothing suitable found.
    """
    query_type_name = (raw_schema.get("queryType") or {}).get("name")
    if not query_type_name:
        return None, None

    graph = build_field_graph(raw_schema)
    query_fields = graph.get(query_type_name, {})

    # Pass 1: direct self loop, type A has a field that returns A
    for field_name, return_type in query_fields.items():
        nested_fields = graph.get(return_type, {})
        for nested_name, nested_return in nested_fields.items():
            if nested_return == return_type:
                return field_name, [nested_name]

    # Pass 2: two hop cycle, type A -> field -> type B -> field -> type A
    for field_name, type_a in query_fields.items():
        fields_on_a = graph.get(type_a, {})
        for a_field_name, type_b in fields_on_a.items():
            if type_b == type_a:
                continue  # already covered by pass 1
            fields_on_b = graph.get(type_b, {})
            for b_field_name, type_c in fields_on_b.items():
                if type_c == type_a:
                    return field_name, [a_field_name, b_field_name]

    return None, None


def build_nested_query(entry_field, repeat_fields, depth):
    """Build a query string nesting through `repeat_fields` (cycled in
    order, always starting with repeat_fields[0] as the outermost field)
    `depth` levels deep inside `entry_field`, terminating with __typename
    at the bottom.

    The field sequence is built outer to inner first, then nested from the
    inside out, so the outermost field is always repeat_fields[0]
    regardless of the requested depth. Building it the other way around
    (cycling while nesting inner to outer) makes the outermost field
    depend on whether depth is odd or even, which breaks alternating
    cycles like A -> B -> A -> B by sometimes placing field B where field
    A is required.
    """
    sequence = [repeat_fields[i % len(repeat_fields)] for i in range(depth)]
    inner = "__typename"
    for field in reversed(sequence):
        inner = f"{field} {{ {inner} }}"
    return f"{{ {entry_field} {{ {inner} }} }}"


def test_depth(url, entry_field, repeat_fields, depths, headers=None):
    headers = headers or {}
    headers.setdefault("Content-Type", "application/json")

    results = []
    max_accepted_depth = 0
    server_enforces_limit = False

    for depth in depths:
        query_str = build_nested_query(entry_field, repeat_fields, depth)
        entry = {"depth": depth}

        start = time.time()
        try:
            resp = requests.post(
                url,
                json={"query": query_str},
                headers=headers,
                timeout=TIMEOUT,
            )
            elapsed = time.time() - start
            entry["elapsed_seconds"] = round(elapsed, 2)
            entry["http_status"] = resp.status_code

            try:
                data = resp.json()
            except ValueError:
                entry["outcome"] = "non_json_response"
                results.append(entry)
                continue

            if "errors" in data and not data.get("data"):
                error_text = str(data.get("errors"))[:300]
                depth_related_hints = ["depth", "complexity", "too deep", "nested", "limit"]
                looks_like_depth_limit = any(hint in error_text.lower() for hint in depth_related_hints)

                entry["error_sample"] = error_text
                if looks_like_depth_limit:
                    entry["outcome"] = "rejected_by_server"
                    server_enforces_limit = True
                else:
                    entry["outcome"] = "rejected_non_depth_related"
                    entry["notes"] = (
                        "Server rejected this query, but the error does not look "
                        "depth or complexity related. This may be a query "
                        "construction issue rather than a real depth limit finding."
                    )
                results.append(entry)
                break
            else:
                entry["outcome"] = "accepted"
                max_accepted_depth = depth
                results.append(entry)

        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            entry["elapsed_seconds"] = round(elapsed, 2)
            entry["outcome"] = "timeout"
            entry["notes"] = "server_did_not_respond_possible_resource_exhaustion"
            results.append(entry)
            break
        except requests.RequestException as exc:
            entry["outcome"] = "request_failed"
            entry["notes"] = str(exc)
            results.append(entry)
            break

    return {
        "depths_tested": results,
        "max_accepted_depth": max_accepted_depth,
        "server_enforces_depth_limit": server_enforces_limit,
    }


def run(url, depths=None, headers=None, output_path=None):
    depths = depths or DEFAULT_DEPTHS

    print(f"[*] Fetching schema from {url} to find a self referencing field")
    raw_schema, err = fetch_full_schema(url, headers)

    result = {
        "tool": "gqlrecon",
        "stage": 3,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": url,
        "entry_field": None,
        "repeat_fields": None,
        "depth_test": None,
        "notes": [],
    }

    if not raw_schema:
        print(f"[-] Could not fetch schema: {err}")
        result["notes"].append(f"schema_fetch_failed: {err}")
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2)
        return result

    entry_field, repeat_fields = find_self_referencing_field(raw_schema)

    if not entry_field:
        print("[-] No self referencing field or cycle found in schema, cannot build a depth test query")
        result["notes"].append("no_self_referencing_field_found")
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2)
        return result

    cycle_desc = " -> ".join(repeat_fields + [repeat_fields[0]])
    print(f"[+] Found nesting cycle: {entry_field} -> {cycle_desc} -> ...")
    result["entry_field"] = entry_field
    result["repeat_fields"] = repeat_fields

    print(f"[*] Testing depths: {depths}")
    depth_result = test_depth(url, entry_field, repeat_fields, depths, headers)
    result["depth_test"] = depth_result

    for entry in depth_result["depths_tested"]:
        depth = entry["depth"]
        outcome = entry["outcome"]
        if outcome == "accepted":
            print(f"    [+] Depth {depth}: accepted ({entry.get('elapsed_seconds')}s)")
        elif outcome == "rejected_by_server":
            print(f"    [-] Depth {depth}: rejected by server (depth limit likely enforced)")
        elif outcome == "rejected_non_depth_related":
            print(f"    [?] Depth {depth}: rejected, but error doesn't look depth related, "
                  f"possible query construction issue: {entry.get('error_sample')}")
        elif outcome == "timeout":
            print(f"    [!] Depth {depth}: TIMEOUT after {entry.get('elapsed_seconds')}s, "
                  f"possible resource exhaustion risk")
        else:
            print(f"    [?] Depth {depth}: {outcome}")

    if not depth_result["server_enforces_depth_limit"] and depth_result["max_accepted_depth"] >= max(depths[:1]):
        print(f"[!] No depth limit detected up to depth {depth_result['max_accepted_depth']}. "
              f"This is a resource exhaustion risk, worth manual follow up with deeper queries.")

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[*] Stage 3 output saved to {output_path}")

    return result


def main():
    parser = argparse.ArgumentParser(description="GQLRecon Stage 3: Depth and Complexity Fuzzing")
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL to test")
    parser.add_argument("--depths", default=None,
                         help="Comma separated list of depths to test, e.g. 5,10,20,50")
    parser.add_argument("--output", default="../output/stage3_depth.json", help="Path to save JSON output")
    args = parser.parse_args()

    depths = None
    if args.depths:
        depths = [int(d.strip()) for d in args.depths.split(",")]

    run(url=args.url, depths=depths, output_path=args.output)


if __name__ == "__main__":
    main()
