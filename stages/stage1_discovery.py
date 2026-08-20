#!/usr/bin/env python3
"""
GQLRecon Stage 1: Schema Discovery

Sends a standard introspection query to a target GraphQL endpoint.
If introspection is disabled, falls back to a wordlist based probe
to find valid GraphQL endpoints and does a lightweight field guess.

Usage:
    python3 stage1_discovery.py --url https://target.com/graphql
    python3 stage1_discovery.py --base https://target.com --wordlist ../wordlists/endpoints.txt
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import requests

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
          defaultValue
        }
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        type { kind name ofType { kind name } }
      }
      interfaces { name }
      enumValues(includeDeprecated: true) { name isDeprecated }
      possibleTypes { name }
    }
    directives {
      name
      description
      locations
      args { name type { kind name } }
    }
  }
}
"""

TIMEOUT = 10


def try_introspection(url, headers=None):
    """Send the introspection query to a single URL. Return parsed schema or None."""
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

    if "errors" in data and "data" not in data:
        return None, "introspection_disabled_or_errors"

    schema = data.get("data", {}).get("__schema")
    if not schema:
        return None, "no_schema_field"

    return schema, None


def parse_schema(raw_schema):
    """Convert raw introspection result into a compact structured summary."""
    query_type = raw_schema.get("queryType", {}) or {}
    mutation_type = raw_schema.get("mutationType", {}) or {}
    subscription_type = raw_schema.get("subscriptionType", {}) or {}

    types = raw_schema.get("types", []) or []

    summary = {
        "query_type_name": query_type.get("name"),
        "mutation_type_name": mutation_type.get("name"),
        "subscription_type_name": subscription_type.get("name"),
        "total_types": len(types),
        "queries": [],
        "mutations": [],
        "subscriptions": [],
        "object_types": [],
    }

    type_lookup = {t.get("name"): t for t in types if t.get("name")}

    def collect_fields(type_name):
        t = type_lookup.get(type_name)
        if not t:
            return []
        fields = t.get("fields") or []
        result = []
        for f in fields:
            result.append({
                "name": f.get("name"),
                "args": [a.get("name") for a in (f.get("args") or [])],
                "deprecated": f.get("isDeprecated", False),
            })
        return result

    if summary["query_type_name"]:
        summary["queries"] = collect_fields(summary["query_type_name"])
    if summary["mutation_type_name"]:
        summary["mutations"] = collect_fields(summary["mutation_type_name"])
    if summary["subscription_type_name"]:
        summary["subscriptions"] = collect_fields(summary["subscription_type_name"])

    for t in types:
        if t.get("kind") == "OBJECT" and not (t.get("name") or "").startswith("__"):
            name = t.get("name")
            if name in (summary["query_type_name"], summary["mutation_type_name"], summary["subscription_type_name"]):
                continue
            summary["object_types"].append({
                "name": name,
                "field_count": len(t.get("fields") or []),
            })

    return summary


def wordlist_probe(base_url, wordlist_path, headers=None):
    """Try each path in the wordlist against the base URL, testing for a GraphQL responder."""
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found: {wordlist_path}")
        return []

    with open(wordlist_path, "r") as f:
        paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    found = []
    probe_query = {"query": "{ __typename }"}
    headers = headers or {}
    headers.setdefault("Content-Type", "application/json")

    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.post(url, json=probe_query, headers=headers, timeout=TIMEOUT)
        except requests.RequestException:
            continue

        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                continue
            if "data" in data and isinstance(data.get("data"), dict) and "__typename" in data.get("data", {}):
                found.append(url)
                print(f"    [+] GraphQL endpoint confirmed: {url}")
            elif "errors" in data:
                # Endpoint exists and speaks GraphQL, but the query itself errored
                found.append(url)
                print(f"    [+] Likely GraphQL endpoint (error response): {url}")

    return found


def run(target_url=None, base_url=None, wordlist_path=None, headers=None, output_path=None):
    result = {
        "tool": "gqlrecon",
        "stage": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "introspection_enabled": False,
        "schema_summary": None,
        "fallback_endpoints_found": [],
        "notes": [],
    }

    if target_url:
        print(f"[*] Trying introspection on {target_url}")
        raw_schema, err = try_introspection(target_url, headers)
        if raw_schema:
            result["introspection_enabled"] = True
            result["schema_summary"] = parse_schema(raw_schema)
            print(f"[+] Introspection enabled. Found {len(result['schema_summary']['queries'])} queries, "
                  f"{len(result['schema_summary']['mutations'])} mutations, "
                  f"{result['schema_summary']['total_types']} total types.")
        else:
            result["notes"].append(f"introspection_failed: {err}")
            print(f"[-] Introspection failed or disabled ({err})")

            if base_url and wordlist_path:
                print(f"[*] Falling back to wordlist probe against {base_url}")
                found = wordlist_probe(base_url, wordlist_path, headers)
                result["fallback_endpoints_found"] = found
                if found:
                    print(f"[*] Retrying introspection against {len(found)} discovered endpoint(s)")
                    for ep in found:
                        raw_schema, err2 = try_introspection(ep, headers)
                        if raw_schema:
                            result["introspection_enabled"] = True
                            result["target_url"] = ep
                            result["schema_summary"] = parse_schema(raw_schema)
                            print(f"[+] Introspection succeeded on fallback endpoint: {ep}")
                            break
                else:
                    print("[-] No confirmed GraphQL endpoints found via wordlist")
    elif base_url and wordlist_path:
        print(f"[*] No direct URL given. Probing {base_url} with wordlist.")
        found = wordlist_probe(base_url, wordlist_path, headers)
        result["fallback_endpoints_found"] = found
        for ep in found:
            raw_schema, err2 = try_introspection(ep, headers)
            if raw_schema:
                result["introspection_enabled"] = True
                result["target_url"] = ep
                result["schema_summary"] = parse_schema(raw_schema)
                print(f"[+] Introspection succeeded on: {ep}")
                break
    else:
        print("[!] You must provide either --url or (--base and --wordlist)")
        sys.exit(1)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[*] Stage 1 output saved to {output_path}")

    return result


def main():
    parser = argparse.ArgumentParser(description="GQLRecon Stage 1: Schema Discovery")
    parser.add_argument("--url", help="Direct GraphQL endpoint URL to test")
    parser.add_argument("--base", help="Base URL to probe with the wordlist if --url is not known or fails")
    parser.add_argument("--wordlist", default="../wordlists/endpoints.txt", help="Path to endpoint wordlist")
    parser.add_argument("--output", default="../output/stage1_schema.json", help="Path to save JSON output")
    args = parser.parse_args()

    run(
        target_url=args.url,
        base_url=args.base,
        wordlist_path=args.wordlist,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
