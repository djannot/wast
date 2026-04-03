#!/usr/bin/env python3
"""Fetch all MCP servers from the official MCP Registry.

Uses cursor-based pagination on the v0.1 API (frozen/stable).
Outputs a JSON file with all servers and prints a summary to stderr.
"""

import json
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode, quote

BASE_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"
PAGE_SIZE = 100
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds, doubles on each retry
OUTPUT_FILE = "mcp_servers.json"


def fetch_page(cursor: str | None = None, limit: int = PAGE_SIZE) -> dict:
    params = {"limit": str(limit)}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}?{urlencode(params)}"

    req = Request(url, headers={"Accept": "application/json", "User-Agent": "wast/0.1"})

    delay = RETRY_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except (HTTPError, URLError, TimeoutError) as e:
            print(f"  [attempt {attempt}/{MAX_RETRIES}] {e}", file=sys.stderr)
            if attempt < MAX_RETRIES:
                time.sleep(delay)
                delay *= 2
            else:
                raise


def fetch_all_servers() -> list[dict]:
    all_servers = []
    cursor = None
    page = 0

    while True:
        page += 1
        data = fetch_page(cursor)

        servers = data.get("servers", [])
        all_servers.extend(servers)

        metadata = data.get("metadata", {})
        count = metadata.get("count", len(servers))
        next_cursor = metadata.get("nextCursor")

        print(f"  page {page}: got {count} entries (total so far: {len(all_servers)})", file=sys.stderr)

        if not next_cursor or not servers:
            break

        cursor = next_cursor
        time.sleep(0.2)  # be polite

    return all_servers


def summarize(servers: list[dict]) -> None:
    latest_only = [s for s in servers if s.get("_meta", {})
                   .get("io.modelcontextprotocol.registry/official", {})
                   .get("isLatest", False)]

    remote_servers = []
    for s in latest_only:
        remotes = s.get("server", {}).get("remotes", [])
        if remotes:
            remote_servers.append(s)

    transport_types: dict[str, int] = {}
    for s in latest_only:
        for r in s.get("server", {}).get("remotes", []):
            t = r.get("type", "unknown")
            transport_types[t] = transport_types.get(t, 0) + 1
        for p in s.get("server", {}).get("packages", []):
            t = p.get("transport", {}).get("type", "unknown")
            transport_types[t] = transport_types.get(t, 0) + 1

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  Total entries (all versions):  {len(servers)}", file=sys.stderr)
    print(f"  Latest versions only:          {len(latest_only)}", file=sys.stderr)
    print(f"  With remote endpoint (latest):  {len(remote_servers)}", file=sys.stderr)
    print(f"  Transport types (latest):       {transport_types}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)


def main():
    print(f"Fetching all servers from {BASE_URL} ...", file=sys.stderr)
    servers = fetch_all_servers()

    summarize(servers)

    with open(OUTPUT_FILE, "w") as f:
        json.dump({"servers": servers, "count": len(servers)}, f, indent=2)
    print(f"Saved {len(servers)} entries to {OUTPUT_FILE}", file=sys.stderr)

    # Also extract just the remote URLs for quick scanning
    remotes_file = "mcp_remote_endpoints.json"
    endpoints = []
    seen = set()
    for s in servers:
        meta = s.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
        if not meta.get("isLatest", False):
            continue
        server = s.get("server", {})
        for r in server.get("remotes", []):
            url = r.get("url", "")
            if url and url not in seen:
                seen.add(url)
                endpoints.append({
                    "name": server.get("name", ""),
                    "description": server.get("description", ""),
                    "transport": r.get("type", ""),
                    "url": url,
                })

    with open(remotes_file, "w") as f:
        json.dump(endpoints, f, indent=2)
    print(f"Saved {len(endpoints)} unique remote endpoints to {remotes_file}", file=sys.stderr)


if __name__ == "__main__":
    main()