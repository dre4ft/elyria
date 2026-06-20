# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Request Graph — tracks discovered endpoints and their relationships
during pentest scanning. Feeds both deterministic and AI scanners
with systematic coverage awareness.
"""

import re
import json
from urllib.parse import urljoin, urlparse


class RequestGraph:
    """Lightweight graph of API endpoints and their relationships."""

    def __init__(self):
        self.nodes = {}          # key=(method,path) -> {status, params, content_type, body_sample}
        self.edges = []          # (source_key, target_key, rel_type, evidence)
        self._seen_ids = set()   # IDs extracted from responses
        self._param_names = set()  # param names discovered

    # ── Node management ──

    def add_request(self, method, path, status, response_body="", request_params=None,
                    response_headers=None, content_type=""):
        """Record a request/response as a node in the graph."""
        key = (method.upper(), path)
        existing = self.nodes.get(key)
        if existing:
            existing["statuses"].add(status)
            if response_body and not existing.get("body_sample"):
                existing["body_sample"] = response_body[:500]
        else:
            self.nodes[key] = {
                "statuses": {status},
                "params": request_params or {},
                "content_type": content_type or "",
                "body_sample": (response_body or "")[:500],
            }
        # Extract relationships from the response
        self._extract_relations(method, path, response_body, response_headers or {})

    def add_discovered(self, method, path, status, snippet=""):
        """Record a discovered but not-yet-tested endpoint."""
        key = (method.upper(), path)
        if key not in self.nodes:
            self.nodes[key] = {
                "statuses": {status},
                "params": {},
                "content_type": "",
                "body_sample": snippet[:200],
            }

    # ── Relationship extraction ──

    def _extract_relations(self, source_method, source_path, body, headers):
        """Extract relationships from a response body and headers."""
        source_key = (source_method.upper(), source_path)
        if not body:
            return

        # Extract IDs from JSON responses
        self._extract_ids_from_body(body)

        # Extract links from JSON (HATEOAS-style _links, related resources)
        self._extract_links(source_key, body)

        # Extract from Location header (redirects)
        loc = headers.get("Location", headers.get("location", ""))
        if loc:
            parsed = urlparse(loc)
            target = parsed.path or "/"
            if target != source_path:
                self.add_edge(source_key, ("GET", target), "redirect")

        # Extract from Link header
        link_h = headers.get("Link", headers.get("link", ""))
        for m in re.finditer(r'<([^>]+)>', link_h):
            parsed = urlparse(m.group(1))
            target = parsed.path or "/"
            if target != source_path:
                self.add_edge(source_key, ("GET", target), "link_header")

    def _extract_ids_from_body(self, body):
        """Extract ID-like values from JSON body for BOLA testing."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return
        self._walk_json(data, "")

    def _walk_json(self, obj, prefix):
        """Recursively walk JSON to find ID fields and nested resource references."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                self._param_names.add(k)
                if self._is_id_field(k) and isinstance(v, (str, int)):
                    self._seen_ids.add(str(v))
                if k in ("id", "uuid", "user_id", "team_id", "project_id", "resource_id",
                         "owner_id", "account_id", "order_id", "product_id", "item_id",
                         "file_id", "document_id", "group_id", "role_id", "tenant_id",
                         "organization_id", "customer_id", "subscription_id", "token_id"):
                    self._seen_ids.add(str(v))
                self._walk_json(v, full_key)
        elif isinstance(obj, list):
            for item in (obj[:5] if len(obj) > 5 else obj):
                self._walk_json(item, prefix)

    def _is_id_field(self, name):
        return name.lower().endswith("_id") or name.lower() in (
            "id", "uuid", "slug", "key", "ref", "code"
        )

    def _extract_links(self, source_key, body):
        """Extract resource links from body (HATEOAS, nested URLs, resource references)."""
        # _links / links patterns
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return
        links_obj = data.get("_links", data.get("links", {}))
        if isinstance(links_obj, dict):
            for rel, link_info in links_obj.items():
                if isinstance(link_info, dict):
                    href = link_info.get("href", "")
                    if href and not href.startswith("http"):
                        self.add_edge(source_key, ("GET", href), f"link:{rel}")

        # URL patterns in string values
        body_str = str(body)
        for m in re.finditer(r'"(/[a-zA-Z][^"]*)"', body_str):
            candidate = m.group(1)
            if candidate.count("/") >= 2 and len(candidate) < 200:
                self.add_edge(source_key, ("GET", candidate), "nested_url")

    def add_edge(self, source, target, rel_type):
        """Add a relationship edge between two endpoints."""
        if source != target:
            self.edges.append((source, target, rel_type, ""))

    # ── Query methods ──

    def get_tested_endpoints(self):
        """Return set of (method, path) that have been tested."""
        return set(self.nodes.keys())

    def get_unexplored_paths(self):
        """Return paths discovered via edges but not yet tested."""
        tested = {k[1] for k in self.nodes}
        unexplored = set()
        for _, target, _, _ in self.edges:
            if target[1] not in tested:
                unexplored.add(target)
        return sorted(unexplored)

    def get_discovered_ids(self):
        """Return IDs extracted from responses for BOLA cross-referencing."""
        return sorted(self._seen_ids)

    def get_high_value_targets(self):
        """Return endpoints that returned interesting status codes for deeper testing."""
        targets = []
        for (method, path), info in self.nodes.items():
            statuses = info.get("statuses", set())
            if statuses & {200, 201, 202, 301, 302, 401, 403, 405}:
                targets.append((method, path, statuses))
        return targets

    # ── Context generation ──

    def to_context_block(self):
        """Generate a compact context block for the AI scanner."""
        parts = []
        tested = self.get_tested_endpoints()
        parts.append(f"## Request coverage graph ({len(tested)} endpoints tested)")

        # Endpoints by method
        by_method = {}
        for method, path in tested:
            by_method.setdefault(method, []).append(path)
        for method in sorted(by_method):
            paths = by_method[method][:15]
            parts.append(f"  {method}: {', '.join(paths)}")

        # Unexplored targets
        unexplored = self.get_unexplored_paths()
        if unexplored:
            sample = unexplored[:15]
            parts.append(f"\nUnexplored paths (discovered from responses — prioritize!): {', '.join(p[1] for p in sample)}")

        # Extracted IDs
        ids = self.get_discovered_ids()
        if ids:
            parts.append(f"\nDiscovered resource IDs: {', '.join(ids[:20])}")

        # Untested methods on known paths
        tested_paths = {k[1] for k in tested}
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        untested_methods = []
        for path in sorted(tested_paths)[:10]:
            for m in methods:
                if (m, path) not in tested:
                    untested_methods.append(f"{m} {path}")
        if untested_methods:
            parts.append(f"\nUntested methods on known paths: {', '.join(untested_methods[:15])}")

        return "\n".join(parts)


# ── Wordlist for fallback when no OpenAPI provided ──

DEFAULT_WORDLIST = [
    # Generic API
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/playground",
    "/docs", "/api-docs", "/swagger.json", "/openapi.json", "/swagger-ui.html",
    "/.well-known/jwks.json", "/.well-known/openid-configuration",
    # Auth
    "/api/auth/login", "/api/auth/register", "/api/auth/refresh", "/api/auth/logout",
    "/api/login", "/api/register", "/api/signin", "/api/signup",
    "/oauth/token", "/oauth/authorize", "/oauth/callback",
    # CRUD resources
    "/api/users", "/api/users/1", "/api/users/me", "/api/users/profile",
    "/api/accounts", "/api/accounts/1",
    "/api/teams", "/api/teams/1",
    "/api/projects", "/api/projects/1",
    "/api/orders", "/api/orders/1",
    "/api/products", "/api/products/1",
    "/api/items", "/api/items/1",
    "/api/tasks", "/api/tasks/1",
    "/api/files", "/api/files/1",
    "/api/documents", "/api/documents/1",
    "/api/posts", "/api/posts/1",
    "/api/comments", "/api/comments/1",
    "/api/notifications", "/api/notifications/1",
    "/api/settings", "/api/config", "/api/configuration",
    "/api/search", "/api/upload", "/api/download",
    "/api/webhooks", "/api/callbacks", "/api/events",
    "/api/admin", "/api/admin/users", "/api/admin/stats", "/api/admin/config",
    "/api/health", "/api/status", "/api/ping", "/api/metrics",
    "/api/wallet", "/api/wallet/balance", "/api/wallet/transfer",
    "/api/payments", "/api/payments/1",
    "/api/checkout", "/api/cart",
    "/api/coupons", "/api/coupons/validate", "/api/promos",
    "/api/subscriptions", "/api/subscriptions/1",
    "/api/invoices", "/api/invoices/1",
    # Common frameworks
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/.env", "/debug", "/console", "/phpinfo.php",
    "/.git/config", "/.git/HEAD",
    "/robots.txt", "/sitemap.xml", "/security.txt",
    # Internal
    "/internal", "/internal/health", "/internal/status",
    "/private", "/hidden",
    "/api/internal", "/api/system",
]
