from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse


def _contains_any(value: str, needles: Set[str]) -> bool:
    return any(token in value for token in needles)


def scan_endpoint(endpoint: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """
    Passively map possible attack vectors based on endpoint metadata.
    This is a heuristic mapper and does not perform exploitation.
    """
    context = context or {}
    headers = {str(k).lower(): str(v) for k, v in (context.get("headers") or {}).items()}
    has_header_context = bool(headers)

    url = str(endpoint.get("url") or "")
    method = str(endpoint.get("method") or "GET").upper()
    endpoint_types = {str(t).lower() for t in (endpoint.get("endpoint_types") or [])}
    has_csrf_token = bool(endpoint.get("has_csrf_token"))

    parsed = urlparse(url)
    path = parsed.path.lower()
    host = parsed.netloc.lower()
    params = {k.lower(): v for k, v in parse_qs(parsed.query).items()}
    param_names = set(params.keys())
    full_lower = url.lower()

    vectors: List[Dict[str, str]] = []
    seen: Set[str] = set()

    def add(category: str, vector: str, reason: str) -> None:
        key = f"{category}:{vector}"
        if key in seen:
            return
        seen.add(key)
        vectors.append({"category": category, "vector": vector, "reason": reason})

    injection_like_params = {
        "id",
        "user",
        "uid",
        "q",
        "query",
        "search",
        "filter",
        "sort",
        "name",
        "email",
        "input",
    }
    redirect_like_params = {"next", "redirect", "return", "url", "uri", "dest", "target", "callback"}
    file_like_params = {"file", "path", "filename", "dir", "folder", "download"}
    command_like_params = {"cmd", "exec", "command", "shell", "run", "process"}
    token_like_params = {"token", "jwt", "access_token", "refresh_token", "session"}
    proto_pollution_params = {"__proto__", "prototype", "constructor"}

    # Injection
    if param_names.intersection(injection_like_params) or _contains_any(path, {"search", "query", "filter"}):
        add("Injection", "SQL Injection", "Queryable user-controlled inputs were detected.")
        add("Injection", "XSS (Cross-Site Scripting)", "User-controlled inputs may be reflected or rendered in the UI.")

    if _contains_any(path, {"xml", "soap", "wsdl"}):
        add("Injection", "XXE Injection", "XML-related endpoint pattern detected.")

    if param_names.intersection({"template", "view", "theme", "engine", "layout"}) or _contains_any(
        path, {"template", "render"}
    ):
        add("Injection", "SSTI", "Template-related inputs were detected.")

    if param_names.intersection({"where", "regex", "gt", "lt", "ne", "in"}) or (
        "api" in endpoint_types and "filter" in param_names
    ):
        add("Injection", "NoSQL Injection", "Structured filtering parameters suggest backend query construction.")

    if param_names.intersection(command_like_params) or _contains_any(path, {"exec", "shell", "command", "system"}):
        add("Injection", "OS Command Injection", "Command-like parameters or execution paths were detected.")

    if param_names.intersection(redirect_like_params):
        add("Injection", "Host Header Injection", "Redirect/URL parameters may be influenced by user input.")

    # Authentication and access
    if _contains_any(path, {"login", "signin", "auth", "token", "password", "session", "sso"}):
        add("Authentication and Access", "Authentication bypass risks", "Authentication-related routes were detected.")
        add("Infrastructure", "Brute force vectors", "Authentication endpoints are usually brute-force targets.")

    if _contains_any(path, {"admin", "manage", "internal", "staff", "role", "permission"}):
        add("Authentication and Access", "Access control weaknesses", "Privileged route patterns were detected.")

    if _contains_any(path, {"oauth", "oidc", "sso"}) or param_names.intersection({"client_id", "redirect_uri", "scope"}):
        add("Authentication and Access", "OAuth misconfiguration", "OAuth/OIDC parameters were detected.")

    if token_like_params.intersection(param_names) or _contains_any(path, {"jwt", "token"}):
        add("Authentication and Access", "JWT vulnerabilities", "Token-bearing parameters or paths were detected.")

    # Web security
    if method in {"POST", "PUT", "PATCH", "DELETE"} and "form" in endpoint_types and not has_csrf_token:
        add("Web Security", "CSRF", "State-changing form endpoint was seen without a detectable CSRF token field.")

    if has_header_context:
        csp = headers.get("content-security-policy", "").lower()
        xfo = headers.get("x-frame-options", "").lower()
        if "deny" not in xfo and "sameorigin" not in xfo and "frame-ancestors" not in csp:
            add("Web Security", "Clickjacking", "Frame protection headers were not detected.")

    if "js-route" in endpoint_types or "api" in endpoint_types:
        add("Web Security", "DOM-based vulnerabilities", "Client-side route/API patterns were discovered.")

    if has_header_context:
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao.strip() == "*" or (acao.strip() == "*" and acac == "true"):
            add("Web Security", "CORS misconfiguration", "Permissive CORS response patterns were detected.")

    if "websocket" in endpoint_types or full_lower.startswith(("ws://", "wss://")):
        add("Web Security", "WebSocket security issues", "WebSocket endpoint was discovered.")

    if param_names.intersection(proto_pollution_params):
        add("Web Security", "Prototype pollution", "Prototype-oriented parameter names were discovered.")

    # Architecture risks
    if param_names.intersection(redirect_like_params.union({"host", "port", "feed", "image"})):
        add("Architecture Risks", "SSRF", "External URL/host parameters were detected.")

    if "file-upload" in endpoint_types or _contains_any(path, {"upload", "import", "avatar", "attachment"}):
        add("Architecture Risks", "File upload vulnerabilities", "Upload endpoint pattern was detected.")

    if param_names.intersection(file_like_params) or _contains_any(path, {"download", "file", "path", "viewer"}):
        add("Architecture Risks", "Path traversal", "File/path handling patterns were detected.")

    if _contains_any(path, {"order", "checkout", "payment", "wallet", "coupon", "redeem", "transfer"}):
        add("Architecture Risks", "Business logic flaws", "Transactional flow endpoint pattern was detected.")

    if method in {"POST", "PUT", "PATCH"} and _contains_any(path, {"transfer", "checkout", "bid", "reserve", "purchase"}):
        add("Architecture Risks", "Race conditions", "Concurrent update-sensitive operation path detected.")

    if _contains_any(path, {"deserialize", "pickle", "marshal", "yaml", "object"}) or param_names.intersection(
        {"payload", "object", "serialized"}
    ):
        add("Architecture Risks", "Insecure deserialization", "Serialization/deserialization markers were detected.")

    if "api" in endpoint_types or _contains_any(path, {"/api/", "/v1/", "/v2/", "/v3/"}):
        add("Architecture Risks", "API vulnerabilities", "API route pattern was detected.")

    if "graphql" in endpoint_types or "graphql" in path:
        add("Architecture Risks", "GraphQL vulnerabilities", "GraphQL endpoint was detected.")

    # Infrastructure
    if has_header_context:
        cache_control = headers.get("cache-control", "").lower()
        if ("public" in cache_control or "max-age" in cache_control) and params:
            add("Infrastructure", "Cache poisoning", "Cacheable responses with query parameters were observed.")

    if path.endswith((".css", ".js", ".jpg", ".png", ".ico")) and params:
        add("Infrastructure", "Cache deception", "Static-looking path with dynamic query parameters was detected.")

    if has_header_context and "transfer-encoding" in headers and "content-length" in headers:
        add("Infrastructure", "HTTP request smuggling", "Conflicting message framing headers were observed.")

    if has_header_context and (headers.get("server") or headers.get("x-powered-by") or headers.get("x-aspnet-version")):
        add("Infrastructure", "Information disclosure", "Server/software fingerprint headers were detected.")

    # Cloud security
    if "firebaseio.com" in full_lower or "firebase" in full_lower:
        add("Cloud Security", "Firebase misconfiguration", "Firebase resource reference detected.")

    if "storage.googleapis.com" in full_lower or ".storage.googleapis.com" in host:
        add("Cloud Security", "GCP storage exposure", "GCP storage resource reference detected.")

    if "metadata.google.internal" in full_lower or "169.254.169.254" in full_lower:
        add("Cloud Security", "Cloud metadata exposure", "Cloud metadata endpoint pattern detected.")

    return vectors
