from __future__ import annotations

import re
from collections import deque
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from playwright.async_api import BrowserContext, Page, async_playwright


class WebCrawler:
    def __init__(self, target_url: str, on_discover=None) -> None:
        self.target_url = target_url
        self.on_discover = on_discover
        self.base_domain = urlparse(target_url).netloc
        self.visited: Set[str] = set()
        self.endpoints: List[Dict[str, object]] = []
        self.endpoint_lookup: Dict[Tuple[str, str], Dict[str, object]] = {}
        self.max_pages = 25
        self.max_html_bytes = 1_500_000
        self.script_cache: Set[str] = set()

    async def crawl(self) -> Dict[str, object]:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/123.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            requests_caught: List[Dict[str, str]] = []
            page.on(
                "request",
                lambda request: requests_caught.append(
                    {
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    }
                ),
            )

            redirects: List[Dict[str, str]] = []
            headers: Dict[str, str] = {}
            final_url = self.target_url
            html_chunks: List[str] = []
            to_visit: deque[str] = deque([self.target_url])

            try:
                while to_visit and len(self.visited) < self.max_pages:
                    current = to_visit.popleft()
                    if current in self.visited:
                        continue

                    print(f"[*] Crawling: {current}")
                    try:
                        response = await page.goto(current, wait_until="domcontentloaded", timeout=30000)
                        await page.wait_for_timeout(900)
                    except Exception as exc:
                        print(f"[!] Page load failed on {current}: {exc}")
                        continue

                    final_url = page.url
                    self.visited.add(current)
                    self.add_endpoint(page.url, "GET", "link", {"page"})

                    if response:
                        response_headers = await response.all_headers()
                        headers.update(response_headers)
                        if response.request and response.request.redirected_from:
                            redirects.append({"from": response.request.redirected_from.url, "to": response.request.url})

                    current_html = await page.content()
                    if sum(len(chunk) for chunk in html_chunks) < self.max_html_bytes:
                        html_chunks.append(current_html)

                    await self.extract_endpoints(page, context, current_html)

                    # Shallow dynamic interaction to surface hidden routes/forms.
                    buttons = await page.query_selector_all("button, input[type='submit'], [role='button']")
                    for button in buttons[:3]:
                        try:
                            if await button.is_visible():
                                await button.click(timeout=1800)
                                await page.wait_for_timeout(400)
                                await self.extract_endpoints(page, context, await page.content())
                        except Exception:
                            continue

                    links = await page.eval_on_selector_all(
                        "a[href]",
                        "nodes => nodes.map(node => node.href).filter(Boolean)",
                    )
                    for link in links:
                        clean_link = self._normalize_url(link)
                        if clean_link and self.is_internal(clean_link) and clean_link not in self.visited:
                            to_visit.append(clean_link)
            except Exception as exc:
                print(f"[!] Global crawl error: {exc}")
            finally:
                for req in requests_caught:
                    if not self.is_internal(req["url"]):
                        continue
                    endpoint_types = self._infer_endpoint_types(req["url"], req.get("resource_type", ""))
                    self.add_endpoint(req["url"], req["method"], "network", endpoint_types)

                cookies = await context.cookies()
                cookie_headers = "; ".join(f"{cookie['name']}={cookie.get('value', '')}" for cookie in cookies)
                if cookie_headers:
                    headers.setdefault("set-cookie", cookie_headers)

                await browser.close()

        return {
            "endpoints": self.endpoints,
            "html": "\n".join(html_chunks),
            "headers": headers,
            "redirects": redirects,
            "final_url": final_url,
            "domains": sorted({urlparse(url).netloc for url in self.visited if urlparse(url).netloc}),
        }

    async def extract_endpoints(self, page: Page, context: BrowserContext, html: str) -> None:
        # Forms
        forms = await page.query_selector_all("form")
        for form in forms:
            action = await form.get_attribute("action") or page.url
            method = (await form.get_attribute("method") or "GET").upper()
            full_url = urljoin(page.url, action)

            has_file = await form.query_selector("input[type='file']") is not None
            has_csrf_token = await form.query_selector(
                "input[name*='csrf' i], input[name='authenticity_token' i], input[name='__RequestVerificationToken' i]"
            )
            endpoint_types = {"form"}
            if has_file:
                endpoint_types.add("file-upload")

            self.add_endpoint(
                full_url,
                method,
                "form",
                endpoint_types,
                {"has_csrf_token": has_csrf_token is not None},
            )

        # Script files and inline scripts
        scripts = await page.query_selector_all("script[src]")
        for script in scripts:
            src = await script.get_attribute("src")
            if not src:
                continue
            full_src = urljoin(page.url, src)
            if not self.is_internal(full_src):
                continue

            self.add_endpoint(full_src, "GET", "asset", {"asset"})

            if full_src in self.script_cache:
                continue
            self.script_cache.add(full_src)

            try:
                js_response = await context.request.get(full_src, timeout=10000)
                if js_response.ok:
                    script_text = await js_response.text()
                    self._extract_js_routes(script_text, page.url)
            except Exception:
                continue

        inline_scripts = await page.eval_on_selector_all(
            "script:not([src])",
            "nodes => nodes.map(node => node.textContent || '')",
        )
        for script_text in inline_scripts[:20]:
            self._extract_js_routes(script_text, page.url)

        # Parse page HTML for route-like literals
        self._extract_js_routes(html, page.url)

    def _extract_js_routes(self, script_body: str, base_url: str) -> None:
        if not script_body:
            return

        patterns = [
            r"fetch\(\s*['\"]([^'\"]+)['\"]",
            r"axios\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]",
            r"\.open\(\s*['\"][A-Z]+['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            r"\.ajax\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]",
            r"new\s+WebSocket\(\s*['\"]([^'\"]+)['\"]\)",
            r"['\"]((?:/api|/v\d+/|/graphql|/socket|/ws|/auth)[^'\"]*)['\"]",
            r"['\"](wss?://[^'\"]+)['\"]",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, script_body, re.I | re.S):
                candidate = match.group(1).strip()
                if not candidate:
                    continue
                full_url = urljoin(base_url, candidate)
                endpoint_types = self._infer_endpoint_types(full_url, "script")
                method = "POST" if "graphql" in full_url.lower() else "GET"
                self.add_endpoint(full_url, method, "js-discovery", endpoint_types)

    def add_endpoint(
        self,
        url: str,
        method: str,
        source: str,
        endpoint_types: Optional[Iterable[str]] = None,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        normalized = self._normalize_url(url)
        if not normalized:
            return
        if not self.is_internal(normalized) and not normalized.startswith(("ws://", "wss://")):
            return

        method_upper = method.upper()
        key = (normalized, method_upper)
        entry = self.endpoint_lookup.get(key)

        inferred_types = set(endpoint_types or set())
        inferred_types.update(self._infer_endpoint_types(normalized, source))

        if entry:
            existing_types = set(entry.get("endpoint_types") or [])
            merged_types = sorted(existing_types.union(inferred_types))
            entry["endpoint_types"] = merged_types
            if metadata and metadata.get("has_csrf_token"):
                entry["has_csrf_token"] = True
            return

        entry = {
            "url": normalized,
            "method": method_upper,
            "source": source,
            "endpoint_types": sorted(inferred_types),
            "has_csrf_token": bool(metadata.get("has_csrf_token")) if metadata else False,
        }
        self.endpoint_lookup[key] = entry
        self.endpoints.append(entry)

        if self.on_discover:
            self.on_discover(entry)

    def _infer_endpoint_types(self, url: str, source: str) -> Set[str]:
        parsed = urlparse(url)
        path = parsed.path.lower()
        endpoint_types: Set[str] = set()

        if source in {"link", "navigation"}:
            endpoint_types.add("page")
        if source == "form":
            endpoint_types.add("form")
        if source in {"js-discovery", "script"}:
            endpoint_types.add("js-route")

        if "/api/" in path or re.search(r"/v\d+/", path):
            endpoint_types.add("api")
        if "graphql" in path:
            endpoint_types.update({"api", "graphql"})
        if url.startswith(("ws://", "wss://")) or "socket" in path or "/ws" in path:
            endpoint_types.add("websocket")
        if "upload" in path or "attachment" in path or "file" in path:
            endpoint_types.add("file-upload")
        if path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico")):
            endpoint_types.add("asset")

        if not endpoint_types:
            endpoint_types.add("page")

        return endpoint_types

    @staticmethod
    def _normalize_url(url: str) -> str:
        clean = (url or "").split("#")[0].strip()
        if not clean:
            return ""
        if clean.startswith(("javascript:", "data:", "mailto:", "tel:")):
            return ""
        return clean.rstrip("/") if clean.endswith("/") else clean

    def is_internal(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc in {self.base_domain, ""}
