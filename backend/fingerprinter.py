from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple


class TechFingerprinter:
    def __init__(self) -> None:
        self.frontend_signatures = {
            "React": [r"data-reactroot", r"_reactRootContainer", r"react(?:\.production)?\.min\.js", r"react-dom"],
            "Angular": [r"ng-version", r"ng-app", r"ng-controller", r"angular(?:\.min)?\.js"],
            "Vue": [r"v-if=", r"v-for=", r"vue(?:\.runtime)?(?:\.min)?\.js", r"data-v-[0-9a-f]+"],
            "Next.js": [r"__NEXT_DATA__", r"/_next/", r"next-head-count"],
            "Nuxt.js": [r"__NUXT__", r"/_nuxt/", r"nuxt"],
            "Svelte": [r"svelte", r"data-svelte"],
            "jQuery": [r"jquery(?:\.min)?\.js", r"\$\("],
            "Bootstrap": [r"bootstrap(?:\.min)?\.(?:css|js)", r"class=[\"'][^\"']*\b(?:container|row|col-\w+)"],
            "TailwindCSS": [r"tailwind", r"class=[\"'][^\"']*\b(?:sm:|md:|lg:|xl:|2xl:|flex|grid|gap-\d+)"],
            "Material UI": [r"mui-", r"@mui", r"material-icons", r"material-ui"],
        }

        self.backend_signatures = {
            "Node.js": [r"x-powered-by:\s*express", r"x-powered-by:\s*next\.js", r"_next/"],
            "Java (Spring/JSP/Servlets)": [r"jsessionid", r"x-application-context", r"spring"],
            "Python (Django/Flask)": [r"csrftoken", r"sessionid", r"werkzeug", r"flask"],
            "PHP": [r"x-powered-by:\s*php", r"phpsessid"],
            "PHP (Laravel)": [r"laravel_session", r"xsrf-token"],
            "PHP (WordPress)": [r"wp-content", r"wordpress", r"wp-json"],
            ".NET": [r"asp\.net_sessionid", r"x-aspnet-version", r"x-powered-by:\s*asp\.net"],
            "Ruby on Rails": [r"_rails_session", r"rails", r"passenger"],
            "Go": [r"golang", r"server:\s*caddy", r"x-powered-by:\s*gin"],
        }

        self.server_signatures = {
            "Nginx": [r"server:\s*nginx", r"server:\s*openresty"],
            "Apache": [r"server:\s*apache"],
            "IIS": [r"server:\s*microsoft-iis"],
            "Tomcat": [r"server:\s*apache-coyote", r"server:\s*tomcat"],
            "Cloudflare": [r"server:\s*cloudflare", r"cf-ray", r"cf-cache-status"],
            "Caddy": [r"server:\s*caddy"],
        }

        self.database_signatures = {
            "MySQL": [r"mysql", r"sql syntax.*mysql", r"mysqli?_"],
            "PostgreSQL": [r"postgresql", r"pg::", r"psql", r"postgres"],
            "Oracle": [r"oracle", r"ora-\d{5}"],
            "MongoDB": [r"mongodb", r"mongo(error|exception)?", r"bson"],
            "Microsoft SQL Server": [r"sql server", r"mssql", r"odbc sql server"],
        }

    @staticmethod
    def _has_styles(html: str) -> bool:
        return bool(re.search(r"<style\b|<link[^>]+stylesheet", html, re.I))

    @staticmethod
    def _has_scripts(html: str) -> bool:
        return bool(re.search(r"<script\b", html, re.I))

    @staticmethod
    def _contains_any(patterns: Iterable[str], haystack: str) -> bool:
        return any(re.search(pattern, haystack, re.I) for pattern in patterns)

    @staticmethod
    def _find_signals(patterns: Iterable[str], content: str, headers: str) -> List[Dict[str, str]]:
        signals: List[Dict[str, str]] = []
        for pattern in patterns:
            html_match = re.search(pattern, content, re.I)
            if html_match:
                signals.append(
                    {
                        "source": "html",
                        "pattern": pattern,
                        "match": html_match.group(0)[:120],
                    }
                )
            header_match = re.search(pattern, headers, re.I)
            if header_match:
                signals.append(
                    {
                        "source": "headers",
                        "pattern": pattern,
                        "match": header_match.group(0)[:120],
                    }
                )
        return signals

    @staticmethod
    def _confidence(signals: List[Dict[str, str]]) -> str:
        if not signals:
            return "low"
        sources = {item["source"] for item in signals}
        if len(sources) > 1 or len(signals) >= 3:
            return "high"
        if len(signals) >= 2:
            return "medium"
        return "low"

    def _build_detection(self, html: str, headers: Dict[str, str]) -> Tuple[Dict[str, List[str]], Dict[str, List[Dict[str, Any]]]]:
        content = html or ""
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())

        frontend = set()
        backend = set()
        server = set()
        database = set()
        details: Dict[str, List[Dict[str, Any]]] = {
            "frontend": [],
            "backend": [],
            "server": [],
            "database": [],
        }

        # Core web languages
        if "<html" in content.lower():
            frontend.add("HTML")
            details["frontend"].append(
                {
                    "name": "HTML",
                    "confidence": "high",
                    "detected_from": ["html"],
                    "matched_signals": ["<html>"],
                    "evidence": ["html: <html> tag detected"],
                }
            )
        if self._has_styles(content):
            frontend.add("CSS")
            details["frontend"].append(
                {
                    "name": "CSS",
                    "confidence": "high",
                    "detected_from": ["html"],
                    "matched_signals": ["<style> or stylesheet link"],
                    "evidence": ["html: style tag or stylesheet link detected"],
                }
            )
        if self._has_scripts(content):
            frontend.add("JavaScript")
            details["frontend"].append(
                {
                    "name": "JavaScript",
                    "confidence": "high",
                    "detected_from": ["html"],
                    "matched_signals": ["<script>"],
                    "evidence": ["html: script tag detected"],
                }
            )

        for name, patterns in self.frontend_signatures.items():
            signals = self._find_signals(patterns, content, header_text)
            if signals:
                frontend.add(name)
                details["frontend"].append(
                    {
                        "name": name,
                        "confidence": self._confidence(signals),
                        "detected_from": sorted({item["source"] for item in signals}),
                        "matched_signals": sorted({item["pattern"] for item in signals})[:6],
                        "evidence": [f'{item["source"]}: {item["match"]}' for item in signals[:4]],
                    }
                )

        for name, patterns in self.backend_signatures.items():
            signals = self._find_signals(patterns, content, header_text)
            if signals:
                backend.add(name)
                details["backend"].append(
                    {
                        "name": name,
                        "confidence": self._confidence(signals),
                        "detected_from": sorted({item["source"] for item in signals}),
                        "matched_signals": sorted({item["pattern"] for item in signals})[:6],
                        "evidence": [f'{item["source"]}: {item["match"]}' for item in signals[:4]],
                    }
                )

        for name, patterns in self.server_signatures.items():
            signals = self._find_signals(patterns, content, header_text)
            if signals:
                server.add(name)
                details["server"].append(
                    {
                        "name": name,
                        "confidence": self._confidence(signals),
                        "detected_from": sorted({item["source"] for item in signals}),
                        "matched_signals": sorted({item["pattern"] for item in signals})[:6],
                        "evidence": [f'{item["source"]}: {item["match"]}' for item in signals[:4]],
                    }
                )

        for name, patterns in self.database_signatures.items():
            signals = self._find_signals(patterns, content, header_text)
            if signals:
                database.add(name)
                details["database"].append(
                    {
                        "name": name,
                        "confidence": self._confidence(signals),
                        "detected_from": sorted({item["source"] for item in signals}),
                        "matched_signals": sorted({item["pattern"] for item in signals})[:6],
                        "evidence": [f'{item["source"]}: {item["match"]}' for item in signals[:4]],
                    }
                )

        technologies = {
            "frontend": sorted(frontend),
            "backend": sorted(backend),
            "server": sorted(server),
            "database": sorted(database),
        }

        for category in details:
            details[category] = sorted(details[category], key=lambda item: item["name"].lower())

        return technologies, details

    def detect(self, html: str, headers: Dict[str, str]) -> Dict[str, List[str]]:
        technologies, _ = self._build_detection(html, headers)
        return technologies

    def detect_with_details(self, html: str, headers: Dict[str, str]) -> Dict[str, Any]:
        technologies, details = self._build_detection(html, headers)
        return {
            "technologies": technologies,
            "technology_details": details,
        }
