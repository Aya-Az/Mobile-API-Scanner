"""
API Scanner - Découverte et analyse des endpoints d'une API mobile
"""

import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import ssl


class APIScanner:
    """Scanner principal pour la découverte des endpoints API"""

    COMMON_ENDPOINTS = [
        "/api/v1/users", "/api/v1/auth/login", "/api/v1/auth/register",
        "/api/v1/auth/logout", "/api/v1/auth/refresh", "/api/v1/profile",
        "/api/v2/users", "/api/v2/auth/login", "/api/v2/profile",
        "/api/users", "/api/auth", "/api/login", "/api/register",
        "/auth/login", "/auth/register", "/auth/token", "/auth/refresh",
        "/users", "/users/me", "/users/profile", "/users/list",
        "/mobile/api/v1/auth", "/mobile/api/v1/users",
        "/v1/auth/login", "/v1/users", "/v1/profile", "/v1/settings",
        "/v2/auth/login", "/v2/users", "/v2/profile",
        "/api/products", "/api/orders", "/api/payments", "/api/cart",
        "/api/search", "/api/notifications", "/api/messages",
        "/admin", "/admin/api", "/admin/users", "/admin/dashboard",
        "/api/admin", "/api/admin/users",
        "/.well-known/openapi.json", "/openapi.json", "/swagger.json",
        "/api-docs", "/docs/api", "/api/docs",
        "/health", "/ping", "/status", "/api/health",
        "/api/v1/files/upload", "/api/v1/export", "/api/v1/import",
        "/graphql", "/api/graphql",
        "/api/v1/password/reset", "/api/v1/password/change",
        "/api/v1/otp", "/api/v1/verify",
    ]

    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

    def __init__(self, target_url: str, options=None):
        self.target_url = target_url.rstrip("/")
        self.options = options
        self.discovered_endpoints = []
        self.timeout = aiohttp.ClientTimeout(total=getattr(options, 'timeout', 10) if options else 10)

    async def discover_endpoints(self) -> List[Dict[str, Any]]:
        """Découvre les endpoints disponibles sur l'API cible"""
        endpoints = []

        # Créer un contexte SSL permissif pour les tests
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_context)

        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self._build_headers()
        ) as session:

            # 1. Tenter de trouver la spec OpenAPI/Swagger
            openapi_endpoints = await self._find_openapi_spec(session)
            if openapi_endpoints:
                endpoints.extend(openapi_endpoints)

            # 2. Scan des endpoints communs
            tasks = []
            max_ep = getattr(self.options, 'max_endpoints', 50) if self.options else 50
            for path in self.COMMON_ENDPOINTS[:max_ep]:
                url = urljoin(self.target_url, path)
                tasks.append(self._probe_endpoint(session, url, path))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, dict) and result.get("accessible"):
                    # Éviter les doublons
                    if not any(e["path"] == result["path"] for e in endpoints):
                        endpoints.append(result)

        self.discovered_endpoints = endpoints
        return endpoints

    async def _find_openapi_spec(self, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """Cherche et parse la spec OpenAPI/Swagger"""
        spec_paths = [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/.well-known/openapi.json", "/api/openapi.json"
        ]
        endpoints = []

        for path in spec_paths:
            url = urljoin(self.target_url, path)
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get("content-type", "")
                        if "json" in content_type or "yaml" in content_type:
                            try:
                                spec = await resp.json(content_type=None)
                                parsed = self._parse_openapi_spec(spec)
                                endpoints.extend(parsed)
                                endpoints.append({
                                    "path": path, "url": url,
                                    "methods": ["GET"], "status_code": 200,
                                    "accessible": True, "source": "openapi_discovery",
                                    "note": f"OpenAPI spec trouvée: {len(parsed)} endpoints"
                                })
                                break
                            except Exception:
                                pass
            except Exception:
                pass

        return endpoints

    def _parse_openapi_spec(self, spec: dict) -> List[Dict[str, Any]]:
        """Parse une spec OpenAPI pour extraire les endpoints"""
        endpoints = []
        paths = spec.get("paths", {})
        base_path = spec.get("basePath", "")

        for path, methods in paths.items():
            full_path = base_path + path
            available_methods = [m.upper() for m in methods.keys()
                                  if m.lower() in [x.lower() for x in self.HTTP_METHODS]]

            endpoints.append({
                "path": full_path,
                "url": urljoin(self.target_url, full_path),
                "methods": available_methods,
                "accessible": True,
                "source": "openapi_spec",
                "parameters": self._extract_params(methods),
                "requires_auth": self._check_auth_required(methods)
            })

        return endpoints

    def _extract_params(self, methods: dict) -> List[str]:
        """Extrait les paramètres d'un endpoint OpenAPI"""
        params = []
        for method_data in methods.values():
            if isinstance(method_data, dict):
                for param in method_data.get("parameters", []):
                    if isinstance(param, dict):
                        params.append(param.get("name", ""))
        return list(set(p for p in params if p))

    def _check_auth_required(self, methods: dict) -> bool:
        """Vérifie si l'endpoint requiert une authentification"""
        for method_data in methods.values():
            if isinstance(method_data, dict):
                if method_data.get("security") or method_data.get("x-requires-auth"):
                    return True
        return False

    async def _probe_endpoint(self, session: aiohttp.ClientSession, url: str, path: str) -> Dict[str, Any]:
        """Sonde un endpoint pour vérifier son accessibilité"""
        result = {
            "path": path, "url": url,
            "methods": [], "status_code": None,
            "accessible": False, "response_headers": {},
            "source": "brute_force", "response_time": None
        }

        import time
        start = time.time()

        try:
            async with session.get(url, allow_redirects=False) as resp:
                elapsed = time.time() - start
                result["status_code"] = resp.status
                result["response_time"] = round(elapsed * 1000, 2)
                result["response_headers"] = dict(resp.headers)

                # Considérer accessible si pas 404/410
                if resp.status not in [404, 410]:
                    result["accessible"] = True
                    result["methods"] = await self._check_methods(session, url)

        except asyncio.TimeoutError:
            result["error"] = "timeout"
        except aiohttp.ClientConnectorError:
            result["error"] = "connection_refused"
        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    async def _check_methods(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        """Vérifie quelles méthodes HTTP sont acceptées"""
        accessible_methods = []
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            try:
                async with session.request(method, url, allow_redirects=False) as resp:
                    if resp.status not in [405, 501]:
                        accessible_methods.append(method)
            except Exception:
                pass
        return accessible_methods

    def _build_headers(self) -> Dict[str, str]:
        """Construit les headers HTTP pour le scanner"""
        headers = {
            "User-Agent": "MobileAPIScanner/1.0 (Security Testing)",
            "Accept": "application/json, text/plain, */*",
            "X-Mobile-Platform": "Android",
            "X-App-Version": "1.0.0",
        }

        if self.options:
            if self.options.auth_type == "bearer" and self.options.auth_token:
                headers["Authorization"] = f"Bearer {self.options.auth_token}"
            elif self.options.auth_type == "api_key" and self.options.api_key:
                headers["X-API-Key"] = self.options.api_key
            elif self.options.auth_type == "basic" and self.options.auth_token:
                import base64
                headers["Authorization"] = f"Basic {self.options.auth_token}"

            if self.options.custom_headers:
                headers.update(self.options.custom_headers)

        return headers
