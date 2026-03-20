"""DNSAudit.io API client."""

import os
import time
import requests

BASE_URL = "https://dnsaudit.io/api"
DEFAULT_TIMEOUT = 30


class DNSAuditError(Exception):
    """Raised when the API returns an error response."""

    def __init__(self, message: str, status_code: int = 0, code: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class RateLimitError(DNSAuditError):
    """Raised on 429 responses."""

    def __init__(self, message: str, retry_after: int = 0, reset_date: str = ""):
        super().__init__(message, status_code=429, code="RATE_LIMIT")
        self.retry_after = retry_after
        self.reset_date = reset_date


class DNSAuditClient:
    """Thin wrapper around the DNSAudit.io REST API."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("DNSAUDIT_API_KEY", "")
        if not self.api_key:
            raise DNSAuditError(
                "No API key provided. Set the DNSAUDIT_API_KEY environment variable "
                "or pass --api-key."
            )
        self._session = requests.Session()
        self._session.headers.update({"X-API-Key": self.api_key})

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def scan(self, domain: str, fmt: str = "json") -> dict:
        """Run a full DNS security scan on *domain*."""
        params = {"domain": domain}
        if fmt != "json":
            params["format"] = fmt
        return self._get("/v1/scan", params=params)

    def export_json(self, domain: str) -> dict:
        """Retrieve full structured scan results for *domain*."""
        return self._get(f"/export/json/{domain}")

    def export_pdf(self, domain: str) -> bytes:
        """Download a PDF security report for *domain*."""
        return self._get_raw(f"/export/pdf/{domain}", params={"format": "detailed"})

    def history(self, limit: int = 10) -> dict:
        """Return recent scan history (up to *limit* entries)."""
        return self._get("/v1/scan-history", params={"limit": limit})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        response = self._request("GET", path, params=params)
        return response.json()

    def _get_raw(self, path: str, params: dict | None = None) -> bytes:
        response = self._request("GET", path, params=params)
        return response.content

    def _request(self, method: str, path: str, params: dict | None = None) -> requests.Response:
        url = BASE_URL + path
        try:
            response = self._session.request(
                method, url, params=params, timeout=DEFAULT_TIMEOUT
            )
        except requests.ConnectionError:
            raise DNSAuditError("Unable to reach dnsaudit.io. Check your network connection.")
        except requests.Timeout:
            raise DNSAuditError(f"Request timed out after {DEFAULT_TIMEOUT}s.")

        if response.status_code == 429:
            data = {}
            try:
                data = response.json()
            except Exception:
                pass
            raise RateLimitError(
                data.get("message", "Rate limit exceeded."),
                retry_after=data.get("retryAfter", 0),
                reset_date=data.get("resetDate", ""),
            )

        if response.status_code == 401:
            raise DNSAuditError("Invalid or missing API key.", status_code=401, code="UNAUTHORIZED")

        if response.status_code == 403:
            raise DNSAuditError(
                "API access not enabled for your account. Contact dnsaudit.io support.",
                status_code=403,
                code="FORBIDDEN",
            )

        if response.status_code == 404:
            raise DNSAuditError(
                "No scan results found for this domain.", status_code=404, code="NOT_FOUND"
            )

        if not response.ok:
            try:
                err = response.json()
                msg = err.get("error", response.text)
                code = err.get("code", "")
            except Exception:
                msg = response.text
                code = ""
            raise DNSAuditError(msg, status_code=response.status_code, code=code)

        return response
