"""Website integrations: ownership-verified passive checks and key-authenticated telemetry intake."""
import asyncio
import ipaddress
import logging
import re
import secrets
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import httpx
from fastapi import APIRouter, File, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from app.core.engine import threat_engine
from app.models.schemas import RequestInspectionPayload
from app.security.source_scanner import MAX_ARCHIVE_BYTES, scan_source_archive

router = APIRouter(prefix="/integrations", tags=["Website Integrations"])
integrations: dict[str, dict] = {}
last_assessment_at: dict[str, float] = {}
last_host_assessment_at: dict[str, float] = {}
last_code_scan_at: dict[str, float] = {}
last_verify_at: dict[str, float] = {}
audit = logging.getLogger("sentinel.audit")
MAX_SITES_PER_USER = 5
VERIFY_PATH = "/.well-known/sentinel-verify.txt"
VERIFICATION_TTL_SECONDS = 30 * 24 * 60 * 60  # ownership must be re-proven monthly
PRIVATE_KEYS = {"key", "owner_id", "verification_token", "verified_ts"}
MAX_RESPONSE_BYTES = 256_000
ASSESSMENT_INTERVAL_SECONDS = 30
REDIRECT_CODES = (301, 302, 303, 307, 308)
HEADER_FIXES = {
    "Content-Security-Policy": ("medium", "Limits where scripts and resources can load from, which helps reduce XSS impact.", "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'"),
    "Strict-Transport-Security": ("medium", "Tells browsers to keep using HTTPS after a secure visit.", "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "X-Content-Type-Options": ("low", "Stops browsers from guessing file types, which can make uploaded content safer.", "X-Content-Type-Options: nosniff"),
    "Frame protection": ("medium", "Prevents other sites from embedding the page in a frame (clickjacking).", "Content-Security-Policy: frame-ancestors 'self'  (or)  X-Frame-Options: DENY"),
    "Referrer-Policy": ("low", "Limits referrer details sent to other sites.", "Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy": ("low", "Restricts browser features that the site does not need.", "Permissions-Policy: camera=(), microphone=(), geolocation=()"),
}


# ── Ownership & access control ────────────────────────────────────────────────
# Sentinel never sends a request to a site (or reads a source archive for it)
# until the signed-in user has proven they control that site.

def _user_id(request: Request) -> str:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Sign in to access Sentinel AI.")
    return user["id"]


def _owned(integration_id: str, request: Request) -> dict:
    item = integrations.get(integration_id)
    # 404 (not 403) so users cannot discover other people's integrations.
    if not item or item.get("owner_id") != _user_id(request):
        raise HTTPException(404, "Integration not found.")
    return item


def _verified(integration_id: str, request: Request, action: str) -> dict:
    item = _owned(integration_id, request)
    if item.get("verified") and time.time() - item.get("verified_ts", 0) > VERIFICATION_TTL_SECONDS:
        item["verified"] = False
    if not item.get("verified"):
        raise HTTPException(403, "Prove you own this website first. Sentinel only runs checks against sites you have verified.")
    audit.info("action=%s user=%s site=%s", action, item["owner_id"], urlparse(item["url"]).hostname)
    return item


def _verification_instructions(item: dict) -> dict:
    host = urlparse(item["url"]).hostname
    token = item["verification_token"]
    return {"token": token, "methods": [
        {"id": "meta", "title": "Meta tag (easiest on Shopify, Wix, WooCommerce)",
         "how": f'Add <meta name="sentinel-verification" content="{token}"> inside the <head> of your homepage.'},
        {"id": "file", "title": "Verification file",
         "how": f"Publish a plain-text file at https://{host}{VERIFY_PATH} containing exactly: {token}"},
        {"id": "dns", "title": "DNS TXT record",
         "how": f"Add a TXT record for _sentinel-verify.{host} with the value {token}"},
    ]}


def _public(item: dict) -> dict:
    data = {k: v for k, v in item.items() if k not in PRIVATE_KEYS}
    if not item.get("verified"):
        data["verification"] = _verification_instructions(item)
    return data


def _dns_has_token(host: str, token: str) -> bool:
    try:
        import dns.resolver  # optional dependency (dnspython)
        answers = dns.resolver.resolve(f"_sentinel-verify.{host}", "TXT", lifetime=5)
        return any(token in b"".join(record.strings).decode("utf-8", "ignore") for record in answers)
    except Exception:
        return False


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=8, max_length=2048)


def _validated_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Enter a public HTTPS URL (credentials in URLs are not allowed).")
    if parsed.port not in (None, 443):
        raise HTTPException(400, "Only standard HTTPS port 443 is supported.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)}
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise HTTPException(400, "The URL must resolve only to public IP addresses.")
    except (socket.gaierror, ValueError):
        raise HTTPException(400, "The hostname could not be resolved to a public address.")
    return value.strip().rstrip("/")


async def _assessment_target(item: dict, render_only: bool = False) -> tuple[str, str]:
    target = await asyncio.to_thread(_validated_url, item["url"])
    parsed = urlparse(target)
    host = parsed.hostname or ""
    if render_only and not host.endswith(".onrender.com"):
        raise HTTPException(400, "Safe probe simulations are limited to registered *.onrender.com demo sites.")
    return target, host


async def _begin_assessment(integration_id: str, request: Request, action: str) -> tuple[str, str]:
    item = _verified(integration_id, request, action)
    target, host = await _assessment_target(item)
    now = time.monotonic()
    if now - last_assessment_at.get(integration_id, 0) < ASSESSMENT_INTERVAL_SECONDS or now - last_host_assessment_at.get(host, 0) < ASSESSMENT_INTERVAL_SECONDS:
        raise HTTPException(429, "This site was assessed recently. Wait 30 seconds before running another assessment.")
    last_assessment_at[integration_id] = now
    last_host_assessment_at[host] = now
    return target, host


async def _get_root(client: httpx.AsyncClient, target: str, probe_value: str | None = None) -> dict:
    parsed = urlparse(target)
    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    if probe_value is not None:
        url += ("&" if parsed.query else "?") + urlencode({"sentinel_probe": probe_value})
    started = time.monotonic()
    try:
        async with client.stream("GET", url) as response:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                remaining = MAX_RESPONSE_BYTES - len(body)
                if remaining <= 0:
                    break
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    break
            return {
                "status_code": response.status_code,
                "headers": response.headers,
                "body": body.decode("utf-8", errors="replace"),
                "latency_ms": round((time.monotonic() - started) * 1000),
                "error": None,
            }
    except httpx.HTTPError as exc:
        return {"status_code": None, "headers": {}, "body": "", "latency_ms": round((time.monotonic() - started) * 1000), "error": type(exc).__name__}


async def _get_root_following(client: httpx.AsyncClient, target: str, max_hops: int = 3) -> dict:
    """Follow a few same-host HTTPS redirects, revalidating each destination."""
    current, hops = target, []
    original_host = (urlparse(target).hostname or "").lower()
    for _ in range(max_hops + 1):
        result = await _get_root(client, current)
        location = result["headers"].get("location") if result["headers"] else None
        if result["status_code"] in REDIRECT_CODES and location:
            nxt = urljoin(current, location)
            if len(hops) >= max_hops:
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
                result["redirect_blocked"] = True
                result["redirect_error"] = "Redirect limit reached."
                return result
            parsed_next = urlparse(nxt)
            hops.append(f"{result['status_code']} -> {nxt}")
            if parsed_next.scheme != "https":
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, True, current
                return result
            if (parsed_next.hostname or "").lower() != original_host:
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
                result["redirect_blocked"] = True
                return result
            try:
                current = await asyncio.to_thread(_validated_url, nxt)
            except HTTPException as exc:
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
                result["redirect_blocked"] = True
                result["redirect_error"] = exc.detail
                return result
            continue
        result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
        return result
    result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
    return result


def _run_safe_probes(baseline_body: str, xss_marker: str, xss_response: dict, sql_response: dict) -> list[dict]:
    xss_value = f"<sentinel-probe>{xss_marker}</sentinel-probe>"
    reflected = xss_value in xss_response["body"]
    sql_errors = ("sql syntax", "sqlite error", "mysql", "postgresql", "sqlstate", "odbc", "unterminated string", "database error")
    sql_body = sql_response["body"].lower()
    db_error = next((signature for signature in sql_errors if signature in sql_body and signature not in baseline_body.lower()), None)

    return [
        {
            "probe": "HTML reflection canary",
            "status_code": xss_response["status_code"],
            "latency_ms": xss_response["latency_ms"],
            "result": "probe_timed_out" if xss_response["error"] else ("potential_html_reflection" if reflected else "no_raw_reflection_observed"),
            "severity": "info" if xss_response["error"] else ("low" if reflected else "info"),
            "details": f"The website did not finish this request ({xss_response['error']})." if xss_response["error"] else ("A harmless custom HTML element was returned unescaped; review output encoding." if reflected else "The harmless HTML canary was not returned unescaped in the response."),
        },
        {
            "probe": "SQL error disclosure canary",
            "status_code": sql_response["status_code"],
            "latency_ms": sql_response["latency_ms"],
            "result": "probe_timed_out" if sql_response["error"] else ("database_error_signature" if db_error else ("server_error" if (sql_response["status_code"] or 0) >= 500 else "no_error_signature_observed")),
            "severity": "info" if sql_response["error"] else ("medium" if db_error or (sql_response["status_code"] or 0) >= 500 else "info"),
            "details": f"The website did not finish this request ({sql_response['error']})." if sql_response["error"] else (f"Response contained a database error signature ({db_error})." if db_error else ("The probe received a server error; review application logs." if (sql_response["status_code"] or 0) >= 500 else "No common database error signature appeared in the bounded response sample.")),
        },
    ]


@router.get("")
async def list_integrations(request: Request):
    uid = _user_id(request)
    return [_public(item) for item in integrations.values() if item.get("owner_id") == uid]


@router.post("")
async def add_integration(body: IntegrationCreate, request: Request):
    uid = _user_id(request)
    if sum(1 for item in integrations.values() if item.get("owner_id") == uid) >= MAX_SITES_PER_USER:
        raise HTTPException(400, f"You can connect up to {MAX_SITES_PER_USER} websites.")
    url = await asyncio.to_thread(_validated_url, body.url)
    item = {"id": uuid.uuid4().hex[:12], "owner_id": uid, "name": body.name.strip(), "url": url,
            "key": secrets.token_urlsafe(32), "status": "not_checked", "checked_at": None,
            "verified": False, "verified_at": None, "verified_ts": 0, "verified_method": None,
            "verification_token": "sentinel-verify-" + secrets.token_hex(16),
            "http_status": None, "latency_ms": None, "last_event_at": None,
            "event_count": 0, "threat_count": 0, "last_scan_at": None,
            "last_scan_findings": None, "last_simulation_at": None}
    integrations[item["id"]] = item
    audit.info("action=add user=%s site=%s", uid, urlparse(url).hostname)
    return _public(item) | {"integration_key": item["key"]}


@router.delete("/{integration_id}")
async def remove_integration(integration_id: str, request: Request):
    _owned(integration_id, request)
    integrations.pop(integration_id, None)
    last_assessment_at.pop(integration_id, None)
    last_code_scan_at.pop(integration_id, None)
    last_verify_at.pop(integration_id, None)
    return {"success": True}


@router.post("/{integration_id}/verify")
async def verify_ownership(integration_id: str, request: Request):
    item = _owned(integration_id, request)
    now = time.monotonic()
    if now - last_verify_at.get(integration_id, 0) < 10:
        raise HTTPException(429, "Wait 10 seconds before checking again.")
    last_verify_at[integration_id] = now
    target = await asyncio.to_thread(_validated_url, item["url"])
    host = (urlparse(target).hostname or "").lower()
    token = item["verification_token"]
    method = None
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False, headers={"User-Agent": "SentinelAI-OwnershipCheck/1.0"}) as client:
        home = await _get_root_following(client, f"https://{host}/")
        if home.get("status_code") == 200 and re.search(r"<meta\b[^>]*sentinel-verification[^>]*" + re.escape(token), home["body"], re.I):
            method = "meta"
        if not method:
            proof = await _get_root(client, f"https://{host}{VERIFY_PATH}")
            if proof["status_code"] == 200 and secrets.compare_digest(proof["body"].strip(), token):
                method = "file"
    if not method and await asyncio.to_thread(_dns_has_token, host, token):
        method = "dns"
    if not method:
        raise HTTPException(400, "Sentinel could not find the verification token on that site yet. Add it, wait a minute for caches or DNS to update, and try again.")
    item.update(verified=True, verified_method=method, verified_ts=time.time(), verified_at=datetime.now(timezone.utc).isoformat())
    audit.info("action=verified user=%s site=%s method=%s", item["owner_id"], host, method)
    return _public(item)


@router.post("/{integration_id}/check")
async def check_site(integration_id: str, request: Request):
    item = _verified(integration_id, request, "check")
    await asyncio.to_thread(_validated_url, item["url"])
    started = datetime.now(timezone.utc)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False) as client:
            response = await client.get(item["url"], headers={"User-Agent": "SentinelAI-AvailabilityCheck/1.0"})
        item["http_status"] = response.status_code
        item["status"] = "online" if response.status_code < 500 else "degraded"
        item["latency_ms"] = round((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    except httpx.TimeoutException:
        item["status"], item["http_status"] = "timed_out", None
        item["latency_ms"] = round((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    except httpx.HTTPError:
        item["status"], item["http_status"], item["latency_ms"] = "unreachable", None, None
    item["checked_at"] = datetime.now(timezone.utc).isoformat()
    return _public(item)


def _begin_code_scan(integration_id: str, request: Request) -> dict:
    item = _verified(integration_id, request, "source_upload")
    now = time.monotonic()
    if now - last_code_scan_at.get(integration_id, 0) < 45:
        raise HTTPException(429, "This source was scanned recently. Wait 45 seconds before scanning it again.")
    last_code_scan_at[integration_id] = now
    return item


def _finish_code_scan(item: dict, result: dict) -> dict:
    if result["scanned_files"] == 0:
        raise HTTPException(400, "No supported source files were found in this archive.")
    result["integration_id"] = item["id"]
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    result["summary"] = "potential issues found" if result["finding_count"] else "no configured patterns matched"
    item["last_code_scan_at"] = result["checked_at"]
    item["last_code_scan_findings"] = result["finding_count"]
    return result


@router.post("/{integration_id}/source/upload")
async def scan_uploaded_source(integration_id: str, request: Request, file: UploadFile = File(...)):
    item = _begin_code_scan(integration_id, request)
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip source archive.")
    archive = await file.read(MAX_ARCHIVE_BYTES + 1)
    await file.close()
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise HTTPException(413, "The source archive is larger than the 12 MB source-review limit.")
    try:
        result = scan_source_archive(archive, file.filename[:120])
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _finish_code_scan(item, result)


@router.post("/{integration_id}/scan")
async def scan_site(integration_id: str, request: Request):
    target, _host = await _begin_assessment(integration_id, request, "scan")
    item = integrations[integration_id]
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False, max_redirects=0, headers={"User-Agent": "SentinelAI-SecurityReview/1.0 (passive checks)"}) as client:
        baseline = await _get_root_following(client, target)
        if baseline["error"]:
            raise HTTPException(502, f"The website could not be reached ({baseline['error']}). Check its URL and try again.")

        headers = baseline["headers"]
        checks = []
        def add(title, result, severity, details, recommendation="", fix=""):
            checks.append({"title": title, "result": result, "severity": severity, "details": details,
                           "recommendation": recommendation, "fix": fix})

        if baseline.get("downgraded"):
            add("Redirect leaves HTTPS", "https_downgrade", "high",
                f"The site redirected away from HTTPS: {' -> '.join(baseline['redirect_chain'])}",
                "Redirect only to HTTPS URLs.", "return 301 https://$host$request_uri;   # nginx")
        elif baseline.get("redirect_blocked"):
            add("Cross-host redirect not followed", "redirect_not_followed", "info",
                "The page redirects to a different hostname. Sentinel stopped before requesting that host; add the destination as a separate integration if it is in scope.")
        status_code = baseline["status_code"]
        if status_code in (401, 403, 429):
            add("Site blocked the scanner", f"http_{status_code}", "info",
                f"The site answered HTTP {status_code}. A firewall or bot protection may be hiding the page, so these results may be incomplete.")

        csp = headers.get("content-security-policy", "")
        present = {
            "Content-Security-Policy": bool(csp),
            "Strict-Transport-Security": bool(headers.get("strict-transport-security")),
            "X-Content-Type-Options": headers.get("x-content-type-options", "").lower() == "nosniff",
            "Frame protection": "frame-ancestors" in csp.lower() or headers.get("x-frame-options", "").lower() in ("deny", "sameorigin"),
            "Referrer-Policy": bool(headers.get("referrer-policy")),
            "Permissions-Policy": bool(headers.get("permissions-policy")),
        }
        for title, configured in present.items():
            severity, explanation, fix = HEADER_FIXES[title]
            if configured:
                add(title, "present", "info", "Configured.")
            else:
                add(f"Missing {title}", "missing", severity, explanation,
                    f"Add the {title} response header at your web server, CDN, or app middleware.", fix)

        cookies = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
        for cookie in cookies:
            lower_cookie = cookie.lower()
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lower_cookie]
            if missing:
                cookie_name = cookie.split("=", 1)[0].strip()[:40]
                severity = "medium" if "httponly" in missing or "secure" in missing else "low"
                add(f"Cookie '{cookie_name}' missing flags", "review", severity,
                    f"Missing: {', '.join(missing)}.",
                    "Set Secure (HTTPS only), HttpOnly (hidden from JavaScript), and SameSite (CSRF protection) on session cookies.",
                    "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax")

        page = baseline["body"]
        content_type = headers.get("content-type", "").lower()
        server_banner = headers.get("server", "") + " " + headers.get("x-powered-by", "")
        if re.search(r"(?:apache|nginx|iis|php|express)[/ ]\d", server_banner, re.IGNORECASE):
            add("Server version disclosed", "version_banner_observed", "low",
                f"Headers reveal: {server_banner.strip()[:80]}",
                "Hide version numbers so attackers cannot target known issues for an exact version.",
                "server_tokens off;   # nginx\nServerTokens Prod   # Apache\napp.disable('x-powered-by')   // Express")
        if "html" in content_type or "<html" in page[:1000].lower():
            if re.search(r"(?:src|poster)\s*=\s*['\"]http://|url\(\s*['\"]?http://", page, re.IGNORECASE):
                add("Mixed HTTP content reference", "potential_mixed_content", "low",
                    "The homepage contains an HTTP resource reference. Upgrade active page resources to HTTPS.",
                    "Load scripts, styles, images, and media over HTTPS.", '<script src="https://static.example.com/app.js"></script>')
            for form in re.findall(r"<form\b[^>]*>", page, re.IGNORECASE)[:40]:
                action = re.search(r"action\s*=\s*['\"]([^'\"]+)['\"]", form, re.IGNORECASE)
                if action and action.group(1).lower().startswith("http://"):
                    add("Form submits over HTTP", "insecure_form_action", "medium",
                        "A form on the homepage appears to submit to an unencrypted HTTP URL.",
                        "Change the form action to HTTPS.", '<form action="https://shop.example.com/submit" method="post">')
                    break
            for script in re.findall(r"<script\b[^>]*\bsrc\s*=\s*['\"][^'\"]+['\"][^>]*>", page, re.IGNORECASE)[:30]:
                src = re.search(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", script, re.IGNORECASE)
                if src and src.group(1).startswith("https://") and "integrity=" not in script.lower():
                    add("External script without integrity attribute", "review_external_script", "info",
                        "An external HTTPS script has no Subresource Integrity attribute. Review whether SRI is practical for this script.",
                        "Pin the script contents with a current SRI hash where the provider supports stable assets.",
                        '<script src="https://cdn.example.com/library.js" integrity="sha384-<computed-hash>" crossorigin="anonymous"></script>')
                    break

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    checks.sort(key=lambda check: order.get(check["severity"], 4))
    findings = sum(1 for check in checks if check["severity"] in ("low", "medium", "high"))
    checked_at = datetime.now(timezone.utc).isoformat()
    report = {
        "integration_id": integration_id,
        "site": baseline.get("final_url", item["url"]),
        "checked_at": checked_at,
        "http_status": baseline["status_code"],
        "latency_ms": baseline["latency_ms"],
        "summary": "potential findings" if findings else "no issues observed by these checks",
        "finding_count": findings,
        "checks": checks,
        "probes": [],
        "redirects": baseline.get("redirect_chain", []),
        "scope": "One bounded, read-only HTTPS GET (following up to 3 validated same-host redirects). Checks response headers, cookies and homepage markup; does not inspect server files, authenticate, submit forms, or prove the site secure.",
    }
    item["status"] = "online" if (baseline["status_code"] or 0) < 500 else "degraded"
    item["http_status"] = baseline["status_code"]
    item["latency_ms"] = baseline["latency_ms"]
    item["checked_at"] = checked_at
    item["last_scan_at"] = checked_at
    item["last_scan_findings"] = findings
    return report


@router.post("/{integration_id}/simulate")
async def simulate_safe_probes(integration_id: str, request: Request):
    target, _host = await _begin_assessment(integration_id, request, "simulate")
    item = integrations[integration_id]
    xss_marker = "snt" + secrets.token_hex(5)
    sql_marker = "snt" + secrets.token_hex(5)
    xss_value = f"<sentinel-probe>{xss_marker}</sentinel-probe>"
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False, max_redirects=0, headers={"User-Agent": "SentinelAI-SafeProbe/1.0"}) as client:
        baseline = await _get_root(client, target)
        xss_response, sql_response = await asyncio.gather(
            _get_root(client, target, xss_value),
            _get_root(client, target, sql_marker + "'"),
        )
    if baseline["error"]:
        raise HTTPException(502, f"The site could not be reached ({baseline['error']}).")
    probes = _run_safe_probes(baseline["body"], xss_marker, xss_response, sql_response)
    item["last_simulation_at"] = datetime.now(timezone.utc).isoformat()
    return {
        "integration_id": integration_id,
        "site": item["url"],
        "simulated_at": item["last_simulation_at"],
        "requests_sent": 3,
        "probes": probes,
        "scope": "Three GET requests to the site's root only: baseline, inert HTML canary, and quote-only SQL error canary. No login attempts, writes, uploads, or load generation.",
    }


@router.post("/{integration_id}/events")
async def ingest_site_event(integration_id: str, payload: RequestInspectionPayload, authorization: str | None = Header(default=None)):
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    if not authorization or not secrets.compare_digest(authorization.removeprefix("Bearer "), item["key"]):
        raise HTTPException(401, "Invalid integration key.")
    result = await threat_engine.inspect_request(payload)
    item["event_count"] += 1
    item["last_event_at"] = datetime.now(timezone.utc).isoformat()
    if result.detected:
        item["threat_count"] += 1
    return {"accepted": True, "integration_id": integration_id, "detection": result.model_dump()}
