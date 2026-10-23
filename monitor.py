"""
Website Diagnostic Monitor v2 — web application backend
-------------------------------------------------------
The original diagnostic checks are exposed through a FastAPI job API.

What's new in v2 — every problem is now reported as:
    WHAT   : the problem in plain English
    WHERE  : the exact stage (DNS / SSL / HTTP / Browser / Render) and the
             exact file, URL, line or header involved
    EVIDENCE: the raw proof (status code, error text, days left, ...)
    WHY    : the most likely cause
    FIX    : numbered, concrete steps (and who needs to do them)

Plus a one-line pipeline view so you can see at a glance WHERE it breaks:
    DNS ✅ → SSL ✅ → HTTP ❌ → Browser ✅ → Render ✅

Screenshots only; no CSV input or output is used.

Checks run for every site (best-effort, each one skipped quietly if blocked):
    DNS · SSL · HTTP status/speed/redirects · real-browser load (JS errors, failed files, blank page)
    · WordPress plugin/theme crash detection · spam/abuse BLOCKLISTS for the server IP and the domain
    · domain expiry · nameservers · email records (MX/SPF/DMARC) · who hosts the server
    · security headers · outdated PHP · Google visibility (noindex/robots.txt/sitemap)
    · http→https redirect · compression · soft-404 · broken links on the page

The web interface accepts one URL or several separated by commas or new lines:
    https://example.com,https://google.com,mysite.org
(Spaces are tolerated, and a missing https:// is added for you.)
"""

import os
import asyncio
import logging
import re
import socket
import ssl
import textwrap
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

import numpy as np
import requests
import dns.resolver as dnsres
import dns.exception as dnsexc
from PIL import Image
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright


# ======================================
# CONFIG — edit these if needed
# ======================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")

MAX_CONCURRENCY = 8
MAX_URLS_PER_CHECK = 100
MAX_URL_INPUT_LENGTH = 250000
HTTP_TIMEOUT = 25
SSL_TIMEOUT = 10
BROWSER_NAV_TIMEOUT_MS = 75000
BROWSER_SETTLE_MS = 6000
HTTP_RETRIES = 2

SSL_WARN_DAYS = 14        # warn when the certificate expires within this many days
SLOW_MS = 1500            # HTTP response slower than this = Low severity note
VERY_SLOW_MS = 3000       # slower than this = Medium
MAX_ITEMS_PER_FINDING = 5 # cap on URLs/errors listed per finding

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
HTTP_HEADERS = {"User-Agent": USER_AGENT}

logging.basicConfig(level=logging.WARNING)


# ======================================
# FINDINGS MODEL — one object per problem
# ======================================

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEV_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}
STAGES = ["DNS", "SSL", "HTTP", "Browser", "Render", "Reputation", "Hygiene"]

# Plain-English meaning of each stage + where a non-technical person goes to fix it
STAGE_INFO = {
    "DNS": {
        "category": "Domain name / DNS records",
        "legend": "the domain's address book entry (turns the name into a server address)",
        "login": "Your domain registrar or DNS host (where you bought/manage the domain: GoDaddy, Namecheap, Cloudflare, ...)",
        "plain": "The domain name can't be turned into a server address, so browsers can't find the site.",
    },
    "SSL": {
        "category": "SSL certificate (the HTTPS padlock)",
        "legend": "the HTTPS padlock certificate",
        "login": "Your hosting control panel (cPanel, Plesk, cloud console) or your SSL provider (Let's Encrypt, Cloudflare)",
        "plain": "The site's security certificate is broken or about to expire; browsers may show a scary warning that drives visitors away.",
    },
    "HTTP": {
        "category": "Server / hosting",
        "legend": "the web server itself answering requests",
        "login": "Your hosting provider's panel, or the server admin (cPanel, VPS/cloud console, SSH)",
        "plain": "The server is not answering properly, so visitors see an error, a very slow site, or nothing.",
    },
    "Browser": {
        "category": "Website content & scripts",
        "legend": "the page and its files (CSS, scripts, images) loading in a real browser",
        "login": "Your website admin area (e.g. WordPress dashboard) or whoever built the site",
        "plain": "The page opens, but some of its files or scripts fail, so parts of it may look or work wrong.",
    },
    "Reputation": {
        "category": "IP / domain reputation (blocklists)",
        "legend": "whether the server's IP or the domain is on spam / abuse / malware blocklists",
        "login": "Your hosting provider (they own the IP) and the blocklist's removal page",
        "plain": "The server's address or the domain has a bad reputation online, which can send email to spam and make security tools block the site.",
    },
    "Hygiene": {
        "category": "Site health & best practices",
        "legend": "extra health checks: domain expiry, email setup, security headers, Google visibility, broken links",
        "login": "Domain registrar, hosting panel or website admin (each finding says which)",
        "plain": "Not an outage, but something that can hurt security, email delivery or Google ranking.",
    },
    "Render": {
        "category": "Website content & scripts",
        "legend": "a visitor actually seeing content on screen",
        "login": "Your website admin area (e.g. WordPress dashboard) or whoever built the site",
        "plain": "The page opens but visitors see little or nothing.",
    },
}


@dataclass
class Finding:
    severity: str            # Critical / High / Medium / Low / Info
    stage: str               # one of STAGES
    problem: str             # WHAT: short plain-English title
    where: str               # WHERE: file / URL / line / header / host
    evidence: str            # raw proof
    cause: str               # WHY: most likely cause
    fixes: list = field(default_factory=list)   # FIX: ordered steps
    owner: str = "Site owner / hosting provider"  # who has to act
    plain: str = ""          # IN PLAIN WORDS: what this means for a non-technical person
    login: str = ""          # FIX AT: which account/panel to open to fix it
    category: str = ""       # TYPE of problem (defaults from the stage)
    inconclusive: bool = False  # True = the CHECK failed, not necessarily the website


def _worst(findings, stage):
    sevs = [SEV_RANK[f.severity] for f in findings if f.stage == stage]
    return max(sevs) if sevs else None


# ======================================
# DNS
# ======================================

def dns_check(domain: str) -> dict:
    t = time.time()
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({i[4][0] for i in infos})
        return {"ok": True, "ips": ips, "ms": int((time.time() - t) * 1000)}
    except socket.gaierror as e:
        return {"ok": False, "error": str(e), "temporary": e.errno == getattr(socket, "EAI_AGAIN", None)}


def _public_lookup(name: str, server_ip: str, rtype: str = "A") -> dict:
    r = dnsres.Resolver(configure=False)
    r.nameservers = [server_ip]
    r.lifetime = 6
    try:
        ans = r.resolve(name, rtype)
        return {"status": "OK", "records": [x.to_text() for x in ans]}
    except dnsres.NXDOMAIN:
        return {"status": "NXDOMAIN", "records": []}
    except dnsres.NoAnswer:
        return {"status": "NOANSWER", "records": []}
    except dnsres.NoNameservers:
        return {"status": "SERVFAIL", "records": []}
    except dnsexc.Timeout:
        return {"status": "TIMEOUT", "records": []}
    except Exception as e:
        return {"status": "ERROR", "records": [], "detail": str(e)[:100]}


def _rdap_lookup(domain: str):
    """Best-effort: is the domain registered, and when does it expire?"""
    root = _root_domain(domain)
    try:
        r = requests.get(f"https://rdap.org/domain/{root}", timeout=10, headers=HTTP_HEADERS)
    except Exception:
        return None
    if r.status_code == 404:
        return {"registered": False, "root": root}
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    exp = ""
    for ev in data.get("events", []):
        if ev.get("eventAction") == "expiration":
            exp = (ev.get("eventDate") or "")[:10]
    return {"registered": True, "root": root, "expires": exp, "status": data.get("status", [])}


def dns_deep_check(domain: str) -> dict:
    """Runs ONLY when the normal lookup failed. Works out WHOSE fault it is:
    this machine's network, the domain's records, the nameservers, or the registration."""
    info = {"control_ok": True, "public_control_ok": True, "public": {}, "ns": [], "rdap": None,
            "verdict": "unknown"}

    # 1) Control test: can this machine look up a site that is certainly alive?
    try:
        socket.getaddrinfo("www.google.com", None)
    except Exception:
        info["control_ok"] = False

    # 2) Same control through a public resolver, so we know public answers can be trusted
    info["public_control_ok"] = _public_lookup("www.google.com", "8.8.8.8")["status"] == "OK"

    # 3) Ask two public resolvers directly (bypasses this machine's own DNS)
    for label, ip in (("Google DNS (8.8.8.8)", "8.8.8.8"), ("Cloudflare DNS (1.1.1.1)", "1.1.1.1")):
        a = _public_lookup(domain, ip, "A")
        if a["status"] == "NOANSWER":
            a6 = _public_lookup(domain, ip, "AAAA")
            if a6["status"] == "OK":
                a = a6
        info["public"][label] = a

    info["ns"] = _public_lookup(_root_domain(domain), "8.8.8.8", "NS")["records"]
    statuses = [v["status"] for v in info["public"].values()]

    if "OK" in statuses:
        info["verdict"] = "records_ok"
    elif not info["public_control_ok"] and not info["control_ok"]:
        info["verdict"] = "monitor_network"   # nothing resolves from here, not even google.com
    elif not info["public_control_ok"]:
        info["verdict"] = "unknown"           # public resolvers unreachable/untrustworthy from here
    elif "NXDOMAIN" in statuses:
        info["verdict"] = "nxdomain"
        info["rdap"] = _rdap_lookup(domain)
    elif "NOANSWER" in statuses:
        info["verdict"] = "norecord"
    elif "SERVFAIL" in statuses:
        info["verdict"] = "servfail"
    elif "TIMEOUT" in statuses:
        info["verdict"] = "ns_timeout"
    return info


def _dns_evidence(sys_err: str, deep: dict) -> str:
    lines = [f"This computer's own lookup: {sys_err}"]
    if deep:
        lines.append("Control test (can this computer look up www.google.com?): "
                     + ("yes" if deep.get("control_ok") else "NO"))
        lines.append("Control test via public DNS (www.google.com via 8.8.8.8): "
                     + ("yes" if deep.get("public_control_ok") else "NO"))
        for name, v in deep.get("public", {}).items():
            more = f" → {', '.join(v['records'][:3])}" if v["records"] else ""
            lines.append(f"{name}: {v['status']}{more}")
        if deep.get("ns"):
            lines.append("Name servers for this domain: " + ", ".join(deep["ns"][:4]))
    return "\n".join(lines)


def analyze_dns(dns: dict, domain: str) -> list:
    if dns["ok"]:
        return []
    deep = dns.get("deep") or {}
    verdict = deep.get("verdict", "unknown")
    ev = _dns_evidence(dns["error"], deep)
    registrar = "Your domain registrar (where you bought the domain: GoDaddy, Namecheap, Squarespace/Google Domains, ...)"
    dnshost = "Your DNS host — usually your registrar, or Cloudflare / Route53 if you moved DNS there"

    if verdict == "monitor_network":
        return [Finding(
            "Medium", "DNS", "This computer has no working internet/DNS, so the website could not be tested (it may be fine)",
            "The machine running this monitor (e.g. your Colab session) — NOT your website", ev,
            "Even www.google.com cannot be looked up from here, so this result says nothing about your site.",
            ["Colab: menu Runtime → Disconnect and delete runtime, reconnect, then run again.",
             "Locally: check your internet connection, VPN, proxy or firewall.",
             f"Meanwhile check from outside: open https://dnschecker.org and type {domain}."],
            "You (the machine running this monitor)",
            plain="The checker itself is offline, so it could not test your website at all. Nothing is known about your site yet.",
            login="Nothing to fix on your website yet — fix this computer's internet first",
            category="Problem with the checker, not the website", inconclusive=True)]

    if verdict == "records_ok":
        ips = ", ".join(sorted({ip for v in deep["public"].values() for ip in v["records"]})[:4])
        return [Finding(
            "Medium", "DNS", "Your domain's DNS records are fine — only this computer's own DNS lookup failed",
            "This computer's DNS resolver (not your website)", ev + f"\nWhat the public internet sees: {domain} → {ips}",
            "Google and Cloudflare can both find your domain. This machine's own DNS service is flaky or blocked, "
            "so the remaining checks could not run.",
            ["Run the cell again (this is often a one-off hiccup).",
             "Colab: Runtime → Disconnect and delete runtime, reconnect, run again.",
             "If it keeps happening on every site, change this machine's DNS to 8.8.8.8 / 1.1.1.1."],
            "You (the machine running this monitor)",
            plain="Your domain looks healthy to the rest of the internet. The checker just couldn't use its own address lookup.",
            login="Nothing to fix on the domain — retry the check",
            category="Problem with the checker, not the website", inconclusive=True)]

    if verdict == "nxdomain":
        r = deep.get("rdap")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if r and r.get("registered") is False:
            problem = "Domain name does not exist — it is not registered (or the name is misspelled)"
            cause = (f"No registration record was found for {r['root']}. Either the name is mistyped, the domain "
                     "expired and was released, or this extension doesn't publish registration data.")
            ev2 = ev + f"\nRegistration lookup: no record for {r['root']}"
            fixes = [f"Double-check the spelling of {domain}.",
                     "If it used to work: search for it at a registrar — if it is available, the registration lapsed; "
                     "re-register it (or contact the registrar immediately, some offer a grace period).",
                     "Once registered, add DNS records pointing to your hosting."]
        elif r and r.get("expires") and r["expires"] < today:
            problem = f"Domain registration EXPIRED on {r['expires']}"
            cause = "Nobody renewed the domain, so it was switched off. Email on this domain stops working too."
            ev2 = ev + f"\nRegistration lookup: {r['root']} expired {r['expires']}"
            fixes = ["Log in to your registrar and renew the domain right now (most have a grace period before it is lost).",
                     "If you can't remember the registrar, search the domain at https://lookup.icann.org.",
                     "After renewing, DNS usually returns within minutes to a few hours."]
        else:
            problem = "Domain name is registered but nothing answers for it in DNS (records/zone missing)"
            cause = ("The domain exists, but its DNS zone was deleted or the registrar points to nameservers that "
                     "don't know this domain (often after moving hosting or DNS).")
            exp = f" (expires {r['expires']})" if r and r.get("expires") else ""
            ev2 = ev + (f"\nRegistration lookup: registered{exp}" if r else "")
            fixes = ["At your registrar, look at the nameservers listed for the domain.",
                     "Open the DNS host those nameservers belong to and check that a zone for this domain exists.",
                     "Re-create the zone and the records (A record for the site) if it is missing."]
        return [Finding("Critical", "DNS", problem, f"The domain registration / nameserver setup for {domain}", ev2, cause, fixes,
                        "Domain owner",
                        plain="Typing this website name leads nowhere, so nobody can open the site (and email on the domain is likely down).",
                        login=registrar)]

    if verdict == "norecord":
        return [Finding(
            "Critical", "DNS", "The domain exists but has NO address record (A/AAAA) — it points to no server",
            f"DNS records of {domain}", ev,
            "The nameservers answer, but there is no 'A' record telling browsers which server hosts the site. "
            "It was deleted, never added, or was added on a different DNS host than the one the domain uses.",
            [f"Open your DNS host and add an A record for '{domain}' pointing to your hosting server's IP (ask your host for it).",
             "Confirm the nameservers shown at the registrar are the SAME DNS host where you edited the records.",
             "Wait 5–60 minutes for the change to spread, then re-run this check."],
            "Domain owner",
            plain="The domain is registered but isn't told where the website lives, so browsers can't find it.",
            login=dnshost)]

    if verdict == "servfail":
        return [Finding(
            "Critical", "DNS", "The domain's nameservers are broken or misconfigured (DNS SERVFAIL)",
            f"Nameserver / DNSSEC settings of {domain}", ev,
            "The nameservers responded with an error. Common causes: the registrar lists nameservers that no longer host "
            "the zone, or DNSSEC is switched on with keys that no longer match.",
            ["At the registrar, check the nameservers are correct and still active.",
             "If you recently moved DNS provider: turn DNSSEC off at the registrar (remove the DS record), wait, then re-enable only if needed.",
             f"Get a detailed diagnosis at https://dnsviz.net (enter {domain})."],
            "Domain owner / DNS provider",
            plain="The domain's address book is returning errors, so most visitors cannot reach the site.",
            login=dnshost)]

    if verdict == "ns_timeout":
        return [Finding(
            "High", "DNS", "The domain's nameservers are not answering (timeout)",
            f"Nameservers of {domain}", ev,
            "The servers that hold this domain's records are offline, unreachable, or the domain points at the wrong ones.",
            ["At the registrar, verify the nameserver names are spelled correctly and belong to a live DNS provider.",
             "Check your DNS provider's status page for an outage.",
             "Re-run in 10–15 minutes to rule out a short outage."],
            "Domain owner / DNS provider",
            plain="The service that should say where the website lives isn't responding, so the site can't be found.",
            login=dnshost)]

    # unknown / could not classify
    return [Finding(
        "High", "DNS", "DNS lookup failed and the cause could not be narrowed down", f"DNS resolver for {domain}", ev,
        "The lookup failed but the public resolvers also gave no clear answer. Could be a brief outage or a network limit here.",
        ["Re-run the check in a minute to rule out a blip.", f"Check from outside: https://dnschecker.org (enter {domain}).",
         "If it keeps failing, check the nameservers at your registrar."],
        "Domain owner / DNS provider", login=dnshost)]


# ======================================
# SSL
# ======================================

def ssl_check(domain: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_ts = ssl.cert_time_to_seconds(cert["notAfter"])
                issuer = {k: v for part in cert.get("issuer", ()) for k, v in part}
                return {
                    "ok": True,
                    "days": int((expiry_ts - time.time()) // 86400),
                    "expires": datetime.fromtimestamp(expiry_ts, timezone.utc).strftime("%Y-%m-%d"),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName", "unknown"),
                    "tls": ssock.version(),
                }
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "kind": "verify", "error": getattr(e, "verify_message", None) or str(e)}
    except (socket.timeout, TimeoutError) as e:
        return {"ok": False, "kind": "timeout", "error": str(e) or "connection timed out"}
    except ConnectionRefusedError as e:
        return {"ok": False, "kind": "refused", "error": str(e)}
    except Exception as e:
        return {"ok": False, "kind": "other", "error": str(e)}


def analyze_ssl(res: dict, domain: str) -> list:
    if res["ok"]:
        d = res["days"]
        if d < 0:
            return [Finding("Critical", "SSL", "SSL certificate has expired", f"Certificate served by {domain}:443",
                            f"Expired {-d} day(s) ago on {res['expires']} (issuer: {res['issuer']})",
                            "Auto-renewal failed or was never set up.",
                            ["Renew the certificate now (Let's Encrypt: `sudo certbot renew`; or via your host panel).",
                             "Reload the web server after renewing (`sudo systemctl reload nginx` / `apache2`).",
                             "Fix auto-renew: check the certbot timer (`systemctl list-timers | grep certbot`)."])]
        if d <= SSL_WARN_DAYS:
            return [Finding("Medium", "SSL", f"SSL certificate expires in {d} day(s)", f"Certificate served by {domain}:443",
                            f"Expires {res['expires']} (issuer: {res['issuer']})",
                            "Renewal has not happened yet — auto-renew may be broken.",
                            ["Renew the certificate before the expiry date.",
                             "Check that the auto-renew job/timer runs and that port 80/443 are reachable for validation."])]
        return []

    kind, err = res.get("kind"), res.get("error", "")
    low = err.lower()
    if kind == "verify":
        if "expired" in low:
            problem, cause = "SSL certificate has expired", "The certificate's validity period ended; renewal failed."
            fixes = ["Renew the certificate (`sudo certbot renew` or your host's panel).",
                     "Reload the web server afterwards."]
        elif "hostname" in low or "doesn't match" in low or "mismatch" in low:
            problem = "SSL certificate does not match this domain name"
            cause = ("The certificate was issued for a different hostname (e.g. covers example.com but not "
                     "www.example.com) or the wrong site/vhost is answering.")
            fixes = [f"Reissue the certificate so it includes `{domain}` (add every hostname you serve).",
                     "Check the web-server vhost/server_name matches the domain and loads the right cert file."]
        elif "self" in low and "signed" in low:
            problem, cause = "Self-signed SSL certificate", "The server uses a certificate not issued by a trusted authority."
            fixes = ["Install a certificate from a trusted CA (free: Let's Encrypt)."]
        elif "issuer" in low or "chain" in low:
            problem = "Incomplete SSL certificate chain"
            cause = "The server sends the site certificate but not the intermediate certificate(s)."
            fixes = ["Install the full-chain file (for Let's Encrypt use `fullchain.pem`, not `cert.pem`).",
                     "Reload the web server and re-test."]
        else:
            problem, cause = "SSL certificate failed verification", "The certificate is not trusted by clients."
            fixes = ["Inspect with `openssl s_client -connect {0}:443 -servername {0}`.".format(domain),
                     "Reissue/reinstall the certificate from a trusted CA."]
        return [Finding("Critical", "SSL", problem, f"Certificate served by {domain}:443", err, cause, fixes)]
    if kind == "timeout":
        return [Finding("High", "SSL", "HTTPS port 443 timed out", f"{domain}:443", err,
                        "A firewall is dropping traffic on 443, or the server is overloaded/offline.",
                        ["Check the firewall / security group allows inbound TCP 443.",
                         "Confirm the web server is running and listening on 443 (`ss -tlnp | grep 443`)."])]
    if kind == "refused":
        return [Finding("High", "SSL", "HTTPS port 443 refused the connection", f"{domain}:443", err,
                        "Nothing is listening on 443 — the web server is stopped or HTTPS isn't configured.",
                        ["Start the web server (`sudo systemctl start nginx` / `apache2`).",
                         "Enable an HTTPS (443) listener with a valid certificate."])]
    return [Finding("High", "SSL", "Could not complete the TLS handshake", f"{domain}:443", err,
                    "Unsupported TLS version/ciphers, a proxy interfering, or a misconfigured server.",
                    ["Test with https://www.ssllabs.com/ssltest/ for a detailed report.",
                     "Make sure TLS 1.2+ is enabled on the server."])]


# ======================================
# HTTP (blocking call, run in executor)
# ======================================

def _http_check_sync(url: str) -> dict:
    last = {"kind": "other", "error": "unknown"}
    for _ in range(HTTP_RETRIES + 1):
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, headers=HTTP_HEADERS)
            return {"ok": True, "code": r.status_code, "final_url": r.url,
                    "chain": [(h.status_code, h.url) for h in r.history],
                    "ms": int(r.elapsed.total_seconds() * 1000),
                    "html": r.text[:500_000].lower(), "html_raw": r.text[:500_000], "headers": dict(r.headers)}
        except requests.exceptions.SSLError as e:
            last = {"kind": "ssl", "error": str(e)}; break
        except requests.exceptions.TooManyRedirects as e:
            last = {"kind": "redirects", "error": str(e)}; break
        except requests.exceptions.ConnectTimeout as e:
            last = {"kind": "timeout", "error": str(e)}
        except requests.exceptions.ReadTimeout as e:
            last = {"kind": "slow", "error": str(e)}
        except requests.exceptions.ConnectionError as e:
            last = {"kind": "conn", "error": str(e)}
        except Exception as e:
            last = {"kind": "other", "error": str(e)}
    return {"ok": False, **last}


async def http_check(url: str) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _http_check_sync, url)


HTTP_HINTS = {
    400: ("Bad request (400)", "The server rejected the request as malformed.",
          ["Check server/proxy logs for the rejected request.", "Look for a broken rewrite rule or oversized headers/cookies."]),
    401: ("Authentication required (401)", "The page (or the whole site) is behind a login/password.",
          ["If the site should be public, remove HTTP basic-auth / maintenance password protection.",
           "If it is intentionally private, exclude it from monitoring or add credentials to the monitor."]),
    403: ("Access forbidden (403)", "A firewall, WAF, bot-protection rule, IP block or file-permission problem is denying access.",
          ["Check WAF/firewall logs (Cloudflare, Wordfence, ModSecurity) for blocked requests.",
           "Check file permissions / ownership of the site's web root.",
           "Allow-list the monitor's IP/User-Agent if a bot rule is blocking it."]),
    404: ("Page not found (404)", "The URL does not exist, the site was moved/deleted, or a rewrite rule is broken.",
          ["Confirm the URL is correct and the content exists.",
           "WordPress: Settings → Permalinks → Save (rebuilds rewrite rules).",
           "Check the web-server root path and index file (index.php/index.html)."]),
    429: ("Rate limited (429)", "Too many requests from this IP — the server or WAF is throttling.",
          ["Slow down/space out the checks or reduce MAX_CONCURRENCY.",
           "Allow-list the monitoring IP in the rate-limit/WAF rules."]),
    500: ("Internal server error (500)", "Application crash: PHP fatal error, bad .htaccess, broken plugin/theme, or failed DB connection.",
          ["Read the server error log (`/var/log/nginx/error.log`, `/var/log/apache2/error.log`, PHP error log).",
           "WordPress: enable WP_DEBUG_LOG, then disable recently updated plugins/themes.",
           "Check the database is up and credentials are correct.", "Check disk space and memory (`df -h`, `free -m`)."]),
    502: ("Bad gateway (502)", "The reverse proxy/CDN could not get a valid answer from the application server (PHP-FPM/app crashed or restarting).",
          ["Restart the app backend (`sudo systemctl restart php-fpm` or your app service).",
           "Check backend logs for crashes / out-of-memory kills.", "Confirm the proxy points to the right upstream host/port."]),
    503: ("Service unavailable (503)", "The server is overloaded, in maintenance mode, or the backend is down.",
          ["Check CPU/RAM load and traffic spikes.", "Look for a stuck maintenance file (WordPress: `.maintenance` in web root).",
           "Restart the web/app services and scale resources if it recurs."]),
    504: ("Gateway timeout (504)", "The backend took too long to respond (slow queries, heavy script, exhausted workers).",
          ["Check slow-query and PHP/app logs.", "Increase backend timeouts / worker count if appropriate.",
           "Add caching (page cache/CDN) to cut backend load."]),
}


def _bot_protection(http: dict) -> bool:
    hdr = " ".join(f"{k}:{v}" for k, v in http.get("headers", {}).items()).lower()
    html = http.get("html", "")
    markers = ("cf-ray", "cf-mitigated", "captcha", "just a moment", "attention required",
               "access denied", "enable javascript and cookies", "akamai", "perimeterx", "datadome", "incapsula")
    return any(m in hdr or m in html[:20000] for m in markers)


def analyze_http(http: dict, url: str, browser_ok_visual: bool) -> list:
    out = []
    host = urlparse(url).hostname

    if not http["ok"]:
        kind, err = http.get("kind"), http.get("error", "")
        sev = "Low" if browser_ok_visual else "Critical"
        note = (" NOTE: a real browser loaded the page fine, so this is probably the monitor being treated "
                "differently from real visitors, not an outage.") if browser_ok_visual else ""
        table = {
            "timeout": ("Server did not accept the connection (timeout)", f"{host}:443/80",
                        "Server is offline/overloaded or a firewall silently drops connections.",
                        ["Check the server is powered on / running and has free CPU & RAM.",
                         "Check firewall / security-group rules for ports 80 and 443.",
                         "Check your hosting provider's status page."]),
            "slow": ("Server accepted the connection but never sent a response", url,
                     "The application is hanging (stuck PHP/DB process or exhausted workers).",
                     ["Restart the web/app service and database.", "Check slow-query and application logs.",
                      "Check for runaway processes (`top`)."]),
            "conn": ("Connection failed / reset by server", f"{host}",
                     "Server is down, the service crashed, or a firewall/WAF is resetting connections.",
                     ["Confirm the web server is running (`systemctl status nginx`).",
                      "Check firewall/WAF logs for blocks.", "Verify the DNS record points at the right server IP."]),
            "ssl": ("HTTPS connection failed due to an SSL error", f"TLS handshake with {host}",
                    "Certificate or TLS configuration problem (see SSL stage).",
                    ["Fix the SSL certificate problem reported above.", "Re-test after reloading the web server."]),
            "redirects": ("Redirect loop (too many redirects)", url,
                          "Two rules redirect to each other (http↔https, www↔non-www, or a CMS/plugin conflict).",
                          ["Look at the redirect rules in .htaccess / nginx config / CDN page-rules.",
                           "Cloudflare: set SSL mode to 'Full (strict)' (a 'Flexible' mode + HTTPS redirect causes loops).",
                           "WordPress: make sure Site URL and Home URL use the same scheme/host."]),
        }
        title, where, cause, fixes = table.get(kind, ("Site unreachable over HTTP", url,
                                                      "Unknown network or server problem.",
                                                      ["Open the site in your own browser to compare.", "Check server and network status."]))
        out.append(Finding(sev, "HTTP", title, where, err[:300], cause + note, fixes))
        return out

    code, final, ms = http["code"], http["final_url"], http["ms"]

    # ---- status code
    if code >= 400:
        title, cause, fixes = HTTP_HINTS.get(code, (
            f"HTTP error {code}",
            "Server error." if code >= 500 else "The server refused or could not find the request.",
            ["Check the web-server/application logs around this time.", "Confirm the URL is correct."]))
        blocked = code in (401, 403, 429, 503) and _bot_protection(http)
        if blocked:
            sev = "Low" if browser_ok_visual else "Medium"
            out.append(Finding(sev, "HTTP", f"Monitor request was blocked by bot protection ({code})",
                               f"Response headers/body from {final}",
                               f"HTTP {code}; server={http['headers'].get('server', '?')}",
                               "A CDN/WAF (e.g. Cloudflare) challenged the script's plain HTTP request. "
                               + ("A real browser loaded the page fine, so real users are probably OK."
                                  if browser_ok_visual else "Real users may or may not be affected — verify manually."),
                               ["Open the URL in a normal browser to confirm real users are fine.",
                                "If you own the site, allow-list the monitor's IP in the WAF/bot rules.",
                                "Otherwise rely on the Browser/Render stage results below."],
                               "Site owner (only if the site is yours)"))
        else:
            out.append(Finding("High", "HTTP", title, f"Main page response from {final}", f"HTTP {code}", cause, fixes))

    # ---- redirects
    chain = http["chain"]
    if len(chain) >= 4:
        steps = " → ".join(f"{c} {u}" for c, u in chain[:4]) + " → ..."
        out.append(Finding("Medium", "HTTP", f"Long redirect chain ({len(chain)} hops)", "Redirect rules (server / CDN / CMS)",
                           steps[:300], "Stacked redirect rules (http→https, www→non-www, trailing slash, language) slow every visit.",
                           ["Redirect straight to the final URL in ONE hop.", "Update internal links and sitemap to the final URL."]))
    if url.startswith("https://") and final.startswith("http://"):
        out.append(Finding("Medium", "HTTP", "HTTPS site redirects down to insecure HTTP", f"Final URL: {final}",
                           f"{url} → {final}", "A redirect rule or CMS setting sends visitors back to http://.",
                           ["Change the site URL / base URL setting to https://.", "Fix redirect rules so they never point to http://."]))

    # ---- speed
    if ms >= VERY_SLOW_MS:
        out.append(Finding("Medium", "HTTP", f"Very slow server response ({ms} ms)", f"Time to first response from {final}",
                           f"{ms} ms (healthy is usually under ~800 ms)",
                           "Overloaded server, slow database queries, or no caching.",
                           ["Enable page caching / a CDN.", "Check slow-query and PHP/app logs.", "Upgrade server resources if usage grew."]))
    elif ms >= SLOW_MS:
        out.append(Finding("Low", "HTTP", f"Slow server response ({ms} ms)", f"Time to first response from {final}",
                           f"{ms} ms", "Uncached pages or a busy server.", ["Enable caching.", "Watch whether it gets worse over time."]))

    # ---- config
    if "index of /" in http["html"] or "<title>index of" in http["html"]:
        out.append(Finding("High", "HTTP", "Directory listing exposed / no index file", f"Web root served at {final}",
                           "Page title is 'Index of /'",
                           "The folder has no index.html/index.php and directory listing is enabled — also leaks file names.",
                           ["Upload/restore the site's index file (index.php / index.html).",
                            "Disable listing: nginx `autoindex off;` or Apache `Options -Indexes`.",
                            "Confirm the web root path points to the right folder."]))
    return out


# ======================================
# PLATFORM DETECTION
# ======================================

def detect_platform(html: str, headers: dict) -> str:
    platform = []
    headers_str = str(headers).lower()

    checks = [
        ("WordPress", ["wp-content", "wp-includes"]),
        ("Elementor", ["elementor"]),
        ("WooCommerce", ["woocommerce", "wc-cart"]),
        ("Shopify", ["cdn.shopify.com", "shopify.com/s/"]),
        ("Wix", ["wix.com", "wixstatic.com"]),
        ("Squarespace", ["squarespace.com", "static1.squarespace"]),
        ("Magento", ["mage/cookies", "magento"]),
        ("Drupal", ["drupal.settings", "/sites/default/files"]),
        ("Joomla", ["joomla"]),
    ]
    for name, needles in checks:
        if any(n in html for n in needles):
            platform.append(name)

    header_checks = [
        ("Cloudflare", ["cloudflare", "cf-ray"]),
        ("LiteSpeed", ["litespeed"]),
        ("Nginx", ["nginx"]),
        ("Apache", ["apache"]),
        ("IIS", ["microsoft-iis"]),
    ]
    for name, needles in header_checks:
        if any(n in headers_str for n in needles):
            platform.append(name)

    return " + ".join(platform) if platform else "Unknown"


# ======================================
# SCREENSHOT ANALYSIS
# ======================================

def screenshot_check(path: str) -> bool:
    try:
        img = np.array(Image.open(path).convert("RGB"))
        total_px = img.shape[0] * img.shape[1]
        white = np.sum(np.all(img > 245, axis=2))
        percent_white = (white / total_px) * 100
        variation = np.std(img)
        if percent_white > 99 and variation < 3:
            return False
        return True
    except Exception:
        return True


# ======================================
# BROWSER (shared instance, one context per site)
# ======================================

def _root_domain(host: str) -> str:
    parts = (host or "").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _loc_from_stack(stack: str) -> str:
    m = re.search(r"(https?://[^\s)]+?:\d+(?::\d+)?)", stack or "")
    return m.group(1) if m else ""


async def browser_check(browser, url: str) -> dict:
    st = {"js": [], "console": [], "failed": [], "bad": [], "mixed": []}
    ctx = await browser.new_context(viewport={"width": 1280, "height": 900}, user_agent=USER_AGENT)
    page = await ctx.new_page()

    def on_pageerror(e):
        st["js"].append({"msg": getattr(e, "message", str(e)),
                         "loc": _loc_from_stack(getattr(e, "stack", "") or "")})

    def on_console(m):
        if m.type != "error":
            return
        text = m.text or ""
        if text.startswith("Failed to load resource"):
            return  # already covered precisely by the response/requestfailed hooks
        if "mixed content" in text.lower():
            st["mixed"].append(text[:250])
            return
        loc = m.location or {}
        where = f"{loc.get('url', '')}:{loc.get('lineNumber', '')}" if loc.get("url") else ""
        st["console"].append({"msg": text[:250], "loc": where})

    def on_failed(req):
        reason = req.failure or "unknown"
        if "ERR_ABORTED" in reason:
            return
        st["failed"].append({"url": req.url, "type": req.resource_type, "reason": reason})

    def on_response(resp):
        if resp.status >= 400:
            st["bad"].append({"url": resp.url, "type": resp.request.resource_type, "status": resp.status})

    page.on("pageerror", on_pageerror)
    page.on("console", on_console)
    page.on("requestfailed", on_failed)
    page.on("response", on_response)

    try:
        t0 = time.time()
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=BROWSER_NAV_TIMEOUT_MS)
        load_ms = int((time.time() - t0) * 1000)
        await page.wait_for_timeout(BROWSER_SETTLE_MS)
        try:
            body = await page.locator("body").inner_text(timeout=5000)
        except Exception:
            body = ""
        title = ""
        try:
            title = await page.title()
        except Exception:
            pass

        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
        hostname = urlparse(url).hostname or "unknown"
        path = f"{SCREENSHOT_DIR}/{hostname.replace('.', '_')}.png"
        await page.screenshot(path=path, full_page=True)

        return {"ok": True, "visual": screenshot_check(path), "body": body, "title": title,
                "status": resp.status if resp else None, "load_ms": load_ms,
                "screenshot": path, "final_url": page.url, **st}
    except Exception as e:
        return {"ok": False, "error": str(e), **st}
    finally:
        await ctx.close()


def _limit(items, fmt):
    shown = [fmt(i) for i in items[:MAX_ITEMS_PER_FINDING]]
    extra = len(items) - len(shown)
    if extra > 0:
        shown.append(f"... and {extra} more")
    return shown


CHALLENGE_MARKERS = ("just a moment", "checking your browser", "verify you are human", "captcha",
                     "attention required", "access denied", "are you a robot")


def analyze_browser(b: dict, url: str) -> list:
    out = []
    site_root = _root_domain(urlparse(url).hostname)

    # ---------- the browser could not load the page at all
    if not b["ok"]:
        err = b.get("error", "")
        low = err.lower()
        if "err_name_not_resolved" in low:
            title, cause, fixes, sev = ("Browser could not resolve the domain", "DNS problem.",
                                        ["Fix the DNS record (see DNS stage)."], "Critical")
        elif "err_cert" in low or "ssl" in low:
            title, cause, fixes, sev = ("Browser blocked the page: SSL certificate error",
                                        "Visitors see a full-page 'Your connection is not private' warning.",
                                        ["Fix/renew the SSL certificate (see SSL stage)."], "Critical")
        elif "err_connection_refused" in low or "err_connection_reset" in low or "err_connection_closed" in low:
            title, cause, fixes, sev = ("Browser connection refused/reset", "Web server down or a firewall is cutting the connection.",
                                        ["Confirm the web server is running.", "Check firewall/WAF rules."], "High")
        elif "err_too_many_redirects" in low:
            title, cause, fixes, sev = ("Browser hit a redirect loop", "Conflicting redirect rules (http↔https / www↔non-www).",
                                        ["Fix redirect rules; on Cloudflare use SSL mode 'Full (strict)'."], "High")
        elif "timeout" in low:
            title = f"Page did not finish loading within {BROWSER_NAV_TIMEOUT_MS // 1000}s"
            cause = "Server too slow/hanging, or a blocking script/resource never completes."
            fixes = ["Check server load and slow logs.", "Test the site in your own browser's Network tab to see what hangs.",
                     "Raise BROWSER_NAV_TIMEOUT_MS if the site is just heavy."]
            sev = "High"
        else:
            title, cause, fixes, sev = ("Headless browser failed to load the page", "Unknown — see the evidence line.",
                                        ["Open the URL in a normal browser and compare.", "Check the server and network."], "High")
        out.append(Finding(sev, "Browser", title, f"Page load of {url}", err[:300], cause, fixes))
        return out

    # ---------- page loaded: analyse what happened while it loaded
    # Failed / broken resources (network level)
    broken = [{"url": r["url"], "type": r["type"], "why": f"HTTP {r['status']}"} for r in b["bad"]]
    broken += [{"url": r["url"], "type": r["type"], "why": r["reason"]} for r in b["failed"]]
    seen, uniq = set(), []
    for r in broken:
        if r["url"] not in seen:
            seen.add(r["url"]); uniq.append(r)

    groups = {"first_core": [], "first_other": [], "third": []}
    for r in uniq:
        first = _root_domain(urlparse(r["url"]).hostname) == site_root
        if first and r["type"] in ("script", "stylesheet", "document", "xhr", "fetch"):
            groups["first_core"].append(r)
        elif first:
            groups["first_other"].append(r)
        else:
            groups["third"].append(r)

    fmt = lambda r: f"[{r['type']}] {r['url'][:140]} → {r['why']}"
    if groups["first_core"]:
        out.append(Finding("High", "Browser", f"{len(groups['first_core'])} of the site's own scripts/styles/API calls failed to load",
                           "Files on the same domain (listed in evidence)", "\n".join(_limit(groups["first_core"], fmt)),
                           "A missing/renamed file (404), a permissions problem (403), a crashing endpoint (5xx) or a blocked request. "
                           "Pages may look unstyled or features may not work.",
                           ["Open each URL listed — note the status code.",
                            "404: the file was deleted/renamed — redeploy it or fix the reference in the theme/template.",
                            "5xx: check the server/application error log.",
                            "After caching/CDN changes, purge the cache."]))
    if groups["first_other"]:
        out.append(Finding("Medium", "Browser", f"{len(groups['first_other'])} image/font/media file(s) on the site failed to load",
                           "Files on the same domain (listed in evidence)", "\n".join(_limit(groups["first_other"], fmt)),
                           "Deleted or renamed media files, wrong paths after a migration, or hotlink protection.",
                           ["Re-upload the missing files or correct the links.", "After a migration, search-and-replace the old domain/path."]))
    if groups["third"]:
        hosts = sorted({urlparse(r["url"]).hostname or "?" for r in groups["third"]})
        out.append(Finding("Low", "Browser", f"{len(groups['third'])} third-party resource(s) failed to load",
                           "External services: " + ", ".join(hosts[:6]), "\n".join(_limit(groups["third"], fmt)),
                           "Usually ad/analytics/widget/CDN endpoints that are blocked, down, or retired. The page itself still works.",
                           ["Check whether you still use that service; remove the embed if not.",
                            "If you do, check the vendor's status page or the embed code/API key."],
                           "Third-party vendor / site owner"))

    # JavaScript errors (code level)
    js_all = [{"msg": e["msg"], "loc": e["loc"], "kind": "uncaught exception"} for e in b["js"]]
    js_all += [{"msg": e["msg"], "loc": e["loc"], "kind": "console error"} for e in b["console"]]
    by_loc = {}
    for e in js_all:
        key = (e["loc"].rsplit(":", 1)[0] if e["loc"] else "unknown source")
        by_loc.setdefault(key, []).append(e)
    for src, errs in list(by_loc.items())[:3]:
        host = urlparse(src).hostname if src.startswith("http") else None
        first = host is not None and _root_domain(host) == site_root
        first_err = errs[0]
        out.append(Finding(
            "Medium" if first else "Low", "Browser",
            "JavaScript error in " + ("the site's own" if first else "third-party" if host else "an unknown")
            + " script (" + str(len(errs)) + " occurrence" + ("s" if len(errs) > 1 else "") + ")",
            f"{first_err['loc'] or 'source not reported by the browser'}",
            f"{first_err['kind']}: {first_err['msg'][:200]}",
            ("A bug in the site's own code or a conflict between plugins/themes — features that depend on this script may be broken."
             if first else
             "Third-party code (analytics, chat, ads, social widgets) is failing. Usually harmless to the main page."),
            (["Open the page → DevTools (F12) → Console, click the error to jump to the line.",
              "WordPress: disable plugins one by one to find the one that breaks; check jQuery is loaded once.",
              "Fix or update the offending script/plugin."]
             if first else
             ["Confirm the page works for users; if so, this is low priority.",
              "Update or remove the third-party embed; check its API key / domain whitelist."]),
            "Site developer" if first else "Third-party vendor / site owner"))
    if len(by_loc) > 3:
        out.append(Finding("Low", "Browser", f"{len(by_loc) - 3} more script source(s) reported JavaScript errors", "Browser console",
                           "Not listed to keep the report short", "See above.", ["Open DevTools → Console on the page to see the full list."]))

    if b["mixed"]:
        out.append(Finding("Medium", "Browser", "Mixed content: insecure (http://) files on an https:// page", "Browser console",
                           "\n".join(_limit(b["mixed"], lambda s: s)),
                           "The page is secure but some images/scripts are still linked with http://. Browsers block or warn about them.",
                           ["Change those links to https:// (or protocol-relative).",
                            "WordPress: run a search-replace of http://yourdomain → https://yourdomain, or use a 'SSL Insecure Content Fixer' plugin."]))

    # ---------- Render stage
    body = (b.get("body") or "").strip()
    low_body = body.lower()
    challenge = any(m in low_body[:600] for m in CHALLENGE_MARKERS) and len(body) < 800
    first_js = [f for f in out if f.stage == "Browser" and "own" in f.problem]
    if challenge:
        out.append(Finding("Medium", "Render", "Monitor was shown a challenge/block page instead of the real site",
                           f"Visible text on {b['final_url']}", body[:160].replace("\n", " "),
                           "Bot protection (captcha / 'checking your browser') is treating the headless browser as a bot. "
                           "Real visitors probably see the normal site.",
                           ["Open the site in a normal browser to confirm.", "Allow-list the monitor's IP in the WAF if you own the site.",
                            "Otherwise treat this result as inconclusive."], "Site owner (only if the site is yours)"))
    elif not b["visual"] or len(body) < 20:
        hint = (" The JavaScript error(s) reported above on the site's own scripts are the most likely culprit."
                if first_js else "")
        out.append(Finding("High", "Render", "Page loaded but shows blank / almost no content", f"Rendered page at {b['final_url']}",
                           f"Visible text: {len(body)} characters; screenshot is {'blank' if not b['visual'] else 'mostly empty'}",
                           "Front-end failed to render: a crashed JavaScript app, a PHP fatal error showing nothing (white screen), "
                           "or CSS hiding the content." + hint,
                           ["Open the screenshot and the page in DevTools → Console for red errors.",
                            "Check the server error log for a PHP fatal error (white screen of death).",
                            "WordPress: switch to a default theme and disable plugins to isolate the cause.",
                            "Clear page/CDN cache and retry."]))
    return out


# ======================================
# APP / PLUGIN CRASH DETECTION (WordPress-aware)
# ======================================

WP_PATH_RE = re.compile(r"/wp-content/(plugins|themes|mu-plugins)/([a-z0-9_.-]+)", re.I)


def _wp_components(text: str) -> list:
    """Find WordPress plugins/themes named in any URL or file path inside `text`."""
    seen, out = set(), []
    for kind, slug in WP_PATH_RE.findall(text or ""):
        kind = {"plugins": "plugin", "themes": "theme", "mu-plugins": "must-use plugin"}[kind.lower()]
        key = (kind, slug.lower())
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _wp_fix_step(kind: str, slug: str) -> str:
    if kind == "theme":
        return (f"Suspect theme '{slug}': WordPress admin → Appearance → Themes → activate a default theme (e.g. Twenty Twenty-Four) "
                f"and reload. If you can't log in, rename wp-content/themes/{slug} to {slug}-off via FTP / File Manager.")
    if kind == "must-use plugin":
        return (f"Suspect must-use plugin '{slug}': it can't be deactivated in the dashboard — via FTP / File Manager move it out of "
                "wp-content/mu-plugins and reload.")
    return (f"Suspect plugin '{slug}': WordPress admin → Plugins → Deactivate it and reload the site. If the site recovers, this plugin "
            f"is the culprit — update it, replace it, or contact its author. Can't log in? Rename wp-content/plugins/{slug} to "
            f"{slug}-off via FTP / File Manager.")


def _attach_wp_culprits(findings: list):
    """If a finding's file paths/URLs point into a WordPress plugin or theme folder, name it."""
    for f in findings:
        if f.stage not in ("HTTP", "Browser", "Render") or "⟵ WordPress" in f.where:
            continue
        comps = _wp_components(f.where + "\n" + f.evidence)
        if not comps:
            continue
        names = ", ".join(f"{k} '{sl}'" for k, sl in comps[:4])
        f.where += f"  ⟵ WordPress {names}"
        f.cause += f" The files involved belong to: {names}."
        f.fixes = [_wp_fix_step(*c) for c in comps[:2]] + f.fixes
        if not f.plain:
            f.plain = (f"The WordPress {comps[0][0]} '{comps[0][1]}' is misbehaving, so whatever it powers on the page "
                       "may be broken or missing.")


def analyze_app_errors(text: str, url: str) -> list:
    """Look inside the page for signs that the site's own software (WordPress, PHP, DB) crashed."""
    t = (text or "").lower()
    out = []
    cat = "Website software (plugin / theme / PHP crash)"
    login = "Hosting File Manager or FTP (and the WordPress admin, if you can still log in)"

    def snippet(marker, width=320):
        i = t.find(marker)
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t[max(0, i - 40): i + width])).strip()

    wp_markers = ("there has been a critical error on this website", "the site is experiencing technical difficulties")
    hit = next((m for m in wp_markers if m in t), None)
    if hit:
        out.append(Finding(
            "Critical", "HTTP", "WordPress has crashed — it is showing its 'critical error' page",
            f"The page served at {url}", f"Page text: \"{snippet(hit, 200)}\"",
            "A PHP fatal error inside a plugin or theme (very often right after an update), or a PHP version the code doesn't support.",
            ["Check the site admin's email inbox: WordPress usually sends a 'technical issue' email with a Recovery Mode link that names the plugin.",
             "No email? In FTP / File Manager rename the folder wp-content/plugins to plugins-off and reload. If the site returns, rename it back and "
             "then rename plugin folders one by one to find the culprit.",
             "Turn on logging: in wp-config.php set WP_DEBUG and WP_DEBUG_LOG to true, then read wp-content/debug.log for the exact file and line.",
             "Also check the PHP version (hosting panel) wasn't changed recently."],
            "Site owner / developer",
            plain="The website crashed because of faulty code — most often a plugin or theme — and visitors see an error message instead of the site.",
            login=login, category=cat))

    if "error establishing a database connection" in t:
        out.append(Finding(
            "Critical", "HTTP", "The website cannot reach its database",
            f"Database connection of the site at {url}", f"Page text: \"{snippet('error establishing a database connection', 120)}\"",
            "The database server is down or overloaded, the login details in wp-config.php are wrong, or the hosting account hit a limit / ran out of disk space.",
            ["Hosting panel: check the MySQL/MariaDB service is running and disk space isn't full.",
             "Check DB_NAME, DB_USER, DB_PASSWORD and DB_HOST in wp-config.php match what the host shows.",
             "Ask your host whether the account hit a resource limit.",
             "Last resort: add define('WP_ALLOW_REPAIR', true); to wp-config.php and open /wp-admin/maint/repair.php (remove the line afterwards)."],
            "Hosting provider / site owner",
            plain="The website's data store is unreachable, so every page shows an error.", login="Hosting control panel (databases) and wp-config.php",
            category="Server / database"))

    if "briefly unavailable for scheduled maintenance" in t:
        out.append(Finding(
            "High", "HTTP", "WordPress is stuck in maintenance mode", f"The page served at {url}",
            f"Page text: \"{snippet('briefly unavailable for scheduled maintenance', 120)}\"",
            "A plugin/theme/core update was interrupted and left a '.maintenance' file behind.",
            ["In FTP / File Manager open the site's root folder (where wp-config.php is) and delete the file named .maintenance (enable 'show hidden files').",
             "Then re-run the interrupted update from Dashboard → Updates."],
            "Site owner", plain="An update got stuck, so visitors see a 'briefly unavailable' notice instead of the site.", login=login, category=cat))

    fatal_markers = ("fatal error:", "parse error:", "uncaught error", "uncaught exception", "allowed memory size of")
    fm = next((m for m in fatal_markers if m in t), None)
    if fm and not hit:
        snip = snippet(fm)
        path = (re.search(r"(/[\w./-]+\.php)", snip) or [None, None])[1]
        line = (re.search(r"on line (\d+)", snip) or [None, None])[1]
        mem = fm == "allowed memory size of"
        out.append(Finding(
            "Critical", "HTTP", "PHP ran out of memory while building the page" if mem else "A PHP error crashed the page and is printed on it",
            f"{path or 'file path not shown'}" + (f" line {line}" if line else ""), f"Page text: \"{snip[:260]}\"",
            ("The page needed more memory than PHP is allowed to use — usually one heavy plugin or a huge import/query."
             if mem else "Faulty code (often a plugin, theme or custom snippet) crashed PHP; the error is shown because error display is on."),
            (["Raise the limit: in wp-config.php add define('WP_MEMORY_LIMIT', '256M'); or raise memory_limit in the hosting panel.",
              "If it comes back, deactivate recently added/updated plugins to find the heavy one."] if mem else
             ["Open the file named in WHERE — the folder name tells you which plugin/theme it belongs to.",
              "Deactivate or roll back that plugin/theme (or undo the recent code edit).",
              "Turn off public error display: set display_errors = Off (or WP_DEBUG_DISPLAY false) once fixed."]),
            "Site owner / developer",
            plain="The website's code crashed while building this page, and visitors see a raw error or a broken page.", login=login, category=cat))

    wm = re.search(r"(warning|notice|deprecated): [^\n]{0,160}? in (/[\w./-]+\.php) on line (\d+)", re.sub(r"<[^>]+>", " ", t))
    if wm and not out:
        out.append(Finding(
            "Low", "HTTP", "PHP warnings are being printed on the public page", f"{wm.group(2)} line {wm.group(3)}",
            f"{wm.group(1)}: {wm.group(0)[:200]}",
            "A plugin/theme has minor code problems and the server is set to show them to visitors. The page still works, but it looks unprofessional and leaks file paths.",
            ["Set WP_DEBUG_DISPLAY to false (or display_errors = Off) so visitors don't see them.",
             "Update the plugin/theme named in the file path, or report the warning to its author."],
            "Site owner / developer", plain="Small code warnings are visible on the page; it still works but looks broken or unprofessional.",
            login=login, category=cat))
    return out


# ======================================
# EXTRA CHECKS — blocklists, domain health, hosting, SEO / security hygiene
# Everything here is best-effort: if a lookup is blocked it is skipped, never reported as a site fault.
# ======================================

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urldefrag

DNSBL_IP = [("Spamhaus ZEN", "zen.spamhaus.org"), ("SpamCop", "bl.spamcop.net"),
            ("Barracuda", "b.barracudacentral.org"), ("PSBL", "psbl.surriel.com"),
            ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"), ("DroneBL", "dnsbl.dronebl.org"),
            ("S5H", "all.s5h.net")]
DNSBL_DOMAIN = [("Spamhaus DBL", "dbl.spamhaus.org"), ("SURBL", "multi.surbl.org")]

BOT_BLOCKING_HOSTS = ("facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com", "t.co",
                      "tiktok.com", "pinterest.com", "whatsapp.com", "wa.me", "fb.me")


# ---------- IP / domain blocklists (DNSBL) ----------

def _dnsbl(qname: str):
    try:
        r = dnsres.Resolver()
    except Exception:
        return "unknown", []
    r.lifetime = 5
    try:
        codes = [x.to_text() for x in r.resolve(qname, "A")]
    except (dnsres.NXDOMAIN, dnsres.NoAnswer):
        return "clean", []
    except Exception:
        return "unknown", []
    if any(c.startswith("127.255.255.") for c in codes):
        return "refused", codes      # list refuses queries coming through public/cloud resolvers
    return "listed", codes


def _decode_bl(list_name: str, codes: list):
    """Returns (plain label, is_minor_policy_listing)."""
    n = 0
    for c in codes:
        try:
            n = int(c.split(".")[-1])
            break
        except ValueError:
            pass
    if "Spamhaus ZEN" in list_name:
        if n in (2, 3):
            return "SBL — known spam source", False
        if 4 <= n <= 7:
            return "XBL — infected / hacked machine", False
        if n == 9:
            return "DROP — hijacked network range", False
        if n in (10, 11):
            return "PBL — home/dynamic IP range (normal for home connections, irrelevant for hosting servers)", True
    if "Spamhaus DBL" in list_name:
        labels = {2: "spam domain", 4: "phishing domain", 5: "malware domain", 6: "botnet-controller domain"}
        return labels.get(n, "abused legitimate site" if n >= 100 else "listed domain"), False
    if "SURBL" in list_name:
        flags = [lab for bit, lab in ((8, "phishing"), (16, "malware"), (64, "abuse / spam"), (128, "cracked / hacked site")) if n & bit]
        return ", ".join(flags) or "listed", False
    return "listed", False


def blocklist_check(ips: list, domain: str):
    jobs = []
    for ip in ips:
        rev = ".".join(reversed(ip.split(".")))
        for name, zone in DNSBL_IP:
            jobs.append(("ip", ip, name, f"{rev}.{zone}"))
    root = _root_domain(domain)
    for name, zone in DNSBL_DOMAIN:
        jobs.append(("domain", root, name, f"{root}.{zone}"))
    if not jobs:
        return None
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda j: _dnsbl(j[3]), jobs))
    return {"rows": [{"kind": j[0], "target": j[1], "list": j[2], "status": st, "codes": codes}
                     for j, (st, codes) in zip(jobs, res)]}


def analyze_blocklists(bl, passed: list) -> list:
    out = []
    if not bl:
        return out
    rows = bl["rows"]
    targets = []
    for r in rows:
        key = (r["kind"], r["target"])
        if key not in targets:
            targets.append(key)

    for kind, target in targets:
        mine = [r for r in rows if (r["kind"], r["target"]) == (kind, target)]
        listed = [r for r in mine if r["status"] == "listed"]
        clean = [r for r in mine if r["status"] == "clean"]
        what = "IP" if kind == "ip" else "domain"
        if not listed:
            if clean:
                passed.append(f"Blocklists: {what} {target} is not on any of the {len(clean)} lists that could be checked")
            continue

        lines, serious = [], 0
        for r in listed:
            label, minor = _decode_bl(r["list"], r["codes"])
            lines.append(f"{r['list']}: LISTED ({', '.join(r['codes'][:2])} = {label})")
            serious += 0 if minor else 1
        names = ", ".join(r["list"] for r in listed)

        if kind == "ip":
            sev = "Low" if serious == 0 else "High" if (serious >= 2 or any("Spamhaus" in r["list"] for r in listed)) else "Medium"
            out.append(Finding(
                sev, "Reputation", f"The server's IP address {target} is on {len(listed)} spam/abuse blocklist(s): {names}",
                f"IP address {target} (the server hosting the site) — listed by: {names}", "\n".join(lines),
                "Someone using this IP (your site, a hacked script, or another customer on the same shared server) was reported for "
                "spam, malware or abuse. Effects: emails sent from this server land in spam or bounce, and some security filters block the site."
                if serious else
                "Only a policy list flags this IP. That is normal for home/dynamic addresses and does not matter for a normal website server.",
                [f"See the reason for each listing: https://check.spamhaus.org and https://multirbl.valli.org (enter {target}).",
                 "Find and remove the cause: scan the site for malware / hacked files, remove spam-sending scripts or plugins, update software, change passwords.",
                 "Only then request removal on each list's delisting page (requests fail while the cause remains).",
                 "On shared hosting: ask the provider to move you to a clean or dedicated IP."] if serious else
                ["No action needed for a website server. Only act if this IP sends your email."],
                "Hosting provider (they own the IP) + you",
                plain="The server's address has a bad reputation online, which can send your emails to spam and make some security tools block the site."
                if serious else "A minor, usually harmless listing.",
                login="Your hosting provider (they own the IP) and each blocklist's removal page",
                category="IP reputation (blocklists)"))
        else:
            out.append(Finding(
                "High", "Reputation", f"The domain {target} is flagged on {len(listed)} domain blocklist(s): {names}",
                f"Domain {target} — listed by: {names}", "\n".join(lines),
                "The domain was reported for spam, phishing or malware — often because the site was hacked, or links to it appear in spam campaigns.",
                ["Scan the site: https://sitecheck.sucuri.net and Google Search Console → Security issues.",
                 "Remove hacked/malicious files and pages, update everything, change all passwords.",
                 "Then request removal: https://check.spamhaus.org (Spamhaus DBL) or https://www.surbl.org/surbl-analysis (SURBL)."],
                "Site owner",
                plain="Security services have flagged the domain as spammy or dangerous, so emails may be blocked and browsers may warn visitors.",
                login="Website admin / hosting panel to clean the site, then each list's removal page",
                category="Domain reputation (blocklists)"))

    refused = [r for r in rows if r["status"] == "refused"]
    unknown = [r for r in rows if r["status"] == "unknown"]
    usable = [r for r in rows if r["status"] in ("clean", "listed")]
    if refused or not usable:
        out.append(Finding(
            "Info", "Reputation", "Some blocklists could not be checked", "DNS blocklist servers",
            f"{len(refused)} list(s) refused the query (they block public/cloud DNS resolvers such as Google's), {len(unknown)} did not answer.",
            "Not a problem with the site.", ["Check manually: https://check.spamhaus.org and https://multirbl.valli.org"]))
    return out


# ---------- Domain health: expiry, nameservers, email records ----------

def domain_health_check(domain: str) -> dict:
    root = _root_domain(domain)
    out = {"root": root, "rdap": _rdap_lookup(domain), "ns": None, "mx": None, "spf": None, "dmarc": None}
    ns = _public_lookup(root, "8.8.8.8", "NS")
    out["ns"] = ns["records"] if ns["status"] == "OK" else None
    mx = _public_lookup(root, "8.8.8.8", "MX")
    if mx["status"] == "OK":
        out["mx"] = [r for r in mx["records"] if r.strip() not in ("0 .", "0 \".\"")]
    elif mx["status"] in ("NOANSWER", "NXDOMAIN"):
        out["mx"] = []
    txt = _public_lookup(root, "8.8.8.8", "TXT")
    if txt["status"] in ("OK", "NOANSWER"):
        out["spf"] = any("v=spf1" in r.lower() for r in txt["records"])
    dm = _public_lookup("_dmarc." + root, "8.8.8.8", "TXT")
    if dm["status"] in ("OK", "NOANSWER", "NXDOMAIN"):
        out["dmarc"] = any("v=dmarc1" in r.lower() for r in dm["records"])
    return out


def analyze_domain_health(dom, domain: str, passed: list) -> list:
    out = []
    if not dom:
        return out
    registrar = "Your domain registrar (where you bought the domain: GoDaddy, Namecheap, Squarespace/Google Domains, ...)"
    r = dom.get("rdap")
    if r and r.get("expires"):
        try:
            days = (datetime.strptime(r["expires"], "%Y-%m-%d") - datetime.now(timezone.utc).replace(tzinfo=None)).days
        except ValueError:
            days = None
        if days is not None:
            passed.append(f"Domain registration: {dom['root']} expires {r['expires']} ({days} days left)")
            if days <= 60:
                sev = "Critical" if days < 0 else "High" if days <= 7 else "Medium" if days <= 30 else "Low"
                title = (f"Domain registration EXPIRED {-days} day(s) ago" if days < 0
                         else f"Domain registration expires in {days} day(s)")
                out.append(Finding(
                    sev, "Hygiene", title, f"Registration of {dom['root']} at your registrar", f"Expiry date: {r['expires']}",
                    "The domain has not been renewed yet. If it lapses, the website AND all email on the domain stop working, and someone else can grab the name.",
                    ["Log in to your registrar and renew now (renew for multiple years if you can).",
                     "Turn on auto-renew and make sure the saved payment card is valid.",
                     "Make sure the registrar's reminder emails go to an address you read."],
                    "Domain owner",
                    plain="If the domain isn't renewed in time, the website and email on it switch off.",
                    login=registrar, category="Domain registration"))
    if dom.get("ns") is not None:
        if len(dom["ns"]) < 2:
            out.append(Finding(
                "Low", "Hygiene", "Only one nameserver is set for the domain", f"Nameserver settings of {dom['root']}",
                f"Nameservers: {', '.join(dom['ns']) or 'none'}",
                "If that single nameserver goes down, the whole domain disappears.",
                ["At the registrar / DNS host, add at least two nameservers (most DNS providers give you two or more)."],
                "Domain owner", plain="The domain's address book has no backup copy.", login=registrar, category="Domain registration"))
        else:
            passed.append(f"Nameservers: {len(dom['ns'])} found ({', '.join(n.rstrip('.') for n in dom['ns'][:2])}...)")

    mx = dom.get("mx")
    if mx:
        parts = [f"MX ok ({len(mx)})"]
        if dom.get("spf") is False:
            out.append(Finding(
                "Medium", "Hygiene", "Email: no SPF record — your emails are more likely to land in spam or be spoofed",
                f"DNS TXT records of {dom['root']}", "No record starting with v=spf1 found",
                "SPF tells receiving mail servers which servers may send email for your domain. Without it, Gmail/Outlook trust your mail less.",
                ["Add a TXT record on the domain: v=spf1 include:<your mail provider> ~all (your email provider's help page gives the exact text).",
                 "Test with https://mxtoolbox.com/spf.aspx."],
                "Domain owner", plain="Email sent from your domain may go to spam, and criminals can more easily fake your address.",
                login="Your DNS host (usually the registrar or Cloudflare)", category="Email setup (spam / spoofing protection)"))
        else:
            parts.append("SPF ok" if dom.get("spf") else "SPF unknown")
        if dom.get("dmarc") is False:
            out.append(Finding(
                "Low", "Hygiene", "Email: no DMARC record", f"DNS TXT record _dmarc.{dom['root']}", "No record starting with v=DMARC1 found",
                "DMARC tells mail providers what to do with fake emails pretending to be you; Gmail and Yahoo now expect it from domains that send email.",
                [f"Add a TXT record named _dmarc.{dom['root']} with value: v=DMARC1; p=none; rua=mailto:you@{dom['root']} (start with p=none, tighten later).",
                 "Test with https://mxtoolbox.com/dmarc.aspx."],
                "Domain owner", plain="Fake emails pretending to be your domain are not being blocked.",
                login="Your DNS host (usually the registrar or Cloudflare)", category="Email setup (spam / spoofing protection)"))
        else:
            parts.append("DMARC ok" if dom.get("dmarc") else "DMARC unknown")
        passed.append("Email setup: " + ", ".join(parts))
    return out


# ---------- Hosting info (who owns the server IP) ----------

def ip_info(ip: str):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6, headers=HTTP_HEADERS)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    org = d.get("org", "") or "unknown provider"
    place = ", ".join(x for x in (d.get("city"), d.get("country")) if x)
    summary = f"{org}" + (f" — {place}" if place else "") + f" (IP {ip})"
    if "cloudflare" in org.lower():
        summary += " — Cloudflare proxy; your real server is hidden behind it"
    return {"summary": summary, "org": org}


# ---------- Hygiene: probes, links, headers, SEO ----------

def extra_http_probe(url: str, final_url: str) -> dict:
    p = urlparse(final_url)
    origin = f"{p.scheme}://{p.netloc}"

    def get(u, **kw):
        try:
            return requests.get(u, timeout=8, headers=HTTP_HEADERS, **kw)
        except Exception:
            return None

    def robots():
        r = get(origin + "/robots.txt")
        return {"status": r.status_code if r is not None else None,
                "text": r.text[:20000].lower() if r is not None and r.status_code == 200 else ""}

    def sitemap():
        r = get(origin + "/sitemap.xml", stream=True)
        if r is None:
            return None
        code = r.status_code
        r.close()
        return code

    def http_redirect():
        if not url.startswith("https://"):
            return None
        r = get("http://" + p.netloc + "/", allow_redirects=False)
        return None if r is None else {"status": r.status_code, "location": r.headers.get("Location", "")}

    def soft404():
        r = get(origin + "/zz-monitor-nonexistent-page-4821", stream=True)
        if r is None:
            return None
        code = r.status_code
        r.close()
        return code

    with ThreadPoolExecutor(4) as ex:
        f = [ex.submit(fn) for fn in (robots, sitemap, http_redirect, soft404)]
        return {"robots": f[0].result(), "sitemap": f[1].result(), "http_redirect": f[2].result(), "soft404": f[3].result()}


def link_check(html_raw: str, final_url: str):
    if not html_raw:
        return None
    host_root = _root_domain(urlparse(final_url).hostname)
    links, seen = [], set()
    for m in re.finditer(r"<a\s[^>]*href\s*=\s*[\"']([^\"'#][^\"']*)[\"']", html_raw, re.I):
        href = m.group(1).strip()
        if href.lower().startswith(("mailto:", "tel:", "javascript:", "data:", "sms:")):
            continue
        u = urldefrag(urljoin(final_url, href))[0]
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            links.append(u)

    def is_internal(u):
        return _root_domain(urlparse(u).hostname) == host_root

    internal = [u for u in links if is_internal(u)][:15]
    external = [u for u in links if not is_internal(u)
                and not any((urlparse(u).hostname or "").endswith(b) for b in BOT_BLOCKING_HOSTS)][:8]

    def chk(u):
        code = None
        for method in ("HEAD", "GET"):
            try:
                r = requests.request(method, u, timeout=8, headers=HTTP_HEADERS, allow_redirects=True, stream=True)
                code = r.status_code
                r.close()
            except requests.exceptions.RequestException as e:
                if method == "GET":
                    return {"url": u, "error": type(e).__name__}
                continue
            if method == "HEAD" and code in (403, 404, 405, 429, 501, 999):
                continue
            break
        return {"url": u, "status": code}

    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(chk, internal + external))

    def broken(r):
        return "error" in r or r["status"] in (404, 410) or (r["status"] or 0) >= 500

    ni = len(internal)
    return {"checked": len(res),
            "internal_broken": [r for r in res[:ni] if broken(r)],
            "external_broken": [r for r in res[ni:] if broken(r)]}


NOINDEX_META = re.compile(
    r"<meta[^>]*(?:name=[\"']robots[\"'][^>]*content=[\"'][^\"']*noindex|content=[\"'][^\"']*noindex[^\"']*[\"'][^>]*name=[\"']robots[\"'])")


def _robots_blocks_all(text: str) -> bool:
    agents, group_has_rule = [], False
    for line in (text or "").splitlines():
        line = line.split("#")[0].strip().lower()
        if line.startswith("user-agent:"):
            if group_has_rule:
                agents, group_has_rule = [], False
            agents.append(line.split(":", 1)[1].strip())
        elif line.startswith(("disallow:", "allow:")):
            group_has_rule = True
            if "*" in agents and line.replace(" ", "") == "disallow:/":
                return True
    return False


def analyze_hygiene(http: dict, probe, links, url: str, passed: list) -> list:
    out = []
    h = {k.lower(): str(v) for k, v in http.get("headers", {}).items()}
    final = http["final_url"]
    https_final = final.startswith("https://")
    host_panel = "Hosting control panel / web-server settings, or Cloudflare if you use it"
    admin = "Your website admin area (e.g. WordPress dashboard) or whoever built the site"

    # --- search-engine visibility
    reasons = []
    if "noindex" in h.get("x-robots-tag", "").lower():
        reasons.append("HTTP header X-Robots-Tag contains 'noindex'")
    if NOINDEX_META.search(http.get("html", "")):
        reasons.append("the page's <meta name=\"robots\"> tag says 'noindex'")
    if probe and probe["robots"]["status"] == 200 and _robots_blocks_all(probe["robots"]["text"]):
        reasons.append("robots.txt contains 'User-agent: *' with 'Disallow: /'")
    if reasons:
        out.append(Finding(
            "High", "Hygiene", "Search engines are being told NOT to list this site",
            f"{final}  (" + "; ".join(reasons) + ")", "\n".join(reasons),
            "Usually a leftover from development/staging, or WordPress's 'Discourage search engines from indexing this site' box being ticked. "
            "(Ignore this if the site is meant to be private.)",
            ["WordPress: Settings → Reading → untick 'Discourage search engines from indexing this site' → Save.",
             "Check SEO plugins (Yoast, Rank Math) for a site-wide 'noindex' setting.",
             "Edit robots.txt to remove 'Disallow: /' (or remove the X-Robots-Tag header in the server config).",
             "Afterwards request re-indexing in Google Search Console."],
            "Site owner", plain="Google is being told to ignore the whole website, so it won't show up in search results.",
            login=admin, category="Search visibility (SEO)"))
    elif probe:
        passed.append("Search visibility: no noindex / robots.txt block found")

    # --- security headers
    missing = []
    if https_final and "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security (HSTS) — forces HTTPS")
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options — stops browsers guessing file types")
    if "content-security-policy" not in h and "x-frame-options" not in h:
        missing.append("X-Frame-Options or Content-Security-Policy — stops other sites framing yours (clickjacking)")
    if missing:
        out.append(Finding(
            "Low", "Hygiene", f"{len(missing)} recommended security header(s) missing", f"HTTP response headers from {final}",
            "\n".join("Missing: " + m for m in missing),
            "The server isn't switching on standard browser protections. Not an outage, but it weakens protection against hijacking attacks.",
            ["Nginx: add_header Strict-Transport-Security \"max-age=31536000\" always; add_header X-Content-Type-Options \"nosniff\" always; "
             "add_header X-Frame-Options \"SAMEORIGIN\" always;",
             "Apache: use 'Header always set ...' lines for the same headers.",
             "Cloudflare: Rules → Transform Rules → Modify Response Header. WordPress: a plugin such as 'HTTP Headers'."],
            "Site owner / developer", plain="Extra browser protections against hijacking are switched off. Not urgent, but recommended.",
            login=host_panel, category="Security best practice"))
    else:
        passed.append("Security headers: HSTS, X-Content-Type-Options and framing protection present")

    # --- software versions
    xp = h.get("x-powered-by", "")
    mphp = re.search(r"php/(\d+)\.(\d+)", xp.lower())
    if mphp and (int(mphp.group(1)), int(mphp.group(2))) < (8, 2):
        out.append(Finding(
            "Medium", "Hygiene", f"PHP {mphp.group(1)}.{mphp.group(2)} is out of date and no longer gets security fixes",
            f"Response header X-Powered-By: {xp}", f"X-Powered-By: {xp}",
            "PHP versions older than 8.2 no longer receive security updates (as of late 2026), so known holes stay open.",
            ["Take a full backup first.", "In your hosting panel (cPanel → Select PHP Version / MultiPHP) switch to a supported PHP (8.3 or newer).",
             "Test the site and update plugins/themes that complain."],
            "Site owner / hosting provider", plain="The site runs on old server software that no longer gets security fixes.",
            login="Hosting control panel (PHP version setting)", category="Software version"))
    sv = h.get("server", "")
    if re.search(r"/\d", sv) or (xp and not mphp) or mphp:
        out.append(Finding(
            "Low", "Hygiene", "Server reveals its exact software versions to everyone", f"Response header Server: {sv or '-'}"
            + (f" / X-Powered-By: {xp}" if xp else ""), f"Server: {sv}  X-Powered-By: {xp}",
            "Showing exact versions helps attackers pick known exploits.",
            ["Nginx: server_tokens off;  Apache: ServerTokens Prod and ServerSignature Off;  PHP: expose_php = Off."],
            "Site owner / hosting provider", plain="The server tells strangers exactly which software it runs. Minor, easy to hide.",
            login=host_panel, category="Security best practice"))

    # --- HTTP -> HTTPS
    hr = probe and probe.get("http_redirect")
    if hr:
        ok = hr["status"] in (301, 302, 307, 308) and hr["location"].lower().startswith("https://")
        if ok:
            passed.append("HTTP → HTTPS: plain http:// visitors are redirected to the secure site")
        elif hr["status"] in (200, 301, 302, 307, 308):
            out.append(Finding(
                "Medium", "Hygiene", "The insecure http:// address does not redirect to https://", f"http://{urlparse(final).netloc}/",
                f"HTTP {hr['status']}" + (f" → {hr['location']}" if hr["location"] else " (served directly, no redirect)"),
                "Visitors who type or follow an old http:// link stay on the unencrypted version; Google may index duplicates.",
                ["Add a site-wide 301 redirect from http:// to https:// (hosting panel 'Force HTTPS', .htaccess, nginx, or Cloudflare 'Always Use HTTPS')."],
                "Site owner / hosting provider", plain="People using the old insecure address aren't sent to the secure version.",
                login=host_panel, category="Security best practice"))

    # --- compression
    if "content-encoding" not in h and len(http.get("html", "")) > 20000:
        out.append(Finding(
            "Low", "Hygiene", "Pages are sent uncompressed (slower for visitors)", f"Response headers from {final}",
            "No Content-Encoding header (gzip / br) on a large page",
            "Compression is switched off, so pages are several times bigger on the wire.",
            ["Enable gzip/brotli: Nginx 'gzip on;', Apache mod_deflate, Cloudflare (on by default), or a caching plugin."],
            "Site owner / hosting provider", plain="The site is slower than it needs to be because pages aren't compressed.",
            login=host_panel, category="Performance"))

    # --- sitemap / soft 404
    if probe:
        in_robots = "sitemap:" in probe["robots"]["text"]
        if probe["sitemap"] is not None and probe["sitemap"] != 200 and not in_robots:
            out.append(Finding(
                "Low", "Hygiene", "No sitemap found (helps Google discover your pages)", f"{urlparse(final).scheme}://{urlparse(final).netloc}/sitemap.xml",
                f"HTTP {probe['sitemap']}; robots.txt lists no Sitemap line",
                "No sitemap at the standard address and none advertised in robots.txt (some sites use another path — then ignore this).",
                ["WordPress: SEO plugins (Yoast, Rank Math) or WordPress itself create /wp-sitemap.xml — add its address to robots.txt and Google Search Console."],
                "Site owner", plain="Google has a harder time finding all your pages.", login=admin, category="Search visibility (SEO)"))
        if probe["soft404"] == 200:
            out.append(Finding(
                "Low", "Hygiene", "Missing pages answer 'OK' instead of 'not found' (soft 404)", f"{urlparse(final).netloc}/<any non-existent page>",
                "A made-up page address returned HTTP 200",
                "A catch-all rule (or a single-page app) serves the home page for every address; Google may index junk URLs and broken links go unnoticed.",
                ["Make unknown addresses return a real 404 page (CMS 404 template, server rewrite rule, or SPA host setting)."],
                "Site developer", plain="Dead links don't show a proper 'page not found', which confuses Google and visitors.",
                login=admin, category="Search visibility (SEO)"))

    # --- broken links
    if links:
        ib, eb = links["internal_broken"], links["external_broken"]
        fmt = lambda r: f"{r['url'][:130]} → " + (f"HTTP {r['status']}" if "status" in r and "error" not in r else f"unreachable ({r.get('error')})")
        if ib:
            out.append(Finding(
                "Medium" if len(ib) >= 3 else "Low", "Hygiene", f"{len(ib)} broken link(s) pointing to your own pages",
                f"Links found on the page {final}", "\n".join(_limit(ib, fmt)),
                "Pages were deleted, renamed or the link was mistyped. Visitors click and land on an error page; Google ranks sites with many dead links lower.",
                ["Edit or remove each link on the page (the evidence shows the dead address).",
                 "If the page moved, add a 301 redirect from the old address to the new one (WordPress: 'Redirection' plugin).",
                 "Re-run this check afterwards."],
                "Site owner", plain="Some buttons or links on the site lead visitors to an error page.", login=admin, category="Broken links"))
        if eb:
            out.append(Finding(
                "Low", "Hygiene", f"{len(eb)} link(s) to other websites lead to dead pages", f"Outgoing links on the page {final}",
                "\n".join(_limit(eb, fmt)), "The other site removed or moved the page (or is down).",
                ["Update the link to the new address or remove it."], "Site owner",
                plain="Some links to other websites no longer work.", login=admin, category="Broken links"))
        if not ib and not eb:
            passed.append(f"Links: {links['checked']} links on the page checked, none broken")
    return out


# ======================================
# DIAGNOSIS + PER-SITE MONITOR
# ======================================

async def monitor(shared_browser, url: str) -> dict:
    t_start = time.time()
    domain = urlparse(url).hostname
    base = {"Website": url, "Platform": "Unknown", "Findings": [], "Passed": [], "Screenshot": "",
            "Pipeline": {}, "Seconds": 0.0}

    if not domain:
        f = Finding("Critical", "DNS", "URL could not be parsed", "The URL you entered", url,
                    "The URL is missing 'https://' or contains a typo.",
                    ["Type a full URL such as https://example.com/"], "You (the person running this script)")
        return {**base, "Status": "🔴 Down", "Findings": [f], "Headline": "URL is invalid",
                "Pipeline": {s: "skip" for s in STAGES}}

    loop = asyncio.get_running_loop()
    findings, passed = [], []

    # ---- DNS (everything else depends on it)
    dns = await loop.run_in_executor(None, dns_check, domain)
    if dns["ok"]:
        passed.append(f"DNS: {domain} → {', '.join(dns['ips'][:3])} ({dns['ms']} ms)")
    else:
        dns["deep"] = await loop.run_in_executor(None, dns_deep_check, domain)
    findings += analyze_dns(dns, domain)

    http = ssl_res = browser = None
    ran = {"DNS"}
    hosting = ""
    if dns["ok"]:
        is_https = url.startswith("https://")
        ssl_task = loop.run_in_executor(None, ssl_check, domain) if is_https else None
        http_task = asyncio.ensure_future(http_check(url))
        browser_task = asyncio.ensure_future(browser_check(shared_browser, url))
        # independent extra checks start immediately, in parallel with the three above
        v4 = [ip for ip in dns["ips"] if ":" not in ip][:2]
        bl_task = loop.run_in_executor(None, blocklist_check, v4, domain)
        dom_task = loop.run_in_executor(None, domain_health_check, domain)
        ipinfo_task = loop.run_in_executor(None, ip_info, v4[0]) if v4 else None

        ssl_res = await ssl_task if ssl_task else None
        http = await http_task
        browser = await browser_task

        if ssl_res:
            if ssl_res["ok"]:
                passed.append(f"SSL: valid for {ssl_res['days']} more day(s), issued by {ssl_res['issuer']} ({ssl_res['tls']})")
            findings += analyze_ssl(ssl_res, domain)

        browser_ok_visual = bool(browser.get("ok") and browser.get("visual") and len(browser.get("body", "").strip()) >= 20)
        if http["ok"]:
            passed.append(f"HTTP: {http['code']} in {http['ms']} ms (final URL: {http['final_url']})")
            base["Platform"] = detect_platform(http["html"], http["headers"])
        findings += analyze_http(http, url, browser_ok_visual)

        if browser["ok"]:
            passed.append(f"Browser: page loaded in {browser['load_ms']} ms"
                          + (f" (title: \"{browser['title'][:60]}\")" if browser.get("title") else ""))
            base["Screenshot"] = browser.get("screenshot", "")
        findings += analyze_browser(browser, url)

        # ---- second wave: reputation, domain health, hosting, hygiene (all best-effort)
        if ssl_res is not None:
            ran.add("SSL")
        if http.get("ok"):
            ran.add("HTTP")
        if browser.get("ok"):
            ran.update({"Browser", "Render"})

        probe = links = None
        if http.get("ok"):
            probe, links = await asyncio.gather(
                loop.run_in_executor(None, extra_http_probe, url, http["final_url"]),
                loop.run_in_executor(None, link_check, http.get("html_raw", ""), http["final_url"]))
        bl, dom, ipi = await asyncio.gather(
            bl_task, dom_task, ipinfo_task if ipinfo_task else asyncio.sleep(0, result=None))

        if bl:
            ran.add("Reputation")
            findings += analyze_blocklists(bl, passed)
        if ipi:
            hosting = ipi["summary"]
            passed.append(f"Hosting: {hosting}")
        findings += analyze_domain_health(dom, domain, passed)
        if http.get("ok"):
            findings += analyze_hygiene(http, probe, links, url, passed)
        if dom or http.get("ok"):
            ran.add("Hygiene")
        findings += analyze_app_errors(
            (http.get("html", "") if http else "") + "\n" + (browser.get("body") or "").lower(), url)

        if browser["ok"] and not any(f.stage == "Render" and f.severity in ("High", "Medium") for f in findings):
            passed.append("Render: page shows visible content")

    # ---- pipeline view: where does it break?
    pipeline = {}
    for st in STAGES:
        w = _worst(findings, st)
        if st == "DNS" and any(f.inconclusive for f in findings if f.stage == "DNS"):
            pipeline[st] = "unk"
        elif w is not None and w >= 3:
            pipeline[st] = "fail"
        elif w is not None and w >= 1:
            pipeline[st] = "warn"
        elif st in ran:
            pipeline[st] = "ok"
        else:
            pipeline[st] = "skip"

    # tell a layman exactly whose panel to open: the company that hosts the server
    if hosting:
        for f in findings:
            if f.stage in ("HTTP", "SSL") and not f.login:
                f.login = f"Your hosting provider's panel — this site's server is hosted at: {hosting}"

    _attach_wp_culprits(findings)
    findings.sort(key=lambda f: -SEV_RANK[f.severity])
    worst = SEV_RANK[findings[0].severity] if findings else 0
    inconclusive = bool(findings) and all(f.inconclusive for f in findings)
    status = ("⚪ Inconclusive" if inconclusive else
              "🔴 Down" if worst >= 4 else "🟡 Warning" if worst >= 2 else "🟢 Working")

    plain = ""
    if not findings:
        headline = "All checks passed — no problems found."
    else:
        top = findings[0]
        extra = f" (+{len(findings) - 1} more finding(s))" if len(findings) > 1 else ""
        headline = f"{top.stage} stage — {top.problem}{extra}"
        plain = top.plain or STAGE_INFO[top.stage]["plain"]

    return {**base, "Status": status, "Findings": findings, "Passed": passed, "Pipeline": pipeline, "Hosting": hosting,
            "Headline": headline, "Plain": plain, "Seconds": round(time.time() - t_start, 1)}


# ======================================
# REPORT PRINTING
# ======================================

PIPE_ICON = {"ok": "✅", "warn": "⚠️ ", "fail": "❌", "skip": "⏭️ ", "unk": "❓"}
WIDTH = 100


def _field(label: str, text: str, indent: int = 7):
    pad = " " * indent
    label = f"{label:<10}: "
    lines = str(text).split("\n")
    first = True
    for ln in lines:
        wrapped = textwrap.wrap(ln, WIDTH - indent - len(label), break_long_words=True) or [""]
        for w in wrapped:
            print(f"{pad}{label if first else ' ' * len(label)}{w}", flush=True)
            first = False


def print_report(idx: int, total: int, r: dict):
    line = "═" * WIDTH
    print(line, flush=True)
    print(f"[{idx}/{total}] {r['Website']}", flush=True)
    print(line, flush=True)
    print(f"STATUS  : {r['Status']}      Platform: {r['Platform']}      Checked in {r['Seconds']}s", flush=True)
    print("PIPELINE: " + "  →  ".join(f"{s} {PIPE_ICON[r['Pipeline'].get(s, 'skip')]}" for s in STAGES), flush=True)
    if r.get("Hosting"):
        print(f"HOSTING : {r['Hosting']}", flush=True)
    print(f"SUMMARY : {r['Headline']}", flush=True)
    if r.get("Plain"):
        _field("IN SHORT", r["Plain"], indent=0)

    if r["Passed"]:
        print("\nWhat is working:", flush=True)
        for p in r["Passed"]:
            print(f"  ✅ {p}", flush=True)

    probs = [f for f in r["Findings"] if f.severity != "Info"]
    major = [f for f in probs if f.severity != "Low"]
    minor = [f for f in probs if f.severity == "Low"]
    if major:
        print(f"\nProblems to fix ({len(major)}), most serious first:", flush=True)
        for i, f in enumerate(major, 1):
            info = STAGE_INFO[f.stage]
            sev_label = "COULD NOT CHECK" if f.inconclusive else f.severity.upper()
            print(f"\n  {i}. {SEV_ICON[f.severity]} {sev_label} — {f.problem}", flush=True)
            _field("TYPE", f.category or info["category"])
            _field("IN PLAIN", f.plain or info["plain"])
            _field("WHERE", f"[{f.stage} stage] {f.where}")
            _field("EVIDENCE", f.evidence)
            _field("WHY", f.cause)
            _field("FIX AT", f.login or info["login"])
            if f.owner and f.owner != "Site owner / hosting provider":
                _field("WHO FIXES", f.owner)
            print("       FIX      :", flush=True)
            for n, step in enumerate(f.fixes, 1):
                for j, w in enumerate(textwrap.wrap(step, WIDTH - 15) or [""]):
                    print(f"         {str(n) + '.' if j == 0 else '  '} {w}", flush=True)
    if minor:
        print(f"\nMinor / recommended improvements ({len(minor)}) — not urgent:", flush=True)
        for f in minor:
            info = STAGE_INFO[f.stage]
            print(f"\n  {SEV_ICON['Low']} {f.problem}", flush=True)
            _field("IN PLAIN", f.plain or info["plain"], indent=5)
            _field("WHERE", f"[{f.stage}] {f.where}", indent=5)
            _field("FIX AT", f.login or info["login"], indent=5)
            if f.evidence and "\n" not in f.evidence:
                _field("EVIDENCE", f.evidence, indent=5)
            if f.fixes:
                _field("FIRST STEP", f.fixes[0], indent=5)
    notes = [f for f in r["Findings"] if f.severity == "Info"]
    if notes:
        print("\nNotes:", flush=True)
        for f in notes:
            print(f"  ⚪ {f.problem} — {f.evidence}", flush=True)
    if r.get("Screenshot"):
        print(f"\nScreenshot: {r['Screenshot']}", flush=True)
    print(flush=True)


# ======================================
# URL INPUT — asks you when the script runs
# ======================================

def parse_urls(raw: str) -> list:
    """Split on commas, trim stray spaces, add https:// if missing, drop empties/duplicates."""
    urls, seen = [], set()
    for part in re.split(r"[,\n]+", raw or ""):
        u = part.strip().strip("\"'")
        if not u:
            continue
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
            u = "https://" + u
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def ask_for_urls() -> list:
    print("Enter the website URL to check.")
    print("For several sites, separate them with commas and NO spaces, e.g.:")
    print("    https://example.com,https://google.com,mysite.org\n")
    while True:
        raw = input("URL(s): ")
        urls = parse_urls(raw)
        if urls:
            return urls
        print("❌ Nothing entered — please type at least one URL.\n")


# ======================================
# MAIN — streams results one by one as they complete
# ======================================

async def run_all(urls, concurrency, on_result=None):
    total = len(urls)
    results = []
    sem = asyncio.Semaphore(concurrency)

    try:
        async with async_playwright() as p:
            print("→ Launching Chromium...", flush=True)
            browser = await p.chromium.launch(headless=True)
            print("→ Browser launched OK.\n", flush=True)

            async def bound_task(url):
                async with sem:
                    try:
                        return await monitor(browser, url)
                    except Exception as e:
                        import traceback
                        f = Finding("Critical", "Browser", "The monitor script itself crashed on this site", "monitor script",
                                    f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}",
                                    "A bug or unexpected response in the monitor — not necessarily a problem with the site.",
                                    ["Re-run the script.", "If it repeats for this URL, share the traceback above to debug."],
                                    "You (monitor script)")
                        return {"Website": url, "Status": "🔴 Down", "Platform": "Unknown", "Findings": [f],
                                "Passed": [], "Screenshot": "", "Pipeline": {s: "skip" for s in STAGES},
                                "Headline": "Monitor script error", "Seconds": 0.0}

            tasks = [asyncio.create_task(bound_task(url)) for url in urls]
            for done_count, coro in enumerate(asyncio.as_completed(tasks), 1):
                result = await coro
                results.append(result)
                print_report(done_count, total, result)
                if on_result is not None:
                    await on_result(result)

            await browser.close()

    except Exception as e:
        import traceback
        print(f"❌ Fatal error during run: {e}", flush=True)
        traceback.print_exc()
        if results:
            print(f"(Partial results available for {len(results)} site(s))", flush=True)
        raise

    return results


def run():
    urls = ask_for_urls()
    print(f"\n→ Will check {len(urls)} URL(s):", flush=True)
    for u in urls:
        print(f"    - {u}", flush=True)

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    print("\nHOW TO READ THE RESULTS — a visitor needs every step below to work, in this order:", flush=True)
    for st in STAGES:
        print(f"  {st:<11}= {STAGE_INFO[st]['legend']}", flush=True)
    print("  The first ❌ in the PIPELINE line is where your problem starts; each problem also tells you")
    print("  its TYPE, what it means IN PLAIN words, and which account/panel to FIX AT.", flush=True)
    print(f"\n→ Starting checks (concurrency={MAX_CONCURRENCY})...\n", flush=True)

    results = asyncio.run(run_all(urls, MAX_CONCURRENCY))

    working = sum(1 for r in results if r["Status"].startswith("🟢"))
    warning = sum(1 for r in results if r["Status"].startswith("🟡"))
    down = sum(1 for r in results if r["Status"].startswith("🔴"))
    unknown = sum(1 for r in results if r["Status"].startswith("⚪"))

    print("═" * WIDTH, flush=True)
    print("DONE", flush=True)
    print(f"Working: {working} | Warning: {warning} | Down: {down} | Inconclusive: {unknown}", flush=True)

    attention = [r for r in results if not r["Status"].startswith("🟢")]
    if attention:
        print("\nFix first (sorted by seriousness):", flush=True)
        attention.sort(key=lambda r: -max((SEV_RANK[f.severity] for f in r["Findings"]), default=0))
        for r in attention:
            top = r["Findings"][0]
            print(f"  {r['Status']}  {r['Website']}\n      → Problem : {top.problem}\n"
                  f"      → Meaning : {r.get('Plain', '')}\n"
                  f"      → Fix at  : {top.login or STAGE_INFO[top.stage]['login']}\n"
                  f"      → 1st step: {top.fixes[0] if top.fixes else 'see details above'}", flush=True)
    print(f"\nScreenshots saved to: {SCREENSHOT_DIR}/", flush=True)
    return results


class CheckRequest(BaseModel):
    urls: str = Field(min_length=1, max_length=MAX_URL_INPUT_LENGTH)


app = FastAPI(title="Website Diagnostic Monitor")
jobs = {}


def _json_result(result):
    return {
        **result,
        "Findings": [asdict(finding) for finding in result["Findings"]],
    }


async def _run_job(job_id, urls):
    job = jobs[job_id]
    job["status"] = "running"

    async def add_result(result):
        job["results"].append(_json_result(result))
        job["completed"] = len(job["results"])

    try:
        await run_all(urls, MAX_CONCURRENCY, on_result=add_result)
        job["status"] = "completed"
    except Exception as exc:
        logging.exception("Website check job %s failed", job_id)
        job["error"] = f"{type(exc).__name__}: {exc}"
        job["status"] = "failed"


@app.get("/api/health")
async def health():
    loop = asyncio.get_running_loop()
    playwright_compatible = not (
        os.name == "nt" and isinstance(loop, asyncio.SelectorEventLoop)
    )
    return {"status": "ok", "playwright_compatible": playwright_compatible}


@app.post("/api/checks", status_code=202)
async def create_check(request: CheckRequest):
    loop = asyncio.get_running_loop()
    if os.name == "nt" and isinstance(loop, asyncio.SelectorEventLoop):
        raise HTTPException(
            status_code=503,
            detail=(
                "This server uses a Windows event loop that cannot launch Playwright. "
                "Stop the old server and restart with `npm run dev`."
            ),
        )

    urls = parse_urls(request.urls)
    if not urls:
        raise HTTPException(status_code=422, detail="Enter at least one website URL.")
    if len(urls) > MAX_URLS_PER_CHECK:
        raise HTTPException(
            status_code=422,
            detail=f"Check no more than {MAX_URLS_PER_CHECK} websites at a time.",
        )
    invalid_urls = [
        url for url in urls
        if urlparse(url).scheme not in ("http", "https") or not urlparse(url).hostname
    ]
    if invalid_urls:
        raise HTTPException(
            status_code=422,
            detail=f"Only complete HTTP or HTTPS website URLs are supported: {', '.join(invalid_urls)}",
        )

    job_id = str(uuid4())
    jobs[job_id] = {
        "id": job_id,
        "status": "queued",
        "total": len(urls),
        "completed": 0,
        "results": [],
        "error": None,
    }
    asyncio.create_task(_run_job(job_id, urls))
    return {"id": job_id, "total": len(urls)}


@app.get("/api/checks/{job_id}")
async def get_check(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Check job not found.")
    return job


@app.get("/api/screenshots/{filename}")
async def get_screenshot(filename: str):
    if not re.fullmatch(r"[a-zA-Z0-9_-]+\.png", filename):
        raise HTTPException(status_code=404, detail="Screenshot not found.")
    path = os.path.abspath(os.path.join(SCREENSHOT_DIR, filename))
    screenshot_dir = os.path.abspath(SCREENSHOT_DIR)
    if os.path.commonpath([path, screenshot_dir]) != screenshot_dir or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Screenshot not found.")
    return FileResponse(path, media_type="image/png")


app.mount("/", StaticFiles(directory=os.path.join(BASE_DIR, "frontend"), html=True), name="frontend")