#!/usr/bin/env python3
"""posture_check.py - passive, authorized-target web posture check (stdlib only).

Checks: DNS (A/AAAA), TLS validity/SAN/expiry/version, hybrid post-quantum key
exchange (X25519MLKEM768, needs OpenSSL 3.5+ on PATH), HTTP->HTTPS redirect
(not followed), HTTPS security headers, and well-known manifests
(llms.txt, security.txt, agent-card.json).

Footprint: a handful of GET requests and handshakes per host. No probing of hidden
paths, no fuzzing, no payloads. Use only on hosts you own or are authorized to assess.

Usage: python3 posture_check.py example.com [www.example.com ...] [--no-pq] [--timeout 10] [-o out.json]
Output: JSON {"tool", "generated_at", "targets", "findings":[finding.schema.json...], "summary"}
"""
import argparse, datetime as dt, http.client, json, shutil, socket, ssl, subprocess, sys

TOOL = "posture_check.py/1.0"
UA = "security-kit-posture-check/1.0 (+authorized assessment)"
_seq = {}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def finding(target, check, status, severity, title, detail="", evidence=None, rec="", refs=None, priority=None):
    prefix = check.split(".")[0].upper()
    _seq[prefix] = _seq.get(prefix, 0) + 1
    if priority is None:
        priority = {"critical": "P0", "high": "P0", "medium": "P1", "low": "P2"}.get(severity) if status in ("fail", "warn") else None
    return {"id": f"{prefix}-{_seq[prefix]:03d}", "check": check, "target": target, "status": status,
            "severity": severity, "title": title, "detail": detail, "evidence": evidence,
            "evidence_basis": "observed", "recommendation": rec, "priority": priority,
            "framework_refs": refs or [], "source": TOOL, "observed_at": now()}


def check_dns(host):
    out = []
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        out.append(finding(host, "dns.resolve", "pass", "info", "Host resolves", evidence={"A": v4, "AAAA": v6},
                           rec="Confirm every address belongs to your expected hosting/CDN provider; remove stray records."))
        import ipaddress
        if any(ipaddress.ip_address(a) in ipaddress.ip_network("198.18.0.0/15") for a in v4):
            out.append(finding(host, "dns.proxy", "info", "info", "Resolver returned a benchmark/fake-IP range (198.18.0.0/15)",
                               "This network likely uses a transparent proxy; DNS and plain-HTTP results are not authoritative. "
                               "Re-run DNS checks from an unproxied network or with an external resolver."))
        return out, True
    except socket.gaierror as e:
        out.append(finding(host, "dns.resolve", "fail", "high", "Host does not resolve", str(e)))
        return out, False


def check_tls(host, timeout):
    out = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert, ver, cipher = ss.getpeercert(), ss.version(), ss.cipher()
    except ssl.SSLCertVerificationError as e:
        out.append(finding(host, "tls.verify", "fail", "critical", "TLS certificate fails verification",
                           e.verify_message or str(e), rec="Issue a valid certificate covering this hostname (SAN).",
                           refs=["NIS2-21(2)(h)", "ISO27001:2022-A.8.24"]))
        return out
    except (OSError, ssl.SSLError) as e:
        out.append(finding(host, "tls.connect", "error", "high", "TLS connection failed on 443", str(e)))
        return out
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    exp = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    days = (exp - dt.datetime.now(dt.timezone.utc)).days
    out.append(finding(host, "tls.verify", "pass", "info", "TLS certificate valid for hostname",
                       evidence={"san": sans, "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                                 "not_after": exp.isoformat(), "protocol": ver, "cipher": cipher[0] if cipher else None}))
    if days < 0:
        out.append(finding(host, "tls.expiry", "fail", "critical", "Certificate expired", evidence={"days_left": days}))
    elif days < 21:
        out.append(finding(host, "tls.expiry", "warn", "high", f"Certificate expires in {days} days",
                           evidence={"days_left": days}, rec="Check auto-renewal; alert at 30 days."))
    else:
        out.append(finding(host, "tls.expiry", "pass", "info", f"Certificate expires in {days} days", evidence={"days_left": days}))
    if ver not in ("TLSv1.3", "TLSv1.2"):
        out.append(finding(host, "tls.version", "fail", "high", f"Weak protocol negotiated: {ver}", rec="Disable TLS < 1.2."))
    return out


def check_pq(host, timeout):
    exe = shutil.which("openssl")
    if not exe:
        return [finding(host, "pq.hybrid_kex", "not_tested", "info", "OpenSSL not found; PQ key exchange not tested")]
    try:
        r = subprocess.run([exe, "s_client", "-connect", f"{host}:443", "-servername", host,
                            "-groups", "X25519MLKEM768", "-brief"], input=b"", capture_output=True, timeout=timeout + 5)
        txt = (r.stdout + r.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return [finding(host, "pq.hybrid_kex", "error", "info", "PQ handshake test timed out")]
    low = txt.lower()
    if "unknown group" in low or ("invalid" in low and "groups" in low) or "unknown option" in low:
        return [finding(host, "pq.hybrid_kex", "not_tested", "info", "Local OpenSSL lacks X25519MLKEM768 (need 3.5+)")]
    neg = None
    for line in txt.splitlines():
        l = line.strip()
        if l.lower().startswith(("negotiated tls1.3 group", "server temp key", "peer temp key")):
            neg = l.split(":", 1)[1].strip()
            break
    if neg and "MLKEM" in neg.upper():
        return [finding(host, "pq.hybrid_kex", "pass", "info", "Hybrid post-quantum key exchange negotiated",
                        evidence={"group": neg}, refs=["FIPS-203"])]
    return [finding(host, "pq.hybrid_kex", "warn", "low", "No hybrid post-quantum key exchange (X25519MLKEM768)",
                    "Traffic captured today could be decrypted later (harvest-now-decrypt-later).",
                    evidence={"negotiated": neg, "handshake_ok": r.returncode == 0},
                    rec="Enable X25519MLKEM768 at the TLS terminator/CDN (OpenSSL 3.5+, BoringSSL, recent CDNs).",
                    refs=["FIPS-203", "NIS2-21(2)(h)"])]


def http_get(host, path, https, timeout):
    C = http.client.HTTPSConnection if https else http.client.HTTPConnection
    kw = {"timeout": timeout}
    if https:
        kw["context"] = ssl.create_default_context()
    c = C(host, **kw)
    try:
        c.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*"})
        r = c.getresponse()
        body = r.read(65536)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body
    finally:
        c.close()


def check_redirect(host, timeout):
    try:
        st, h, _ = http_get(host, "/", False, timeout)
    except OSError as e:
        return [finding(host, "http.redirect", "not_tested", "info", "Port 80 unreachable from this network", str(e))]
    loc = h.get("location", "")
    ev = {"status": st, "location": loc}
    if st in (301, 308) and loc.startswith("https://"):
        return [finding(host, "http.redirect", "pass", "info", f"HTTP permanently redirects to HTTPS ({st})", evidence=ev)]
    if st in (302, 303, 307) and loc.startswith("https://"):
        return [finding(host, "http.redirect", "warn", "low", f"HTTP redirect is temporary ({st})", evidence=ev,
                        rec="Use 301/308 so browsers and HSTS preload treat it as permanent.")]
    if 500 <= st < 600:
        return [finding(host, "http.redirect", "not_tested", "info", f"HTTP returned {st}; redirect could not be assessed", evidence=ev)]
    return [finding(host, "http.redirect", "fail", "medium", f"HTTP does not redirect to HTTPS (status {st})", evidence=ev,
                    rec="Redirect all HTTP to HTTPS with 301/308.", refs=["NIS2-21(2)(h)"])]


HEADER_RULES = [
    ("strict-transport-security", "medium", "Add HSTS: max-age=31536000; includeSubDomains (preload when ready)."),
    ("content-security-policy", "medium", "Add a CSP; start with report-only, avoid 'unsafe-inline'/'unsafe-eval', set frame-ancestors."),
    ("x-content-type-options", "low", "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "low", "Add Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "low", "Add a Permissions-Policy disabling unused features (camera, microphone, geolocation)."),
]


def check_headers(host, timeout):
    out = []
    try:
        st, h, _ = http_get(host, "/", True, timeout)
    except (OSError, ssl.SSLError) as e:
        return [finding(host, "headers.fetch", "error", "info", "Could not fetch HTTPS headers", str(e))]
    ref = ["OWASP-ASVS-V14", "NIS2-21(2)(e)"]
    for name, sev, rec in HEADER_RULES:
        v = h.get(name)
        if not v:
            out.append(finding(host, f"headers.{name}", "fail", sev, f"Missing {name}", rec=rec, refs=ref, evidence={"status": st}))
            continue
        status, extra = "pass", ""
        if name == "strict-transport-security":
            try:
                ma = int(v.lower().split("max-age=")[1].split(";")[0].strip())
            except (IndexError, ValueError):
                ma = -1
            if ma < 15552000:
                status, extra = "warn", "max-age below 180 days"
        if name == "content-security-policy":
            if "'unsafe-inline'" in v or "'unsafe-eval'" in v:
                status, extra = "warn", "allows unsafe-inline/unsafe-eval"
            if "frame-ancestors" not in v and "x-frame-options" not in h:
                extra += ("; " if extra else "") + "no frame-ancestors / X-Frame-Options"
                status = "warn"
        out.append(finding(host, f"headers.{name}", status, "info" if status == "pass" else "low",
                           f"{name} present" + (f" ({extra})" if extra else ""), evidence={"value": v[:300]},
                           rec="" if status == "pass" else rec, refs=ref))
    if "server" in h or "x-powered-by" in h:
        out.append(finding(host, "headers.disclosure", "info", "info", "Server/stack disclosed in headers",
                           evidence={k: h[k] for k in ("server", "x-powered-by") if k in h},
                           rec="Optional: minimize version disclosure."))
    return out


def check_wellknown(host, timeout):
    out = []
    for path, check in (("/llms.txt", "manifest.llms_txt"), ("/.well-known/security.txt", "manifest.security_txt"),
                        ("/.well-known/agent-card.json", "manifest.agent_card")):
        try:
            st, h, body = http_get(host, path, True, timeout)
        except (OSError, ssl.SSLError) as e:
            out.append(finding(host, check, "error", "info", f"Could not fetch {path}", str(e)))
            continue
        ctype = h.get("content-type", "")
        ev = {"path": path, "status": st, "content_type": ctype}
        text = body.decode("utf-8", "replace")
        html = "text/html" in ctype or text.lstrip().lower().startswith(("<!doctype html", "<html"))
        if st != 200 or html:
            sev, stt = ("low", "warn") if check == "manifest.security_txt" else ("info", "info")
            out.append(finding(host, check, stt, sev, f"{path} not published" + (" (HTML fallback page)" if st == 200 else ""),
                               evidence=ev, rec="Publish RFC 9116 security.txt with Contact and Expires." if check == "manifest.security_txt" else
                               "Optional: publish if you expose content or agents to AI clients; keep links accurate."))
            continue
        if check == "manifest.security_txt":
            low = text.lower()
            miss = [f for f in ("contact:", "expires:") if f not in low]
            exp_past = False
            for line in text.splitlines():
                if line.lower().startswith("expires:"):
                    try:
                        exp_past = dt.datetime.fromisoformat(line.split(":", 1)[1].strip().replace("Z", "+00:00")) < dt.datetime.now(dt.timezone.utc)
                    except ValueError:
                        pass
            if miss or exp_past:
                out.append(finding(host, check, "warn", "low", "security.txt incomplete or expired",
                                   evidence={**ev, "missing": miss, "expired": exp_past}, rec="Include Contact and a future Expires (RFC 9116)."))
            else:
                out.append(finding(host, check, "pass", "info", "security.txt present with Contact and Expires", evidence=ev))
        elif check == "manifest.agent_card":
            try:
                card = json.loads(text)
                keys = sorted(card)[:20] if isinstance(card, dict) else []
                out.append(finding(host, check, "info", "info", "agent-card.json present; verify every advertised endpoint exists and requires auth where needed",
                                   evidence={**ev, "keys": keys, "url": card.get("url") if isinstance(card, dict) else None}))
            except ValueError:
                out.append(finding(host, check, "warn", "low", "agent-card.json is not valid JSON", evidence=ev))
        else:
            out.append(finding(host, check, "info", "info", "llms.txt present; check its links resolve to your own hosts",
                               evidence={**ev, "bytes": len(body)}))
    return out


def run(hosts, timeout, pq):
    findings = []
    for host in hosts:
        host = host.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
        dns, ok = check_dns(host)
        findings += dns
        if not ok:
            continue
        findings += check_tls(host, timeout)
        if pq:
            findings += check_pq(host, timeout)
        findings += check_redirect(host, timeout)
        findings += check_headers(host, timeout)
        findings += check_wellknown(host, timeout)
    sev_order = ["critical", "high", "medium", "low"]
    bad = [f for f in findings if f["status"] in ("fail", "warn")]
    counts = {s: sum(1 for f in bad if f["severity"] == s) for s in sev_order}
    errors = sum(1 for f in findings if f["status"] == "error")
    verdict = "critical gaps" if counts["critical"] or counts["high"] else "needs work" if counts["medium"] or counts["low"] else "solid"
    return {"tool": TOOL, "generated_at": now(), "targets": hosts, "findings": findings,
            "summary": {"verdict": verdict, "issues_by_severity": counts, "total_checks": len(findings), "errors": errors,
                        "complete": errors == 0,
                        "disclaimer": "Passive heuristic posture check; not a penetration test, audit or certification."}}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", nargs="+")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--no-pq", action="store_true")
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    res = run(a.hosts, a.timeout, not a.no_pq)
    s = json.dumps(res, indent=2)
    if a.output:
        open(a.output, "w").write(s + "\n")
    print(s)
    return 1 if res["summary"]["verdict"] == "critical gaps" else 0


if __name__ == "__main__":
    sys.exit(main())
