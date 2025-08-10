#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# forti_cert_swap.py — Upload/rotate a certificate on FortiGate and bind it to GUI, SSL-VPN, and FTM.
#
# Features (baseline kept):
#  - YAML config (-C/--config) merging with CLI
#  - Derive cert name from CN + expiry (default) or override via --name
#  - GLOBAL vs VDOM store
#  - Dry-run mode
#  - Prune older certs with same base name (after successful bindings)
#  - Rebind-only mode: --rebind <existing-cert-name>
#  - Robust retry policy (no POST/500 retry loops)
#  - Suppress warnings when --insecure
#  - TLS verify uses system store unless --insecure
#
# New in 1.8.0:
#  - --log FILE and --log-level {standard,debug}
#  - Plain, timestamped log with sensitive values scrubbed
#
# Version: 1.8.0
#
# MIT License
# Copyright (c) 2025 CyB0rgg @ Kiroshi.Group
# Co-author: Jarvis @ Kiroshi.Group


import argparse, json, os, sys, re, datetime
from typing import Optional, Tuple, Dict, Any, List

missing_msgs = []

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
except Exception:
    missing_msgs.append(("[cryptography]", "pip3 install cryptography", "sudo apt-get install python3-cryptography"))

try:
    import yaml as yml  # optional unless -C/--config used
except Exception:
    yml = None

try:
    import requests
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
except Exception:
    missing_msgs.append(("[requests]", "pip3 install requests", "sudo apt-get install python3-requests"))

if missing_msgs:
    for pkg, pip_hint, apt_hint in missing_msgs:
        print(f"[!] Missing required Python module: {pkg}\n    pip:  {pip_hint}\n    apt:  {apt_hint}")
    if any("[cryptography]" in m[0] or "[requests]" in m[0] for m in missing_msgs):
        sys.exit(1)

API_PREFIX = "/api/v2"
VERSION = "1.8.0"

# ---------------------------
# Logging (file + levels)
# ---------------------------
class Logger:
    def __init__(self, path: Optional[str], level: str):
        self.path = path
        self.level = level.lower() if level else "standard"
        self.fp = None
        if self.path:
            try:
                self.fp = open(self.path, "a", encoding="utf-8")
            except Exception as e:
                print(f"[!] Could not open log file '{self.path}': {e}")
                self.fp = None

    def _ts(self) -> str:
        return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _scrub(self, s: str) -> str:
        if not isinstance(s, str):
            try:
                s = json.dumps(s)
            except Exception:
                s = str(s)
        # basic token scrub
        s = re.sub(r"(Bearer\s+)[A-Za-z0-9._\-]+=*", r"\1<REDACTED>", s)
        s = re.sub(r"([\"']token[\"']\s*:\s*[\"']).+?([\"'])", r"\1<REDACTED>\2", s, flags=re.IGNORECASE)
        return s

    def _write(self, level: str, msg: str):
        if not self.fp:
            return
        line = f"{self._ts()} {level.upper()} {self._scrub(msg)}\n"
        try:
            self.fp.write(line)
            self.fp.flush()
        except Exception:
            pass

    def info(self, msg: str, also_stdout: bool = False):
        self._write("info", msg)
        if also_stdout:
            print(msg)

    def warn(self, msg: str, also_stdout: bool = False):
        self._write("warn", msg)
        if also_stdout:
            print(msg)

    def error(self, msg: str, also_stdout: bool = False):
        self._write("error", msg)
        if also_stdout:
            print(msg, file=sys.stderr)

    def debug(self, msg: str, also_stdout: bool = False):
        if self.level == "debug":
            self._write("debug", msg)
            if also_stdout:
                print(msg)

LOGGER = Logger(None, "standard")  # will be replaced in main()

def load_file(path: str) -> str:
    with open(path, "rb") as f:
        return f.read().decode("utf-8", errors="ignore")

def _split_pem_chain(pem: str) -> List[str]:
    parts = []
    current = []
    for line in pem.splitlines():
        if "BEGIN CERTIFICATE" in line:
            current = [line]
        elif "END CERTIFICATE" in line:
            current.append(line)
            parts.append("\n".join(current) + "\n")
            current = []
        elif current:
            current.append(line)
    return parts if parts else [pem]

def summarize_chain(cert_pem: str) -> str:
    chunks = _split_pem_chain(cert_pem)
    lines = ["[*] Certificate chain summary:"]
    for idx, chunk in enumerate(chunks):
        try:
            cert = x509.load_pem_x509_certificate(chunk.encode("utf-8"), default_backend())
            not_after = cert.not_valid_after
            cn = None
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    cn = attr.value
                    break
            if cn is None:
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    dns = san.get_values_for_type(x509.DNSName)
                    cn = dns[0] if dns else "(no CN)"
                except Exception:
                    cn = "(no CN)"
            tag = "[leaf]" if idx == 0 else f"[{idx}]"
            lines.append(f"    {tag} CN={cn}  NotAfter~{not_after.date()}")
        except Exception:
            lines.append(f"    [{idx}] <unparsed cert>")
    return "\n".join(lines)

def planned_cert_name(cert_pem: str, override: Optional[str]) -> str:
    if override:
        return override
    leaf = _split_pem_chain(cert_pem)[0]
    cert = x509.load_pem_x509_certificate(leaf.encode("utf-8"), default_backend())
    base = None
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            base = attr.value
            break
    if not base:
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns = san.get_values_for_type(x509.DNSName)
            base = dns[0] if dns else "cert"
        except Exception:
            base = "cert"
    base = re.sub(r"^\*\.", "", base.strip())
    base = re.sub(r"[^A-Za-z0-9._-]", "-", base)
    exp = cert.not_valid_after.strftime("%Y%m%d")
    return f"{base}-{exp}"

def base_from_name(name: str) -> str:
    m = re.match(r"^(.*)-\d{8}$", name)
    return m.group(1) if m else name

def load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    if yml is None:
        print("[!] YAML config requested but PyYAML is not installed.\n    pip:  pip3 install pyyaml\n    apt:  sudo apt-get install python3-yaml")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return yml.safe_load(f) or {}

def merge_args_with_config(args: argparse.Namespace, cfg: Dict[str, Any]) -> argparse.Namespace:
    # Only populate missing CLI fields from config
    for key, val in cfg.items():
        # Skip unknown keys silently
        if not hasattr(args, key):
            continue
        if getattr(args, key, None) in (None, False, 0, ""):
            setattr(args, key, val)
    return args

def print_effective(args: argparse.Namespace, used_config: bool):
    print("[*] Effective configuration:")
    print(f"    host: {args.host}")
    print(f"    port: {args.port}")
    print(f"    vdom: {'GLOBAL' if not args.vdom else args.vdom}")
    print(f"    insecure: {bool(args.insecure)}")
    print(f"    dry_run: {bool(args.dry_run)}")
    print(f"    prune: {bool(args.prune)}")
    print(f"    timeout_connect: {args.timeout_connect}s")
    print(f"    timeout_read: {args.timeout_read}s")
    if args.log:
        print(f"    log: {args.log}")
        print(f"    log_level: {args.log_level}")

def _scope_params(scope: str, vdom: Optional[str]) -> Dict[str, Any]:
    if scope == "global":
        return {"scope": "global"}
    return {"vdom": vdom or "root"}

class FortiAPI:
    def __init__(self, host: str, port: int, token: str, verify: bool, t_conn: int, t_read: int):
        self.base_url = f"https://{host}:{port}{API_PREFIX}"
        self.verify = verify
        self.timeout = (t_conn, t_read)
        self.session = self._build_session(token, verify)

    def _build_session(self, token: str, verify: bool):
        s = requests.Session()
        s.headers.update({"Authorization": f"Bearer {token}"})
        retry = Retry(
            total=2, connect=2, read=2, backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]),
            raise_on_status=False,
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry, pool_maxsize=10)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        if not verify:
            urllib3.disable_warnings(InsecureRequestWarning)
        return s

    def _req(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
             json_body: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        url = f"{self.base_url}{path}"
        LOGGER.debug(f"HTTP {method} {url} params={params or {}} json={ '<omitted>' if json_body and 'private-key' in json_body else (json_body or {}) } verify={self.verify}")
        r = self.session.request(
            method, url, params=params or {}, json=json_body, files=files,
            verify=self.verify, timeout=self.timeout
        )
        code = r.status_code
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        LOGGER.debug(f"HTTP {code} response for {method} {path}: {data if code!=200 else '<200 OK>'}")
        return code, data

    def cmdb_get(self, path: str, params: Optional[Dict[str, Any]] = None):
        return self._req("GET", f"/cmdb/{path}", params=params)

    def cmdb_post(self, path: str, json_body: Dict[str, Any], params: Optional[Dict[str, Any]] = None):
        return self._req("POST", f"/cmdb/{path}", params=params, json_body=json_body)

    def cmdb_put(self, path: str, json_body: Dict[str, Any], params: Optional[Dict[str, Any]] = None):
        return self._req("PUT", f"/cmdb/{path}", params=params, json_body=json_body)

    def cmdb_delete(self, path: str, params: Optional[Dict[str, Any]] = None):
        return self._req("DELETE", f"/cmdb/{path}", params=params)

def upload_or_update_cert(api: 'FortiAPI', name: str, cert_pem: str, key_pem: str, store: str, vdom: Optional[str], dry_run: bool) -> Tuple[str, Any]:
    params = _scope_params("global" if store == "GLOBAL" else "vdom", vdom)
    payload = {"name": name, "certificate": cert_pem, "private-key": key_pem, "range": store.lower()}
    if dry_run:
        LOGGER.info(f"DRYRUN: would POST vpn.certificate/local name={name} store={store} scope={params}")
        return "dry_run", {"would_post": True, "path": "vpn.certificate/local", "params": params}
    code, data = api.cmdb_post("vpn.certificate/local", payload, params=params)
    if code == 200:
        return "created", data
    code, data = api.cmdb_put(f"vpn.certificate/local/{name}", payload, params=params)
    if code == 200:
        return "updated", data
    return "error", {"http_status": code, "detail": data}

def bind_gui(api: 'FortiAPI', name: str, vdom: Optional[str], store: str) -> Tuple[bool, Dict[str, Any]]:
    path = "system/global"
    payload = {"admin-server-cert": name}
    code, data = api.cmdb_put(path, payload, params=_scope_params("global" if store == "GLOBAL" else "vdom", vdom))
    return (code == 200), {"http_status": code, "detail": data}

def bind_ssl_vpn(api: 'FortiAPI', name: str, vdom: Optional[str], store: str) -> Tuple[bool, Dict[str, Any]]:
    path = "vpn.ssl/settings"
    payload = {"servercert": name}
    code, data = api.cmdb_put(path, payload, params=_scope_params("global" if store == "GLOBAL" else "vdom", vdom))
    return (code == 200), {"http_status": code, "detail": data}

def bind_ftm(api: 'FortiAPI', name: str, vdom: Optional[str], store: str) -> Tuple[bool, Dict[str, Any]]:
    path = "system/ftm-push"
    payload = {"server-cert": name}
    code, data = api.cmdb_put(path, payload, params=_scope_params("global" if store == "GLOBAL" else "vdom", vdom))
    return (code == 200), {"http_status": code, "detail": data}

def list_local_certs(api: 'FortiAPI', store: str, vdom: Optional[str]) -> List[str]:
    code, data = api.cmdb_get("vpn.certificate/local", params=_scope_params("global" if store == "GLOBAL" else "vdom", vdom))
    names = []
    if code == 200 and isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
        for item in results:
            n = item.get("name")
            if isinstance(n, str):
                names.append(n)
    return names

def delete_cert(api: 'FortiAPI', name: str, store: str, vdom: Optional[str]) -> Tuple[bool, Dict[str, Any]]:
    code, data = api.cmdb_delete(f"vpn.certificate/local/{name}", params=_scope_params("global" if store == "GLOBAL" else "vdom", vdom))
    return (code == 200), {"http_status": code, "detail": data}

def prune_old(api: 'FortiAPI', current_name: str, store: str, vdom: Optional[str], do_prune: bool) -> Dict[str, Any]:
    out = {"deleted": [], "skipped": []}
    if not do_prune:
        return out
    base = base_from_name(current_name)
    names = list_local_certs(api, store, vdom)
    for n in names:
        if n == current_name:
            continue
        if base_from_name(n) != base:
            out["skipped"].append({"name": n, "reason": "different base"})
            continue
        ok, detail = delete_cert(api, n, store, vdom)
        if ok:
            out["deleted"].append(n)
        else:
            out["skipped"].append({"name": n, "reason": f"delete failed ({detail.get('http_status')})"})
    return out

def main():
    global LOGGER
    p = argparse.ArgumentParser(description="Upload/rotate FortiGate certificate and bind to GUI/SSL-VPN/FTM.")
    p.add_argument("--host", help="FortiGate hostname")
    p.add_argument("--port", type=int, help="HTTPS port (e.g., 443 or 8443)")
    p.add_argument("--token", help="REST API token")
    p.add_argument("--cert", help="PEM certificate (leaf + chain)")
    p.add_argument("--key", help="PEM private key")
    p.add_argument("--name", help="Override planned certificate name")
    p.add_argument("--vdom", help="VDOM name (omit for GLOBAL store)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--dry-run", dest="dry_run", action="store_true", help="Do not change FortiGate; show planned actions")
    p.add_argument("--prune", action="store_true", help="Delete older certs with the same base name after successful bindings")
    p.add_argument("--timeout-connect", dest="timeout_connect", type=int, default=5)
    p.add_argument("--timeout-read", dest="timeout_read", type=int, default=30)
    p.add_argument("-C", "--config", help="YAML config file")
    # Rebind-only
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--rebind", metavar="CERTNAME", help="Bind GUI/SSL-VPN/FTM to existing certificate name on FortiGate")
    # Logging
    p.add_argument("--log", help="Write a plain log to this file")
    p.add_argument("--log-level", dest="log_level", choices=["standard","debug"], default="standard",
                   help="Log verbosity when --log is used (default: standard)")

    args = p.parse_args()
    cfg = load_config(args.config) if args.config else {}
    args = merge_args_with_config(args, cfg)

    # Init logger now that we know file/level
    LOGGER = Logger(args.log, args.log_level)

    if not args.host or not args.port or not args.token:
        p.error("host, port, and token are required (via CLI or config).")
    store = "GLOBAL" if not args.vdom else "VDOM"

    if not args.rebind:
        if not args.cert or not args.key:
            p.error("cert and key are required unless --rebind CERTNAME is used.")
        cert_pem = load_file(args.cert)
        key_pem = load_file(args.key)
        print(summarize_chain(cert_pem))
        planned_name = planned_cert_name(cert_pem, args.name)
        print(f"[*] Planned certificate name: {planned_name}")
        LOGGER.info(f"planned_name={planned_name}")
    else:
        planned_name = args.rebind
        cert_pem = key_pem = None
        print(f"[*] Rebinding existing certificate: {planned_name}")
        LOGGER.info(f"rebind_only name={planned_name}")

    print(f"[*] Target store: {store}")
    print_effective(args, used_config=bool(args.config))
    LOGGER.debug(f"effective_config host={args.host} port={args.port} vdom={args.vdom or 'GLOBAL'} insecure={args.insecure} prune={args.prune} dry_run={args.dry_run} timeouts=({args.timeout_connect},{args.timeout_read})")

    # Build API client (this is where TLS verify matters)
    try:
        api = FortiAPI(args.host, int(args.port), args.token, verify=(not args.insecure),
                       t_conn=args.timeout_connect, t_read=args.timeout_read)
    except Exception as e:
        LOGGER.error(f"Failed to initialize API session: {e}")
        raise

    result = {"status": "ok", "certificate": None, "bindings": {}, "version": VERSION}

    # Upload or skip (rebind)
    if args.rebind:
        state, detail = ("rebind", {"skipped_upload": True})
        result["certificate"] = {"name": planned_name, "store": store, "state": state}
    else:
        try:
            state, detail = upload_or_update_cert(api, planned_name, cert_pem, key_pem, store, args.vdom, dry_run=args.dry_run)
        except requests.exceptions.SSLError as e:
            # Scrub and give actionable hint
            short = "certificate verify failed" if "CERTIFICATE_VERIFY_FAILED" in str(e) else "TLS/SSL error"
            print(f"[!] TLS verification failed talking to FortiGate ({short}). If expected, re-run with --insecure.")
            LOGGER.error(f"TLS verify failure: {e}")
            sys.exit(2)
        if state == "dry_run":
            payload = {"status": "dry_run", "detail": detail, "version": VERSION}
            print(json.dumps(payload, indent=2))
            LOGGER.info(json.dumps(payload))
            return
        msg = "created new" if state == "created" else ("re-uploaded existing" if state == "updated" else "failed to upload")
        http_code = detail.get('http_status', 'n/a') if isinstance(detail, dict) else 'n/a'
        print(f"[*] Result: {msg} certificate \"{planned_name}\" in {store} store (via {'cmdb_post' if state=='created' else 'cmdb_put'}, HTTP {http_code})")
        LOGGER.info(f"upload_result state={state} http={http_code}")
        result["certificate"] = {"name": planned_name, "store": store, "state": state}

    # Bindings
    gui_ok, gui_d = bind_gui(api, planned_name, args.vdom, store)
    ssl_ok, ssl_d = bind_ssl_vpn(api, planned_name, args.vdom, store)
    ftm_ok, ftm_d = bind_ftm(api, planned_name, args.vdom, store)
    LOGGER.info(f"bind_results gui={gui_ok} ssl_vpn={ssl_ok} ftm={ftm_ok}")

    result["bindings"]["gui"] = {"ok": gui_ok, "http_status": gui_d["http_status"], "detail": gui_d["detail"]}
    result["bindings"]["ssl_vpn"] = {"ok": ssl_ok, "http_status": ssl_d["http_status"], "detail": ssl_d["detail"]}
    result["bindings"]["ftm"] = {"ok": ftm_ok, "http_status": ftm_d["http_status"], "detail": ftm_d["detail"]}

    print(json.dumps(result, indent=2))
    LOGGER.debug(f"result_json={result}")

    if args.prune:
        if gui_ok and ssl_ok and ftm_ok:
            pr = prune_old(api, planned_name, store, args.vdom, do_prune=True)
            print(json.dumps({"prune": pr}, indent=2))
            LOGGER.info(f"prune={pr}")
        else:
            msg = "[!] One or more bindings failed; skipping prune to avoid deleting a cert still needed for rollback."
            print(msg)
            LOGGER.warn(msg)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass