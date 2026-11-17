#!/usr/bin/env python3
"""Simulate AP41's move from Server.IssuerUrl=https://ap41.uw.osg-htc.org:8444 (the Origin itself) to the
Origin's per-namespace embedded issuer, inside a private Pelican federation built from the published v26.0
images (see compose.yaml):

  discovery   stand-in for https://osg-htc.org's federation discovery, pointing at this federation
  registry, director
  origin      AP41's Origin (XRootD, StorageType posix) with stages/<stage>.yaml. Its IssuerKeysDirectory
              holds the simulated AP signing key, as AP41's must for the AP's tokens to verify today.
  cache       a Cache, which builds its XRootD token config from the Director's namespace ads
  client      where test requests come from

For every stage, the Origin is restarted with that stage's config. The script waits until the Director
serves the new advertisement, restarts the Cache so it rebuilds its token config, and then records, for
/ospool/ap41:
  - the issuers the Director advertises (X-Pelican-Authorization, X-Pelican-Token-Generation)
  - the issuer sections XRootD was given on the Origin and on the Cache (saved under .sim/report/)
  - for each token, whether it can write and read at the Origin, and read through the Cache:
      old AP        iss=https://ap41.uw.osg-htc.org:8444, signed by the AP key
      new AP        iss=<ap41 embedded issuer>, signed by the AP key
      slash-iss     iss=<ap41 embedded issuer> + "/", signed by the AP key
      unpublished   iss=<ap41 embedded issuer>, signed by a key nobody publishes (always refused)
  - what the embedded issuer's discovery and JWKS endpoints publish, and the Origin's server-wide JWKS
and compares each with the expected result.

Usage:
  python3 -I verify.py [stage ...]    run the given stages (default: all), then tear down
  python3 -I verify.py up [stage]     bring the federation up at a stage (default 0-current) and leave it
  python3 -I verify.py down           tear down
Requires docker and openssl. Nothing leaves this machine.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "compose.yaml"
SIM = HERE / ".sim"
REPORT = SIM / "report"
IMAGES = [f"hub.osg-htc.org/pelican_platform/{c}:v26.0" for c in ("origin", "cache", "director", "registry")]
ORIGIN, CACHE, CLIENT = "ap41-switch-over-origin", "ap41-switch-over-cache", "ap41-switch-over-client"
EXT = "https://ap41.uw.osg-htc.org:8444"     # AP41's Server.ExternalWebUrl
XROOTD = "https://ap41.uw.osg-htc.org:8443"  # AP41's Origin.Url
CACHE_URL = "https://cache:8443"
DIRECTOR = "https://director:8444"
NS = "/ospool/ap41"
STORAGE = "/storage/ap41"
OLD = EXT                                    # AP41's Server.IssuerUrl today
NEW = f"{EXT}/api/v1.0/issuer/ns{NS}"
NEW_SLASH = NEW + "/"

TOKENS = ["old AP", "new AP", "slash-iss", "unpublished"]

# Expected behaviour per stage: issuers the Director advertises for /ospool/ap41, which tokens are accepted
# (the same at the Origin and through the Cache), and whether the embedded issuer exists.
STAGES = {
    "0-current":                dict(adv=[OLD],      accept={"old AP"}, embedded=False),
    # With the default issuer, the advertised URL keeps the export's trailing slash while the issuer names
    # itself without one; the slash spelling fails under XRootD too (".../ap41//.well-known/..." is a 404).
    "1a-issuer-on-only":        dict(adv=[NEW_SLASH], accept=set(),     embedded=True),
    "1b-issuer-on-pinned":      dict(adv=[OLD],      accept={"old AP"}, embedded=True),
    "2-both-issuers":           dict(adv=[NEW, OLD], accept={"old AP", "new AP"}, embedded=True),
    "4a-old-issuer-dropped":    dict(adv=[NEW],      accept={"new AP"}, embedded=True),
    "4c-server-issuer-removed": dict(adv=[NEW],      accept={"new AP"}, embedded=True),
    "4b-defaults":              dict(adv=[NEW_SLASH], accept=set(),     embedded=True),
}

failures: list[str] = []


def check(ok: bool, what: str, detail: str = "") -> None:
    print(f"    {'PASS' if ok else 'FAIL'}  {what}" + (f"  (got {detail})" if detail and not ok else ""))
    if not ok:
        failures.append(what)


def run(*cmd: str, env: dict | None = None, check_rc: bool = True) -> str:
    result = subprocess.run(cmd, capture_output=True, env=env)
    if check_rc and result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{result.stderr.decode()}{result.stdout.decode()}")
    return result.stdout.decode()


def compose(stage: str, *args: str) -> None:
    run("docker", "compose", "-f", str(COMPOSE), *args, env={**os.environ, "SIM_DIR": str(SIM), "STAGE": stage})


def curl(url: str, token: str | None = None, method: str = "GET", data: str | None = None) -> tuple[int, dict, str]:
    """Request from inside the federation. Returns status, headers (lists of values) and body."""
    cmd = ["docker", "exec", CLIENT, "curl", "-s", "-D", "/tmp/headers", "-o", "/tmp/body", "-w", "%{http_code}",
           "--max-time", "30", "-X", method, url]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if data is not None:
        cmd += ["--data-binary", data]
    status = int(run(*cmd, check_rc=False).strip() or 0)
    headers: dict[str, list[str]] = {}
    for line in run("docker", "exec", CLIENT, "cat", "/tmp/headers", check_rc=False).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers.setdefault(key.strip().lower(), []).append(value.strip())
    body = run("docker", "exec", CLIENT, "cat", "/tmp/body", check_rc=False)
    return status, headers, body


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def thumbprint(members: dict) -> str:
    """RFC 7638 thumbprint: the kid Pelican assigns to a PEM key."""
    return b64url(hashlib.sha256(json.dumps(members, separators=(",", ":"), sort_keys=True).encode()).digest())


def short(url: str) -> str:
    return {OLD: "old (Origin itself)", NEW: "ap41-embedded", NEW_SLASH: "ap41-embedded/"}.get(url, url)


# ---------------------------------------------------------------- simulation material

OPENSSL_CNF = """
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[v3_srv]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:osg-htc.org
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def ec_kid(pem: Path) -> str:
    der = subprocess.run(["openssl", "ec", "-in", str(pem), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    point = der[-65:]
    assert point[0] == 4, "unexpected EC public key encoding"
    return thumbprint({"crv": "P-256", "kty": "EC", "x": b64url(point[1:33]), "y": b64url(point[33:])})


def build_sim() -> None:
    """Create .sim/ once: the test CA, the discovery stand-in's certificate and document, the simulated AP
    key (also installed as the Origin's signing key) and an unpublished key. Kept between runs so the
    Origin's and Cache's registrations stay valid."""
    if (SIM / "ap-keys" / "ap.pem").exists():
        return
    for sub in ("ca", "ap-keys", "origin-keys", "cache-keys", "discovery-tls", "discovery-www/.well-known", "work"):
        (SIM / sub).mkdir(parents=True, exist_ok=True)
    work = SIM / "work"
    cnf = work / "openssl.cnf"
    cnf.write_text(OPENSSL_CNF)

    ca_key, ca_pem = SIM / "ca" / "ca.key", SIM / "ca" / "ca.pem"
    run("openssl", "req", "-x509", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
        "-out", str(ca_pem), "-days", "30", "-subj", "/CN=ap41-switch-over test CA",
        "-config", str(cnf), "-extensions", "v3_ca")
    tls = SIM / "discovery-tls"
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tls / "server.key"),
        "-out", str(work / "server.csr"), "-subj", "/CN=osg-htc.org", "-config", str(cnf))
    run("openssl", "x509", "-req", "-in", str(work / "server.csr"), "-CA", str(ca_pem), "-CAkey", str(ca_key),
        "-CAserial", str(work / "ca.srl"), "-CAcreateserial", "-out", str(tls / "server.pem"), "-days", "30",
        "-extfile", str(cnf), "-extensions", "v3_srv")

    ap_pem = SIM / "ap-keys" / "ap.pem"
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ap_pem))
    shutil.copy(ap_pem, SIM / "origin-keys" / "ap41-signing-key.pem")
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out",
        str(SIM / "ap-keys" / "unpublished.pem"))

    (SIM / "discovery-www" / ".well-known" / "pelican-configuration").write_text(json.dumps({
        "director_endpoint": DIRECTOR,
        "namespace_registration_endpoint": "https://registry:8444",
        "jwks_uri": f"{DIRECTOR}/.well-known/issuer.jwks",
        "broker_endpoint": "",
    }))
    for path in SIM.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)


# ---------------------------------------------------------------- waiting

def wait(what: str, condition, timeout: int = 240, interval: int = 3):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = condition()
        if last:
            return last
        time.sleep(interval)
    print(f"    (timed out after {timeout}s waiting for {what})")
    return last


def director_view() -> tuple[int, list[str], str]:
    status, headers, _ = curl(f"{DIRECTOR}{NS}/migration-test/seed.txt")
    auth = [h.removeprefix("issuer=") for h in headers.get("x-pelican-authorization", [])]
    gen = (headers.get("x-pelican-token-generation") or [""])[0]
    return status, auth, gen.split(",")[0].removeprefix("issuer=") if gen else ""


def scitokens_cfg(container: str) -> str:
    return run("docker", "exec", container, "sh", "-c",
               "cat /run/pelican/xrootd/*/scitokens-*-generated.cfg 2>/dev/null", check_rc=False)


def issuer_sections(cfg: str) -> dict[str, str]:
    """issuer URL -> base_path, from an XRootD scitokens config."""
    out, current = {}, None
    for line in cfg.splitlines():
        m = re.match(r"\s*issuer\s*=\s*(\S+)", line)
        if m:
            current = m.group(1)
            out[current] = ""
        m = re.match(r"\s*base_path\s*=\s*(.+)", line)
        if m and current:
            out[current] = m.group(1).strip()
    return out


def bring_up(stage: str) -> None:
    build_sim()
    compose(stage, "up", "-d", "discovery", "registry", "director", "client")
    compose(stage, "up", "-d", "--force-recreate", "origin")
    want = STAGES[stage]["adv"]
    if not wait("the Director to serve this stage's advertisement", lambda: director_view()[1] == want):
        print(f"    Director view: {director_view()}")
    run("docker", "exec", ORIGIN, "sh", "-c",
        f"mkdir -p {STORAGE}/migration-test && echo seed > {STORAGE}/migration-test/seed.txt && chmod -R a+rwX {STORAGE}")
    compose(stage, "up", "-d", "--force-recreate", "cache")
    wait("the Cache's XRootD token config to list this stage's issuers",
         lambda: set(want) <= set(issuer_sections(scitokens_cfg(CACHE))))
    wait("the Cache to serve", lambda: curl(f"{CACHE_URL}/")[0] not in (0,), timeout=120)


# ---------------------------------------------------------------- per-stage checks

def mint(issuer: str, subject: str, pem: str) -> str:
    cmd = ["docker", "exec", ORIGIN, "pelican-server", "origin", "token", "create",
           "--issuer", issuer, "--subject", subject, "--audience", "https://wlcg.cern.ch/jwt/v1/any",
           "--scope", "storage.read:/", "--scope", "storage.create:/", "--lifetime", "900", "--private-key", pem]
    return [line for line in run(*cmd).splitlines() if line.startswith("eyJ")][-1]


def run_stage(name: str) -> dict:
    want = STAGES[name]
    print(f"\n== {name} (stages/{name}.yaml) ==")
    bring_up(name)

    status, auth, gen = director_view()
    print(f"    Director: HTTP {status}; advertised {[short(u) for u in auth]}; token generation {short(gen) or '(none)'}")
    check(auth == want["adv"], f"{name}: Director advertises the expected issuers", str(auth))
    check(gen == want["adv"][0], f"{name}: Director token-generation issuer", gen)

    REPORT.mkdir(parents=True, exist_ok=True)
    for role, container in (("origin", ORIGIN), ("cache", CACHE)):
        cfg = scitokens_cfg(container)
        (REPORT / f"{name}-{role}-scitokens.cfg").write_text(cfg)
        for issuer, base in issuer_sections(cfg).items():
            if base.startswith(NS):
                print(f"    XRootD on {role}: issuer {short(issuer)} -> base_path {base}")

    tokens = {
        "old AP": mint(OLD, "old-ap", "/sim/ap.pem"),
        "new AP": mint(NEW, "new-ap", "/sim/ap.pem"),
        "slash-iss": mint(NEW_SLASH, "slash-iss", "/sim/ap.pem"),
        "unpublished": mint(NEW, "unpublished", "/sim/unpublished.pem"),
    }
    result = {"adv": [short(u) for u in auth], "origin": set(), "cache": set()}
    for tname, token in tokens.items():
        expected = tname in want["accept"]
        fname = f"{name}-{tname}.txt"
        put, _, _ = curl(f"{XROOTD}{NS}/migration-test/{fname}", token, "PUT", fname)
        get, _, body = curl(f"{XROOTD}{NS}/migration-test/seed.txt", token)
        ok = put in (200, 201, 204) and get == 200 and body.strip() == "seed"
        if ok:
            result["origin"].add(tname)
        check(ok == expected, f"{name}: {tname} token {'accepted' if expected else 'refused'} at the Origin",
              f"PUT {put}, GET {get}")
        cget, _, cbody = curl(f"{CACHE_URL}{NS}/migration-test/seed.txt", token)
        cok = cget == 200 and cbody.strip() == "seed"
        if cok:
            result["cache"].add(tname)
        check(cok == expected, f"{name}: {tname} token {'accepted' if expected else 'refused'} through the Cache",
              f"GET {cget}")

    ap_kid = json.loads(base64.urlsafe_b64decode(tokens["old AP"].split(".")[0] + "=="))["kid"]
    status, _, body = curl(f"{EXT}/api/v1.0/issuer/ns{NS}/.well-known/openid-configuration")
    iss = json.loads(body).get("issuer") if status == 200 else None
    jstatus, _, jbody = curl(f"{EXT}/api/v1.0/issuer/ns{NS}/.well-known/issuer.jwks")
    ns_kids = {k["kid"] for k in json.loads(jbody).get("keys", [])} if jstatus == 200 else set()
    print(f"    ap41 embedded issuer: discovery HTTP {status}" + (f" issuer={iss}" if iss else "")
          + f"; JWKS HTTP {jstatus}, {len(ns_kids)} key(s)")
    if want["embedded"]:
        check(iss == NEW, f"{name}: embedded discovery names the per-namespace issuer", str(iss))
        check(ns_kids == {ap_kid}, f"{name}: embedded issuer publishes exactly the AP key", str(ns_kids))
    else:
        check(status == 404, f"{name}: no embedded issuer yet", str(status))

    _, _, sbody = curl(f"{EXT}/.well-known/openid-configuration")
    sdisco = json.loads(sbody)
    _, _, skbody = curl(sdisco.get("jwks_uri", f"{EXT}/.well-known/issuer.jwks"))
    server_kids = {k["kid"] for k in json.loads(skbody).get("keys", [])}
    print(f"    Origin's own discovery: issuer={sdisco.get('issuer')}; JWKS {len(server_kids)} key(s)")
    check(server_kids == {ap_kid}, f"{name}: the Origin's own JWKS is exactly the AP key", str(server_kids))
    return result


def main(args: list[str]) -> int:
    if args[:1] == ["down"]:
        compose("0-current", "down")
        return 0
    if args[:1] == ["up"]:
        stage = args[1] if len(args) > 1 else "0-current"
        bring_up(stage)
        print(f"Federation up at {stage}. Tear down with: python3 -I verify.py down")
        return 0

    selected = args or list(STAGES)
    unknown = [s for s in selected if s not in STAGES]
    if unknown:
        print(f"unknown stage(s) {unknown}; choose from {list(STAGES)}")
        return 2
    for image in IMAGES:
        print(run("docker", "inspect", "--format", "{{index .RepoDigests 0}}", image).strip())
    print(run("docker", "run", "--rm", "--entrypoint", "pelican-server", IMAGES[0], "--version").splitlines()[0])

    rows = []
    try:
        for name in selected:
            rows.append((name, run_stage(name)))
    finally:
        compose("0-current", "down")

    print("\nSummary: where each token is accepted (Origin / Cache)")
    print(f"  {'stage':26} {'Director advertises':42} " + " ".join(f"{t:13}" for t in TOKENS))
    for name, res in rows:
        cells = [f"{'ok' if t in res['origin'] else '-'} / {'ok' if t in res['cache'] else '-'}" for t in TOKENS]
        print(f"  {name:26} {', '.join(res['adv']):42} " + " ".join(f"{c:13}" for c in cells))
    print(f"\n{len(failures)} failure(s)" + (": " + "; ".join(failures) if failures else ""))
    print(f"XRootD token configs for every stage: {REPORT}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
