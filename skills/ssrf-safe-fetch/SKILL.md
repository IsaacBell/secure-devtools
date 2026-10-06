---
name: ssrf-safe-fetch
description: "Use when writing or reviewing server code that fetches a URL it did not get from its own fixed configuration — link previews, webhooks, crawlers, import-from-URL, or enrichment of a domain or site a third party supplied. Covers server-side request forgery (SSRF): how to validate the URL and the resolved address before the request goes out, and what to test."
version: 1.0.0
---

# SSRF-safe fetch

**BLUF:** if a URL comes from outside your own fixed configuration, the server that fetches it can be pointed at its own private network. Check the address class before every request, not just the hostname, and connect to the address you checked.

## What SSRF is

Server-side request forgery (SSRF) is this: your server fetches a web address, and someone outside your organization controls that address. They do not point it at a normal public website. They point it at a place only your server can reach — its own machine (`localhost`), its office or cloud network, or the cloud provider's metadata address, which hands out credentials to whatever asks from inside. Your server does the fetching, so it crosses the fence the internet itself cannot cross. A link-preview feature, a webhook callback, a "paste a URL to import" box, and a tool that looks up facts about a domain or site a visitor typed in are the usual places this hides, because the URL is data from someone else, not a path you wrote.

## When this applies

Any server code that builds an outbound HTTP(S) request from a URL, host or domain that is not a string literal already in your source or config. If the value is user input, a webhook target a customer registered, or a site/domain to enrich or crawl, treat it as hostile until checked.

## Checklist

1. **Scheme and port.** Allow only `http` and `https`. Allow only port 80 and 443 unless the product genuinely needs another port, and then pin that port explicitly — do not allow "any port" by default. Reject `file://`, `gopher://`, `ftp://`, `dict://` and every other scheme.
2. **Resolve the host yourself, and reject every address that is not public.** Looking at the hostname is not enough — resolve it to an IP address and check the address. Give the resolution a timeout, so a slow or hostile DNS server cannot hang the check. Reject:
   - loopback: `127.0.0.0/8`, `::1`
   - private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and their IPv6 unique-local equivalent `fc00::/7`
   - link-local: `169.254.0.0/16` (this is where the cloud metadata address `169.254.169.254` lives) and IPv6 `fe80::/10`
   - carrier-grade NAT: `100.64.0.0/10`
   - unspecified and broadcast: `0.0.0.0/8`, IPv6 `::`, and `255.255.255.255`
   - multicast: `224.0.0.0/4` and IPv6 `ff00::/8`
   - reserved: `240.0.0.0/4`
   - IPv4 written inside IPv6, in any form: `::ffff:127.0.0.1`, `::ffff:7f00:1`, `64:ff9b::169.254.169.254` — unwrap it and re-check the IPv4 address
   - IPv6 transition forms that carry an IPv4 address: 6to4 `2002::/16` and Teredo `2001::/32` — unwrap the embedded IPv4 address and re-check it, or reject the whole range
   - IPv4 host forms that are not dotted decimal — decimal `2130706433`, hex `0x7f000001`, octal, and short forms such as `127.1` are all accepted by resolvers and turn into `127.0.0.1`. Resolve first, then check the resolved address; never classify the raw host string.
   - a hostname can resolve to more than one address (A/AAAA records); check every address it resolves to, not just the first
3. **Follow redirects by hand.** Do not let the HTTP client follow redirects automatically. Read the `Location` header yourself, run the full check (scheme, port, resolve, address class) on the new URL, and cap the number of hops (5 is reasonable). An allowed URL can redirect to a forbidden one.
4. **Cap bytes and time.** Set a connect timeout, a total timeout, and a maximum response size. An unbounded fetch is a denial-of-service surface even when the address is fine.
5. **Never forward credentials or cookies across a redirect to a different host.** If your client sends an `Authorization` header or a session cookie, strip it before following a redirect, or refuse the redirect outright for anything carrying credentials.
6. **Check and connect using the same parsed host.** Parse the URL once. Do not re-parse it differently for the security check than for the actual connection — that gap is where user-info and delimiter tricks live. A URL can put a user name before the at sign, so the real host is the part after it, and libraries disagree about which side of the at sign wins; treat any credentials in the URL as hostile and reject them outright. The backslash trick works the same way: a backslash where one parser expects a path separator makes another read a different host. Use one URL parse, pull the host from it, and use that same parsed value for both the check and the request.
7. **DNS can change between your check and your connection — this is DNS rebinding.** A name can resolve to a public address during your check and a private one microseconds later, when the HTTP client connects on its own. The check above is necessary but not sufficient against a determined attacker who controls DNS for their domain. For high-risk code (anything that fetches on behalf of another tenant, or that runs with real network access to sensitive internal services), do not re-resolve at connect time: resolve once, check that address, then connect directly to the checked IP address (while still sending the original `Host` header / TLS SNI for virtual hosting). This is the only way to guarantee the address you checked is the address you talk to.
8. **Webhooks and other stored URLs: validate twice, and prefer an allowlist.** A URL a customer registers today can be swapped for an internal address tomorrow, or can resolve differently later (rebinding). Validate on save, and validate again at send time, right before the request goes out. Where the product allows it, prefer an explicit allowlist of destinations over "any URL."

## Reference implementations

Each one checks the scheme and port (step 1) and the resolved address class (step 2); Python and TypeScript also follow redirects by hand (step 3). None of them strip credentials on a cross-host redirect for you (step 5 — do that in the caller), and none solve step 7 (rebinding) — see the note at the end of each. The Rust one is a sketch of the same checks, not a complete fetch loop.

### Python (`requests`)

```python
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 5
MAX_BYTES = 5 * 1024 * 1024
TIMEOUT = (3, 10)  # connect, read


def _is_public(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
        elif ip in ipaddress.ip_network("64:ff9b::/96"):
            # NAT64: the embedded IPv4 address is the last 32 bits.
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip in ipaddress.ip_network("2001::/32"):
            # Teredo: the client IPv4 is the last 32 bits, bitwise-inverted.
            ip = ipaddress.IPv4Address((int(ip) & 0xFFFFFFFF) ^ 0xFFFFFFFF)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False
    # Carrier-grade NAT, 100.64.0.0/10, is not covered by is_private.
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def assert_public_url(url: str, resolver=socket.getaddrinfo) -> str:
    """Raise ValueError if url is not safe to fetch. Returns the checked url."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"scheme not allowed: {parsed.scheme!r}")
    if "@" in (parsed.netloc or ""):
        raise ValueError("user-info in URL is not allowed")
    host = parsed.hostname
    if not host:
        raise ValueError("no host in URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError(f"port not allowed: {port}")

    try:
        infos = resolver(host, port)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve host: {host}") from exc

    for _family, _type, _proto, _canon, sockaddr in infos:
        if not _is_public(sockaddr[0]):
            raise ValueError(f"host resolves to a non-public address: {sockaddr[0]}")

    return url


def safe_fetch(url: str, *, _hop: int = 0) -> requests.Response:
    """Fetch url, checking every hop by hand. Caller must consume the
    response with a size cap, e.g. resp.iter_content(..., decode_unicode=False)
    stopped at MAX_BYTES, since this function does not download the body."""
    assert_public_url(url)
    resp = requests.get(
        url,
        timeout=TIMEOUT,
        allow_redirects=False,
        stream=True,
    )
    if resp.is_redirect or resp.is_permanent_redirect:
        location = resp.headers.get("Location")
        if not location:
            raise ValueError("redirect with no Location header")
        resp.close()
        if _hop >= MAX_REDIRECTS:
            raise ValueError("too many redirects")
        return safe_fetch(urljoin(resp.url, location), _hop=_hop + 1)
    return resp
```

Rebinding note: `safe_fetch` resolves twice (once in `assert_public_url`, again when `requests` opens the socket). For high-risk use, resolve once and connect to that exact IP while still presenting the original host for virtual hosting and TLS. `requests` cannot do this by itself: its `verify` argument takes a bool or a CA-bundle path, never a hostname, and it has no argument that sets the connection address separately from the URL — passing a hostname to `verify` either raises or loads a nonexistent file, and it never sets the TLS SNI. The plain-stdlib route is to subclass `http.client.HTTPSConnection` and connect to the numeric IP while passing `server_hostname=host` to the TLS wrap; `urllib3`'s connection classes and `httpx`'s custom transports expose the same split if you would rather stay in those libraries. If your stack cannot separate the connect address from the host, run the fetch in a sandbox that has no route to internal addresses instead. This is the connect-to-the-checked-address pattern from checklist step 7.

### TypeScript (Node, `undici`/global `fetch`)

```ts
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);
const ALLOWED_PORTS = new Set(["", "80", "443"]);
const MAX_REDIRECTS = 5;
const MAX_BYTES = 5 * 1024 * 1024;

// Expand an IPv6 literal into eight 16-bit groups, or null if it is malformed.
function expandIPv6(address: string): number[] | null {
  const body = address.split("%")[0];
  const parts = body.split("::");
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const fill = parts.length === 2 ? new Array(missing).fill("0") : [];
  const groups = [...head, ...fill, ...tail];
  if (groups.length !== 8) return null;
  const out: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    out.push(parseInt(group, 16));
  }
  return out;
}

function ipv4TailToText(groups: number[]): string {
  const hi = groups[6];
  const lo = groups[7];
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

function isPublicIPv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return false;
  }
  const [a, b] = octets;
  if (a === 0) return false; // 0.0.0.0/8, unspecified
  if (a === 127) return false; // loopback
  if (a === 10) return false; // private
  if (a === 172 && b >= 16 && b <= 31) return false; // private
  if (a === 192 && b === 168) return false; // private
  if (a === 169 && b === 254) return false; // link-local, includes 169.254.169.254
  if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
  if (a >= 224) return false; // multicast 224/4, reserved 240/4, broadcast 255.255.255.255
  return true;
}

function isPublicIPv6(address: string): boolean {
  // Fold a dotted-quad tail (`::ffff:127.0.0.1`) into two hex groups first.
  let normalized = address;
  const dotted = address.match(/^(.*):(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const raw = dotted[2].split(".").map(Number);
    if (raw.length === 4 && raw.every((o) => Number.isInteger(o) && o >= 0 && o <= 255)) {
      const hi = ((raw[0] << 8) | raw[1]).toString(16);
      const lo = ((raw[2] << 8) | raw[3]).toString(16);
      normalized = `${dotted[1]}:${hi}:${lo}`;
    }
  }
  const groups = expandIPv6(normalized.toLowerCase());
  if (!groups) return false;
  if (groups.every((g) => g === 0)) return false; // ::, unspecified
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return false; // ::1, loopback
  // IPv4-mapped `::ffff:0:0/96` and NAT64 `64:ff9b::/96` carry an IPv4 address.
  const isMapped =
    groups[0] === 0 && groups[1] === 0 && groups[2] === 0 &&
    groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
  const isNat64 =
    groups[0] === 0x64 && groups[1] === 0xff9b &&
    groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0;
  if (isMapped || isNat64) return isPublicIPv4(ipv4TailToText(groups));
  if ((groups[0] & 0xffc0) === 0xfe80) return false; // link-local fe80::/10
  if ((groups[0] & 0xfe00) === 0xfc00) return false; // unique-local fc00::/7
  if ((groups[0] & 0xff00) === 0xff00) return false; // multicast ff00::/8
  if (groups[0] === 0x2002) return false; // 6to4, 2002::/16
  if (groups[0] === 0x2001 && groups[1] === 0) return false; // Teredo, 2001::/32
  return true;
}

function isPublicAddress(address: string): boolean {
  const bare = address.replace(/^\[/, "").replace(/\]$/, "");
  const version = isIP(bare);
  if (version === 4) return isPublicIPv4(bare);
  if (version === 6) return isPublicIPv6(bare);
  return false;
}

export async function assertPublicUrl(urlText: string): Promise<URL> {
  const url = new URL(urlText);
  if (!ALLOWED_SCHEMES.has(url.protocol)) {
    throw new Error(`scheme not allowed: ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new Error("user-info in URL is not allowed");
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    throw new Error(`port not allowed: ${url.port}`);
  }

  const hostname = url.hostname.replace(/^\[/, "").replace(/\]$/, "");
  const records = await lookup(hostname, { all: true, verbatim: true });
  for (const record of records) {
    if (!isPublicAddress(record.address)) {
      throw new Error(`host resolves to a non-public address: ${record.address}`);
    }
  }
  return url;
}

export async function safeFetch(urlText: string, hop = 0): Promise<Response> {
  const url = await assertPublicUrl(urlText);
  const resp = await fetch(url, { redirect: "manual" });

  const isRedirect =
    resp.status === 301 || resp.status === 302 || resp.status === 303 ||
    resp.status === 307 || resp.status === 308;

  if (isRedirect) {
    const location = resp.headers.get("location");
    if (!location) throw new Error("redirect with no Location header");
    if (hop >= MAX_REDIRECTS) throw new Error("too many redirects");
    return safeFetch(new URL(location, url).toString(), hop + 1);
  }

  const reader = resp.body?.getReader();
  if (!reader) return resp;
  // Buffer the body so the caller gets a readable Response, not a consumed one.
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BYTES) {
      await reader.cancel();
      throw new Error("response too large");
    }
    chunks.push(value);
  }
  return new Response(new Blob(chunks), {
    status: resp.status,
    statusText: resp.statusText,
    headers: resp.headers,
  });
}
```

Rebinding note: same gap as the Python version — `lookup()` and `fetch()`'s own resolution are two separate DNS calls. For high-risk use, resolve once, then connect to the literal IP with a `Host` header set to the original hostname (Node's `http.request` accepts an IP in `host` and a `Host` header override), instead of letting `fetch` re-resolve the hostname.

### Rust (`reqwest`), sketch

```rust
// This is a sketch of the checks, not a complete fetch loop. Disable
// automatic redirects; reqwest's default follows up to 10 hops without
// re-checking the address.
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
}

fn is_private_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified() // 0.0.0.0/8
        || a.is_multicast() // 224.0.0.0/4
        || o[0] >= 240 // reserved 240.0.0.0/4, broadcast 255.255.255.255
        || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT, 100.64.0.0/10
}

fn assert_public_url(url: &url::Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("scheme not allowed: {}", url.scheme()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("user-info in URL is not allowed".into());
    }
    let port = url.port_or_known_default().ok_or("no port")?;
    if port != 80 && port != 443 {
        return Err(format!("port not allowed: {port}"));
    }
    let host = url.host_str().ok_or("no host")?;
    for addr in (host, port).to_socket_addrs().map_err(|e| e.to_string())? {
        let ip = addr.ip();
        let bad = match ip {
            IpAddr::V4(a) => is_private_v4(a),
            IpAddr::V6(a) => {
                let s = a.segments();
                a.is_loopback()
                    || a.is_unspecified()
                    || (s[0] & 0xfe00) == 0xfc00 // unique-local, fc00::/7
                    || (s[0] & 0xffc0) == 0xfe80 // link-local, fe80::/10
                    || (s[0] & 0xff00) == 0xff00 // multicast, ff00::/8
                    || a.to_ipv4_mapped().map(is_private_v4).unwrap_or(false)
                    || s[0] == 0x2002 // 6to4, 2002::/16
                    || (s[0] == 0x2001 && s[1] == 0) // Teredo, 2001::/32
                    || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64, 64:ff9b::/96
            }
        };
        if bad {
            return Err(format!("host resolves to a non-public address: {ip}"));
        }
    }
    Ok(())
}
// Loop: assert_public_url, send with the redirect-disabled client, read
// `Location` by hand on a 3xx, re-run assert_public_url on it, cap hops.
```

Rebinding note: same gap as above. `to_socket_addrs()` and reqwest's own connect are two resolutions. For high-risk use, resolve once and connect by IP, overriding the TLS SNI / `Host` header to the original hostname (reqwest's `resolve()` builder method can pin a hostname to a specific `SocketAddr` for this purpose).

## Hostile inputs to test against

Any guard function must reject every one of these, and must accept an ordinary public URL (`https://example.com/`):

1. `http://localhost/` and `http://localhost:80/`
2. `http://127.0.0.1/`
3. `http://[::1]/`
4. `http://169.254.169.254/` (cloud metadata address)
5. `http://0x7f000001/` (loopback written as hex)
6. `http://2130706433/` (loopback written as a decimal integer)
7. `http://0177.0.0.1/` (loopback written as octal) and `http://127.1/` (short form that resolves to `127.0.0.1`)
8. `http://0.0.0.0/` (unspecified), `http://224.0.0.1/` (multicast), and `http://255.255.255.255/` (broadcast)
9. `http://[::]/` (IPv6 unspecified) and `http://[ff02::1]/` (IPv6 multicast)
10. `http://[64:ff9b::a9fe:a9fe]/` (NAT64 carrying `169.254.169.254`), `http://[2002:7f00:1::]/` (6to4 carrying loopback), and `http://[2001::1]/` (Teredo)
11. a public-looking hostname that a DNS lookup resolves to a loopback or private address (stub the resolver in the test; do not rely on a real record)
12. a redirect from an allowed URL to an internal address (`http://evil.example/` responding `302` to `http://169.254.169.254/`)
13. `file:///etc/passwd`
14. `gopher://127.0.0.1:6379/`
15. `http://127.0.0.1:22/` and `http://127.0.0.1:6379/` (disallowed ports on a loopback address — the port check and the address check are both needed)
16. a URL that puts a user name before the at sign, so the real host is the part after it (this catches a parser disagreement about which side is the real host); reject any credentials in the URL. Also test a URL that uses a backslash where a parser expects a path separator, which makes some libraries read a different host than others.

## Testing without the network

Test literal IP and loopback-name cases directly — no network needed, they fail at the address-class check. For the DNS-dependent cases (hostname resolving to loopback, redirect to an internal address), stub the resolver / HTTP transport in the test rather than making a real request.
