# Separate routing and TLS delegation

This alternative uses explicit TLSA pins for server authorization.

This proposal separates routing from TLS authorization. HTTPS records select
where to connect; TLSA records explicitly authorize the service's TLS key or
certificate.
Changing a route does not grant permission to replace that TLS authorization.

The service can be `identity`, `app.identity`, or `_pubky.identity`.
Delegation covers the exact service name, not all its subnames. Login,
sessions, and file-write permissions remain separate.

Assume DANE-aware clients. Reuse DANE naming and verification where possible,
with Pkarr signatures authenticating records instead of DNSSEC. This is a
proposed adaptation; the inspected SDK does not implement it.

## Two signed chains

Examples use role names in place of full public-key labels:

- `identity`: the user's main key and trust anchor.
- `provider`: the operator's key managing the delegated service.
- `router`: the key managing endpoint selection.
- `tls-manager`: the key authorizing TLS pins and certificate names.
- `tls`: the server's TLS key, represented below by its SPKI hash.

Each commented record group belongs to its signer's Pkarr packet:

```dns
; Signed by identity: stable delegation to the provider
identity.              300 IN HTTPS 0 provider.
_443._tcp.identity.    300 IN CNAME _443._tcp.provider.
; Signed by provider: internal management roles
provider.              300 IN HTTPS 0 router.
_443._tcp.provider.    300 IN CNAME _443._tcp.tls-manager.
; Signed by router
router.                300 IN HTTPS 1 edge.example. port=443
; Signed by tls-manager
_443._tcp.tls-manager. 300 IN TLSA 3 1 1 <hash-of-tls-spki>
```

The client verifies two paths rooted in `identity`:

- **Routing:** `identity -> provider -> router` selects `edge.example:443`.
- **TLS authorization:** TLSA-name CNAMEs lead from `identity` through
  `provider` to `tls-manager`, whose TLSA record authorizes `tls`.

The identity owner chooses the provider, not its internal managers. The
provider can replace either manager without changing the owner's records,
or manage both roles directly without additional keys.

The client connects to the selected endpoint and accepts it only if the TLS
handshake satisfies the authorized TLSA record. Direct requests retain the
original URL, HTTP authority, and, in this example, SNI `identity`.
The TLS key needs no Pkarr packet of its own.

A compromised `router` can misdirect or block traffic, but cannot authorize a
new TLS key. Using the same signing keys for both paths remains possible,
but does not isolate a compromised signer. Two chains also cost more records;
mixed updates can leave routing and authorization inconsistent, so clients
must reject an unauthorized key.

**Alternative: one chain.** One HTTPS chain could select both the route and the
TLSA publisher. This saves a separate authorization chain, but routing changes
can change who authorizes TLS. Selecting the final delegate as the TLSA base
through HTTPS aliases would also be a Pubky extension.

## HTTPS routing

- `HTTPS 0 target` follows the target's HTTPS records.
- `HTTPS 1 target` selects an endpoint without following its HTTPS records.
  A target of `.` uses addresses at the record's owner name.
- Ordinary DNS may supply endpoint addresses, but must not become the
  authority for the Pubky service's TLS key.

HTTPS targets do not change the URL, HTTP authority, or TLSA base name.
Standard HTTPS service binding keeps the original name for SNI
([RFC 9460][https-identity], [SNI rules][https-sni]). This proposal allows
the TLS delegate to select SNI through signed TXT metadata, described below;
the routing target alone cannot select it.

## TLSA authorization

TLSA binds a TLS key or certificate to a service. Standard DANE authenticates
these records through DNSSEC; this proposal authenticates each Pkarr hop by
its packet signature. The TLSA chain determines authorization independently
of the HTTPS route.

### Allowed records

The first field selects the verification mode, the second selects SPKI (`1`)
or the full certificate (`0`), and the last field below selects SHA-256 (`1`)
([TLSA fields][tlsa-fields]):

- **`3 1 1` (DANE-EE):** pins the DER-encoded SPKI. It accepts a raw key,
  self-signed X.509, or CA-issued X.509. CA validation, certificate names,
  and validity dates are ignored.
- **`3 0 1` (DANE-EE with Pubky validity checks):** pins the full DER-encoded
  X.509 certificate, self-signed or CA-issued. Require the current time to be
  within `notBefore` / `notAfter`. Raw keys cannot satisfy it. CA validation
  and certificate-name matching are not required.
- **`1 1 1` (PKIX-EE):** pins the DER-encoded SPKI and requires X.509 with a
  CA chain trusted by the client, a matching certificate name, and valid
  `notBefore` / `notAfter` dates, including expiry.

Each candidate must match an authorized hash and satisfy its verification
mode and Pubky policy ([PKIX-EE][pkix-ee]). A CA-required policy must not fall
back to usage `3` on failure. Pins at one service name form an accepted set;
different endpoint policies need different service names.

Identical SPKI gives the same pin whether presented directly or in X.509.
TLSA does not select the TLS presentation; both peers must support it
([raw public keys][raw-public-keys]). Raw keys have no certificate expiry.
Renewal with unchanged SPKI needs no pin update for `3 1 1` or `1 1 1`;
`3 0 1` requires a new pin on renewal, even with the same key.

### Standard DANE and our deviation

Standard DANE-EE, including `3 0 1`, authenticates the server through the TLSA
association without requiring a CA chain. It must accept certificate-name
mismatches and ignore certificate expiry. The binding's lifetime instead
comes from DNSSEC signature validity ([RFC 7671, section 5.1][dane-ee]).

Our `3 0 1` policy checks both validity dates when establishing a connection.
The pin commits to those dates: an attacker holding only the TLS
private key cannot extend them without a new certificate hash and fresh TLSA
authorization. This bounds acceptance of that certificate, including when an
old signed packet still advertises it. It requires a reliable client clock
and timely renewal; it does not prove the delegation chain is current.

We retain DANE-EE's lack of CA and name checks. The signed TLSA chain already
binds the certificate to the service, allowing a shared certificate across
identities without a registrar or CA dependency. Pkarr authentication and
certificate validity checks are explicit Pubky deviations; ordinary DANE
clients will not enforce the added expiry rule.

A client requiring expiring full-certificate pins must accept only `3 0 1`
pins for that policy, without falling back to SPKI pins such as `3 1 1`.
Otherwise a parallel key pin could authorize an expired or replacement
certificate and bypass the bound.

### Service names and lookups

Start with the original service name as the TLSA base. Use the selected
connection's port and transport: for `identity` over TCP port 9443, query
`_9443._tcp.identity`, even if the URL is `https://identity:8443/`.
HTTP authority remains `identity:8443`. Mapping ports across the delegated
chain still needs specification.

A CNAME on the TLSA query name moves the pin lookup without changing the
base ([TLSA delegation][dane-provider]). In the main example, the lookup ends
at `_443._tcp.tls-manager`, but the base remains `identity`. Without the TXT
extension below, SNI and mode `1` certificate-name checks use `identity`
([name checks][dane-names]). An authenticated hostname CNAME can change the
base under standard DANE ([CNAME rules][dane-cname]); this proposal keeps
routing and certificate naming independent instead.

### Certificate name via TXT

The TLS delegate may publish an optional TXT record alongside its TLSA records:

```dns
; Signed by identity: stable delegation
identity.           300 IN HTTPS 0 provider.
_443._tcp.identity. 300 IN CNAME _443._tcp.provider.
; Signed by provider: independently changeable settings
provider.           300 IN HTTPS 1 . port=443
provider.           300 IN A 203.0.113.10
_443._tcp.provider. 300 IN TLSA 1 1 1 <hash-of-tls-spki>
_443._tcp.provider. 300 IN TXT "pubky-tls-name=edge.example"
```

The client connects to `203.0.113.10:443`, sends SNI `edge.example`, and
requires the pinned SPKI, a trusted CA chain, a matching certificate name,
and valid certificate dates. The URL and HTTP authority remain `identity`.
It does not resolve `edge.example` for addresses or replacement pins.

Proposed rules:

- Read TXT only at the terminal TLSA owner, from the same verified Pkarr
  packet as the pins. Metadata from routing or intermediate delegates has
  no effect. The selected name applies to the entire TLSA set at that owner.
- Concatenate each TXT record's character strings before parsing
  ([TXT format][txt-format]). Allow at most one `pubky-tls-name=` entry,
  containing one concrete ASCII DNS hostname without a port or wildcard.
  Reject malformed or multiple entries; ignore unrelated TXT records.
- Use that name for SNI. For `1 1 1`, accept a certificate matching either
  the original TLSA base or this additional name; the pin, CA chain, and
  validity checks remain mandatory. Usage `3` gains no certificate-name
  check from TXT. Without TXT, retain the original service name.

DANE permits protocol-specific additional acceptable certificate names, but
normally requires SNI to be the TLSA base ([RFC 7671][dane-names]). Defining
this TXT field and using it for SNI are explicit Pubky extensions. Ordinary
DANE and HTTPS clients do not interpret it.

The provider can change routes, pins, and the declared name in its signed
records without changing the identity owner's delegation. A routing-only
delegate cannot change the name. CA validation remains optional through the
choice of TLSA mode, preserving the ability to leave that dependency.

### Deployment examples

Reuse the stable `identity -> provider` delegation from the TXT example.
Each example replaces the provider's records; the
identity owner's records stay unchanged. All connections below use TCP 443.

#### No domain: raw key or self-signed certificate

```dns
; Signed by provider
provider.           300 IN HTTPS 1 . port=443
provider.           300 IN A 203.0.113.10
_443._tcp.provider. 300 IN TLSA 3 1 1 <hash-of-tls-spki>
```

The client connects to the IP and verifies the TLS key. The server may present
it as a raw key or inside a self-signed certificate. No CA, certificate-name,
or expiry check is required; no TXT name is needed.

To authorize one exact X.509 certificate with expiry checks instead, replace
the TLSA record with:

```dns
_443._tcp.provider. 300 IN TLSA 3 0 1 <hash-of-full-certificate>
```

This works with self-signed or CA-issued certificates. Renewal needs a new
pin, even when the key stays the same.

#### ICANN domain for routing and its CA certificate

```dns
; Signed by provider
provider.           300 IN HTTPS 0 edge.example.
_443._tcp.provider. 300 IN TLSA 1 1 1 <hash-of-tls-spki>
_443._tcp.provider. 300 IN TXT "pubky-tls-name=edge.example"
; Ordinary DNS for edge.example
edge.example.       300 IN HTTPS 1 . port=443
edge.example.       300 IN A 203.0.113.10
```

Routing follows the domain's HTTPS records and addresses. The server presents
its CA certificate for `edge.example`; TXT selects that name for SNI and
certificate matching. Pubky clients also require the Pkarr-signed SPKI pin.
Ordinary clients visiting `https://edge.example/` use normal WebPKI.

The operator manages routing in ordinary DNS and certificate issuance through
its CA. Same-key renewal needs no Pkarr update; key rotation does. Changing
the domain requires a provider packet update, but no identity-owner update.
Pubky requests keep URL and HTTP authority `identity`, so the server must
accept that HTTP authority even though SNI is `edge.example`.

For addresses only, use `HTTPS 1 edge.example. port=443` in the provider's
packet; that does not follow the domain's HTTPS settings. To reuse the same
certificate without CA/name checks, use `3 1 1`, or `3 0 1` for an exact
certificate with validity checks. TXT can still select SNI.

#### Independent routing and TLS managers

The provider splits its internal permissions while the owner's delegation
stays unchanged:

```dns
; Signed by provider
provider.              300 IN HTTPS 0 router.
_443._tcp.provider.    300 IN CNAME _443._tcp.tls-manager.
; Signed by router
router.                300 IN HTTPS 1 gateway.example. port=443
; Signed by tls-manager
_443._tcp.tls-manager. 300 IN TLSA 1 1 1 <hash-of-tls-spki>
_443._tcp.tls-manager. 300 IN TXT "pubky-tls-name=edge.example"
```

`gateway.example` supplies the address; the TLS server there must present the
pinned CA certificate matching an acceptable name, normally `edge.example`.
SNI is `edge.example`; URL and HTTP authority remain `identity`. The router
can change destinations but cannot change pins or the declared TLS name.
The provider retains authority to replace either manager.

#### Full handoff to ICANN DNS: outside this proposal

An operator might also want TLSA pins and name metadata managed entirely in
the domain's DNS zone, avoiding Pkarr updates on TLS-key rotation:

```dns
; Signed by provider
provider.               300 IN HTTPS 0 edge.example.
_443._tcp.provider.     300 IN CNAME _443._tcp.edge.example.
; DNSSEC-authenticated records for edge.example
edge.example.           300 IN HTTPS 1 . port=443
edge.example.           300 IN A 203.0.113.10
_443._tcp.edge.example. 300 IN TLSA 1 1 1 <hash-of-tls-spki>
_443._tcp.edge.example. 300 IN TXT "pubky-tls-name=edge.example"
```

**The proposed verifier rejects this handoff:** its terminal pins and TXT must
come from a signed Pkarr packet. Accepting it would require a separate policy
allowing DNSSEC-authenticated terminal TLSA and TXT records. A TLSA-name
CNAME alone still does not change the certificate reference name; accepting
the domain's TXT would also need that policy.

Here the domain's DNSSEC authority could replace pins and names, and its CA
would validate the certificate. The provider could revoke the handoff through
its signed records, preserving the public-key identity and an exit path, but
service authentication would depend on ICANN DNS authority while it is active.
The preceding domain example preserves independent Pkarr authorization.

#### Browser SDK using WebTransport

Use `3 0 1` for whole-certificate pinning through `serverCertificateHashes`.
WebTransport exchanges streams and datagrams with a dedicated server endpoint.
It enforces validity, matching our added check, and limits certificate lifetime
to two weeks. That limit comes from WebTransport. Renewal needs a new pin
([WebTransport][webtransport]).

#### Multiple servers or TLS-key rotation

```dns
; Signed by provider; routing records omitted
_443._tcp.provider. 300 IN TLSA 3 1 1 <hash-of-old-tls-spki>
_443._tcp.provider. 300 IN TLSA 3 1 1 <hash-of-new-tls-spki>
```

Either key may serve the identity during the overlap. Remove retired pins
afterward. The same pattern works for two `1 1 1` pins with a shared TXT name,
or two `3 0 1` certificate pins, subject to their verification checks.

## Homeserver discovery

For `_pubky.identity`, routing starts at that name and TLS authorization starts
at `_443._tcp._pubky.identity`:

```dns
; Signed by identity
_pubky.identity.           300 IN HTTPS 0 provider.
_443._tcp._pubky.identity. 300 IN CNAME _443._tcp.provider.
; Signed by provider
provider.                  300 IN HTTPS 1 . port=443
provider.                  300 IN A 203.0.113.10
_443._tcp.provider.        300 IN TLSA 3 1 1 <hash-of-tls-spki>
```

Here `provider` manages both paths, while `tls` remains a separate TLS key.
The service name remains `_pubky.identity`. The website at `identity` needs
its own records; `app.identity` starts at `_443._tcp.app.identity`.

The inspected homeserver helper reports the immediate `_pubky` target.
Adding `_pubky.identity -> controller -> provider` can therefore make it report
`controller`. Update the helper or retain `_pubky.identity -> provider`.
Publishing tools must update both chains when changing homeservers.

## Rotation and revocation

Publish the old and new pins, allow caches to refresh, switch the server's
key or certificate, then remove the old pin. Clients accept either during
the overlap. With `3 0 1`, this also applies to certificate renewal with the
same key; complete the switch before the old certificate expires. When
moving endpoints, publish authorization before routing to the new endpoint.

For a compromised key, remove its authorization promptly without an overlap.
`identity` can replace `provider`; `provider` can replace `router` or
`tls-manager`.
Mainline nodes holding newer versions reject older replacements
([BEP 44][bep44]), but clients may still hold old policy. The examples'
300-second TTL is a cache setting, not proof of freshness. Refreshed policy
must invalidate affected connections and TLS sessions.

## Client integration

### Inspected implementation

These observations refer to the pinned sources listed below:

- **Native SDK:** follows signed service records and accepts a resolved
  endpoint's signing key in raw-key TLS. The homeserver uses one Ed25519 key
  for packet signing and TLS; the client does not verify TLSA authorization.
- **Browser SDK:** rewrites requests to an advertised ordinary domain and uses
  WebPKI. Native clients can also take this route. The API carries the user's
  identity in a path or `pubky-host`.
- **pkdns:** exposes Pkarr records through DNS; it does not change browser TLS
  verification.

The resolver follows public-key targets in either HTTPS mode and its verifier
accepts any resolved endpoint key. The SDK recognizes bare keys and
`_pubky.identity`; generic `app.identity` support needs work.

### Native clients

Clients need to distinguish HTTPS modes, verify both signed chains, and
validate the selected endpoint against TLSA using the original service's
TLSA base and any authorized TXT name. Pins and TXT must come from the same
verified packet. Missing or invalid authorization must fail, without falling
back to the endpoint signer's key or ordinary WebPKI.

Client and server must support the chosen TLS presentation and independent
TLS-key configuration. For `1 1 1`, the verifier enforces both normal CA
validation and the SPKI pin. Old native clients work only while the endpoint
still presents the signing key they expect. Legacy domain access remains
WebPKI and does not enforce the Pubky delegation policy.

### Browser clients

`fetch()` exposes no custom TLS verifier or peer SPKI
([Fetch specification][fetch-api]). JavaScript packet verification therefore
does not enforce TLSA on the connection. Service workers and WASM using
`fetch()` have the same limit.

SDK transport and navigation to `https://identity/` are separate goals.
Possible paths need evaluation:

- **WebSocket tunnel:** the SDK runs inner TLS/HTTP over a byte relay and
  enforces the TLSA policy. The relay can block traffic but cannot read inner
  plaintext. This needs framing, session handling, replaceable relays, and a
  trusted SDK bootstrap; browser cookies do not become inner HTTP cookies.
- **Pinned WebTransport:** uses the whole-certificate pin in the
  [deployment examples](#deployment-examples). It needs a dedicated endpoint;
  P-256 is the interoperable algorithm. It does not enable ordinary navigation.
- **Installed software:** an extension can call a verifier through
  [native messaging][native-messaging], or a local TLS proxy can verify
  upstream TLS and issue browser-facing certificates under local trust.
  Both are trusted with plaintext. Navigation also needs resolution and routing.
- **Browser support:** verify Pkarr chains and TLSA, apply SNI rules, and
  preserve origin isolation across redirects, subresources, cookies, caches, and
  connection reuse. pkdns resolution alone cannot supply those checks.

## Open decisions

- Define authenticated policy or client configuration for permitted TLSA modes
  and enforcement of the CA-required or expiring-certificate policy.
- Decide whether to cap certificate lifetime for `3 0 1`; checking dates alone
  allows arbitrarily long validity periods. WebTransport imposes its own cap.
- Specify port mapping, QUIC transport labels, and SNI when the original
  service name is not a valid DNS hostname and no TXT name is supplied.
- Bound chain depth, branching, lookup time, and retries. Decide whether a
  verified endpoint can be used before slower routing branches finish.
- Define authorization freshness and a bound on replaying old signed packets.
  Cache TTL is not an authorization expiry. Our `3 0 1` validity check bounds
  certificate acceptance, but does not establish freshness of either chain.
- Define invalidation of resumed TLS sessions, early data, and cross-origin
  connection reuse after authorization changes, and how certificate expiry
  affects existing connections and resumption.
- Measure complete packets, including rotation records, within the DHT budget.

## Implementation sources

| Area | Inspected source |
|------|------------------|
| User discovery records and immediate HS lookup | [SDK Pkdns](https://github.com/pubky/pubky-homeserver/blob/4c4e350145d1c2ba7bf128c1caaf982c70c91e18/pubky-sdk/src/actors/pkdns.rs) |
| Native transport and domain fallback | [Native client](https://github.com/pubky/pubky-homeserver/blob/4c4e350145d1c2ba7bf128c1caaf982c70c91e18/pubky-sdk/src/client/http_targets/native.rs) |
| Browser transport | [Browser client](https://github.com/pubky/pubky-homeserver/blob/4c4e350145d1c2ba7bf128c1caaf982c70c91e18/pubky-sdk/src/client/http_targets/wasm.rs) |
| Storage addressing | [SDK storage adapter](https://github.com/pubky/pubky-homeserver/blob/4c4e350145d1c2ba7bf128c1caaf982c70c91e18/pubky-sdk/src/client/http_targets/storage.rs) |
| Server records and TLS key | [Record publisher](https://github.com/pubky/pubky-homeserver/blob/4c4e350145d1c2ba7bf128c1caaf982c70c91e18/pubky-homeserver/src/republishers/key_republisher.rs), [TLS listener](https://github.com/pubky/pubky-homeserver/blob/4c4e350145d1c2ba7bf128c1caaf982c70c91e18/pubky-homeserver/src/client_server/app.rs) |
| Pkarr endpoint traversal and TLS checks | [Resolver](https://github.com/pubky/pkarr/blob/0275a1be25d69f68153b720029f8cffbbce2e7b2/pkarr/src/extra/endpoints/mod.rs), [Verifier](https://github.com/pubky/pkarr/blob/0275a1be25d69f68153b720029f8cffbbce2e7b2/pkarr/src/extra/tls.rs) |
| DNS answers in this repository | [Pkarr resolver](../server/src/resolution/pkd/pkarr_resolver.rs), [Query matching](../server/src/resolution/pkd/query_matcher.rs) |

[https-identity]: https://www.rfc-editor.org/rfc/rfc9460.html#section-2.3
[https-sni]: https://www.rfc-editor.org/rfc/rfc9460.html#section-9.4
[dane-ee]: https://www.rfc-editor.org/rfc/rfc7671.html#section-5.1
[pkix-ee]: https://www.rfc-editor.org/rfc/rfc7671.html#section-5.3
[dane-provider]: https://www.rfc-editor.org/rfc/rfc7671.html#section-6
[dane-cname]: https://www.rfc-editor.org/rfc/rfc7671.html#section-7
[dane-names]: https://www.rfc-editor.org/rfc/rfc7671.html#section-10.2
[tlsa-fields]: https://www.rfc-editor.org/rfc/rfc6698.html#section-2
[txt-format]: https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.14
[raw-public-keys]: https://www.rfc-editor.org/rfc/rfc7250.html#section-3
[bep44]: https://www.bittorrent.org/beps/bep_0044.html#mutable-items
[fetch-api]: https://fetch.spec.whatwg.org/#requestinit
[webtransport]:
  https://www.w3.org/TR/webtransport/#webtransportoptions-dictionary
[native-messaging]:
  https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
