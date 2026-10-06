# Routing and TLS delegation

This proposal separates two permissions: **HTTPS records select where to
connect; signed TLS CNAMEs select who may authenticate the server.** A TLS
delegate can be a Pubky key or the CA system for an ICANN domain.

## Overview

### A user delegates to a provider

Role names such as `identity` and `provider` stand for full public-key names.
Each group belongs to its signer's Pkarr packet:

```dns
; Signed by identity
identity.           IN HTTPS 0 provider.
_443._tcp.identity. IN CNAME _443._tcp.provider.
; Signed by provider
provider.           IN HTTPS 1 . port=443
provider.           IN A 203.0.113.10
```

The CNAME at `_443._tcp.identity` is the **TLS CNAME**. Because `provider`
publishes no further TLS CNAME, its key is the TLS authority. The client
connects to `203.0.113.10:443`, where the provider can present either:

- **Its raw public key:** the server proves possession of `provider`'s private
  key. That key lives on the serving machine and has no expiry.
- **A certificate signed by `provider`:** the server uses a separate TLS
  key. The client checks the issuer signature, certificate name, and validity
  period (`notBefore` / `notAfter`), and proof that the server possesses the
  corresponding private key. This lets the provider keep its signing key off the
  live server and issue certificates with limited lifetimes.

SNI and certificate-name checks use `provider`. Native requests retain the
original URL and HTTP authority `identity`, which the backend must accept. The
provider can change servers and issue new certificates without an identity-owner
update.

### Cloudflare Tunnel on Free: CA-only TLS

Configure the tunnel to serve `edge.example` and publish:

```dns
; Signed by provider
provider.           IN HTTPS 1 edge.example. port=443
_443._tcp.provider. IN CNAME _443._tcp.edge.example.

; Cloudflare DNS configuration, not a Pkarr record
edge.example.       IN CNAME <tunnel-id>.cfargotunnel.com.
```

The domain's CNAME routes traffic to the configured tunnel ([Cloudflare DNS
setup][cloudflare-dns]). Clients use SNI `edge.example` and validate its CA
certificate. The tunnel alias does not change the TLS name. Browser requests to
`https://edge.example/` also use HTTP authority `edge.example`, carrying the
Pubky identity in the application request.

Cloudflare terminates client TLS with its managed edge certificate. **There is
no Pubky check of that server key**, and CA renewal needs no Pubky record
update.

### Pubky TLS plus a CA endpoint

Keep TLS delegation ending at `provider`, with a Pubky TLS route and a separate
CA endpoint for browser requests:

```dns
; Signed by provider: no further TLS CNAME
provider. IN HTTPS 1 . port=443
provider. IN A 203.0.113.10
provider. IN TXT "pubky-ca-endpoint=https://edge.example/"
```

Pubky clients connect to `203.0.113.10:443`, use SNI `provider`, and verify its
key or signed certificate. Web apps verify the endpoint declaration and Fetch
`https://edge.example/` with CA validation. Both paths can serve the same
backend. On one server, SNI can select the appropriate certificate.

## Design details

The following sketches how names, permissions, and credentials could fit
together. The checks describe the proposed trust boundaries; the exact protocol
still needs design work.

### HTTPS routing

The idea is to reuse the record modes from [RFC 9460][https-rules]:

- **`HTTPS 0 target`:** follow the target's HTTPS records, using its name
  exactly as written. Ignore parameters on this AliasMode record.
- **`HTTPS N target`, where `N > 0`:** use the target's addresses and this
  ServiceMode record's parameters. Do not follow the target's HTTPS records. A
  target of `.` uses the record owner's addresses.
- Prefer lower priorities; shuffle equal priorities. Follow routing CNAMEs.
  Apply standard `mandatory`, `alpn`, and `no-default-alpn` compatibility rules.

Thus `HTTPS 1 edge.example. port=443` uses the domain's addresses; `HTTPS 0
edge.example.` also delegates connection settings to its HTTPS records. Neither
authorizes that domain's TLS credentials.

Every public-key lookup, including address lookups, would use a complete,
verified Pkarr packet. Its signer would have authority only within its own
namespace. Ordinary DNS could supply routes without changing TLS authority.

The proposed resolver would need a compatible ServiceMode record. It would skip
unsupported candidates, including HTTP/3-only endpoints, and stop if none
remained. There would be no fallback to bare addresses; `HTTPS 0 .`  would mean
unavailable.

To keep routes unambiguous, the proposal would reject malformed parameters,
mixed modes, multiple AliasMode records, and CNAMEs alongside other routing
records at the same owner. Missing or invalid packets, cycles, and exhausted
lookup limits would also stop resolution. Retries would retain the TLS policy.
Limits would cover delegation hops, queries, and elapsed time.

Requiring ServiceMode and rejecting ambiguous sets are stricter than ordinary
HTTPS resolution. They prevent fallback from bypassing connection settings.
Address hints and routing CNAMEs grant no TLS authority; a hostname CNAME does
not delegate child names such as `_443._tcp.identity`.

### Service names and ports

For `https://identity/`, query HTTPS at `identity`; for
`https://identity:8443/`, query `_8443._https.identity` ([RFC
9460][https-query]). After an alias, use its exact target. A ServiceMode `port`
selects the connection port; otherwise retain the original URL port.

For TLS authorization, the proposed starting name is
`_<connection-port>._tcp.<original-service>`. TLS CNAMEs would preserve that
port and transport. Changing network ports would leave the URL and HTTP
authority unchanged.

For example, a request to `https://identity:8443/` routed to port 9443 checks
`_9443._tcp.identity` but sends HTTP authority `identity:8443`. Moving to port
443 requires checking `_443._tcp.identity` independently.

Each service needs its own records. For a homeserver, routing starts at
`_pubky.identity` and TLS authorization at `_443._tcp._pubky.identity`. That
delegation does not cover `identity`, `app.identity`, or their subnames.

### TLS authority

The TLS chain would be resolved independently of routing, with each Pubky packet
verified. Three cases determine where it ends:

- **Another Pubky name:** the chain would continue at that exact target, with
  one target per TLS CNAME and unchanged port and TCP labels.
- **No TLS CNAME in a verified packet:** the namespace's public key would become
  the TLS authority. The suffix after `_<port>._tcp` would be the TLS name. A
  timeout or unverified negative answer could not establish absence.
- **An ICANN hostname:** a signed TLS CNAME would select normal CA,
  certificate-name, and validity checks for that hostname. Its DNS TLS CNAMEs,
  TLSA records, and address aliases would not change the chosen authority.

Malformed targets, conflicting records, invalid or missing packets, cycles, and
exhausted limits would stop resolution. TLSA records at consulted Pubky TLS
names would also be rejected to avoid mixing authorization models.

Allowed authentication modes would be chosen before connecting. A client
requiring Pubky TLS would reject CA access; authentication failure would never
change the mode.

The selected TLS name would serve as SNI and the certificate reference name. It
needs to be a concrete hostname suitable for both. An underscore-prefixed
service such as `_pubky.identity` would delegate to a name such as `provider`,
rather than stripping labels ([X.509 names][x509-names]). Selecting SNI and the
certificate name through a TLS CNAME extends standard HTTPS and DANE ([HTTPS
SNI][https-sni], [DANE][tlsa-cname]).

### Separate managers

The provider can delegate the two permissions to different keys:

```dns
; Signed by provider
provider.           IN HTTPS 0 router.
_443._tcp.provider. IN CNAME _443._tcp.tls-manager.
; Signed by router
router.             IN HTTPS 1 edge.example. port=443
```

If `tls-manager`'s verified packet has no further TLS CNAME, the client connects
to `edge.example` and authenticates `tls-manager`. A compromised router can
disrupt traffic but cannot authorize a new TLS key. The provider can replace
either manager; sharing a key gives it both permissions.

### Pubky server credentials

The server would prove possession of its TLS private key in either form:

- **Raw public key:** it would equal the selected Pubky authority's key. There
  is no expiry, and placing this key on the server also exposes its
  record-signing authority.
- **Pubky-signed X.509 leaf:** the selected authority would sign it directly.
  Proposed checks include the exact TLS name as a `dNSName` in `subjectAltName`,
  valid `notBefore` / `notAfter`, digital-signature key usage,
  server-authentication extended key usage, and `CA=false`. Unsupported
  algorithms, unknown critical extensions, wildcards, and intermediate issuers
  would be excluded. The issuer's textual name would not establish trust.

A separate serving key would let the issuer stay off serving machines and
prevent the server from authorizing records or other certificates. Renewal would
need a new issuer signature, without an identity-owner update. A policy
requiring expiring credentials would exclude raw-key TLS.

X.509 needs a custom client verifier; raw-key TLS needs support at both ends.
Ordinary browser Fetch supports neither Pubky verification path.

### Browser endpoint declaration

The `pubky-ca-endpoint` field would be read only at the final Pubky TLS service
name, from the same verified packet establishing its authority. Routing-only
signers and intermediate delegates could not supply it. Without a valid field,
that Pubky TLS path would advertise no Fetch endpoint.

A simple format would allow one absolute HTTPS URL with a concrete ASCII ICANN
hostname, optional valid port, and path `/`. Port 443 would be the
default. Parsing would concatenate each TXT record's strings, ignore unrelated
records, and reject credentials, wildcards, queries, fragments, duplicates, or
malformed declarations. Permission would cover only the delegated service.

For either CA path in the overview, a web app would verify the signed
permission, then use normal browser CA validation ([Fetch][fetch-options]):

- The endpoint would come from the signed CA hostname and delegated port, or
  from the declared URL when Pubky TLS remains available.
- Requests would preserve the application's path and query, carrying the
  original identity in its established format, such as the homeserver's identity
  path or `pubky-host` field.
- A conservative starting point would disable redirects and omit ambient
  credentials. Application credentials would be bound to the service and
  endpoint, without transferring Pubky-origin cookies. Cross-origin requests
  would depend on the endpoint's CORS policy.

Fetch uses the endpoint's origin and browser-selected route. It cannot enforce
the separate Pubky route or enable navigation to `https://identity/`. Native
clients can retain the original HTTP authority only if the endpoint accepts
it. A generic website needs an application mapping to use this path.

The Cloudflare case uses managed certificates that Cloudflare rotates. Custom
edge certificates require Business or Enterprise
([rotation][cloudflare-pinning], [availability][cloudflare-custom]). The CA
delegation would accommodate certificate and key changes without Pubky updates.

CA access requires client policy permission, never fallback after failed Pubky
authentication. It depends on the domain, DNS, CA system, and TLS operator. The
owner can leave by changing the signed delegation while retaining their
identity. Access during domain or CA censorship requires a working Pubky TLS
route and compatible clients.

### Rotation and withdrawal

Alice can keep her identity key offline by delegating both paths to an
operational key, which delegates to the provider. Changing providers then needs
only the operational key; replacing that key needs the identity key.

Routine rotation would deploy new leaves before expiry. Several servers could
use different valid leaves for the selected name. Publishing new authorization
before moving routes would give caches time to refresh; inconsistent updates
would fail authentication.

Replacing a TLS CNAME would change delegates; removing it would return authority
to the packet's own key. Disabling all paths would instead mean publishing
`HTTPS 0 .`, withdrawing CA TLS delegation, and removing any CA endpoint field.

The proposed policy would close affected connections and discard resumption
state when authorization changes are observed. Superseded authority would not
permit resumption or early data. Leaf expiry would also close connections and
prevent new or resumed ones.

There is no per-leaf revocation. A stolen serving key works until certificate
expiry or until clients learn that its issuer is no longer authorized.
Short-lived leaves limit exposure. Record freshness and bounds on withdrawal
propagation are outside this proposal's scope.

## Potential addition: combined delegation

A signed hostname CNAME could delegate both routing and TLS when one provider
manages both:

```dns
; Signed by identity
identity. IN CNAME provider.
```

This would replace the two identity-owner records in the first example. The
client would follow `provider` for both HTTPS routing and TLS authority. The
original identity and HTTP authority would stay unchanged.

This is a possible extension to the routing-only CNAME model above. It needs an
explicit Pubky rule because DNS does not alias child names such as
`_443._tcp.identity`. Its port and service scope, and its interaction with a
separate TLS CNAME, would need to be defined before adoption.

## Open design questions

- **Lookup limits:** how many delegation hops and queries may a client make, and
  how long may resolution take?
- **Browser navigation:** how can `https://identity/` work while preserving
  origin isolation, cookies, and other browser security boundaries?
- **HTTP/3:** how should TLS delegation apply to QUIC, and when may clients
  reuse connections across services or after authorization changes?

[tlsa-cname]: https://www.rfc-editor.org/rfc/rfc7671.html#section-6
[https-rules]: https://www.rfc-editor.org/rfc/rfc9460.html#section-2.4
[https-query]: https://www.rfc-editor.org/rfc/rfc9460.html#section-9.1
[https-sni]: https://www.rfc-editor.org/rfc/rfc9460.html#section-9.4
[x509-names]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6
[fetch-options]: https://fetch.spec.whatwg.org/#requestinit [cloudflare-dns]: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/ [cloudflare-pinning]: https://developers.cloudflare.com/ssl/reference/certificate-pinning/ [cloudflare-custom]: https://developers.cloudflare.com/ssl/edge-certificates/custom-certificates/
