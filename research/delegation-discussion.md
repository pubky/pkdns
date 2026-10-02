# Pubky service delegation

## Problem and scope

A user needs to keep the identity key offline, delegate hosting, and change
providers without changing URLs. The provider needs to rotate TLS keys and
move endpoints without updates from every user.

This document compares three proposed authorization rules. They follow the
[first principles](./first-principles.md) and
[delegation requirements](./delegation-motivation.md); browser compatibility
remains subject to the [design principles](./design-principles.md).

Examples use K for the user identity, K2 for an operational key, S for provider
management, and T for TLS. Each commented group of records belongs to its
signer's packet.

The proposals cover HTTPS services at any Pkarr name: K, `app.K`, or
`_pubky.K`. Delegation is scoped to the exact service name; K does not
implicitly delegate its subnames. Ordinary domains need a separately defined
trust anchor to adopt these rules. DNSSEC-based DANE provides a different
model for them. Ordinary DNS can still supply endpoint addresses.

Direct connections retain the original URL and HTTP authority. SNI selects
server configuration; the client verifies the server key separately. SNI does
not communicate the accepted key set. These rules differ from standard HTTPS,
which retains the original name for certificate validation and SNI
([RFC 9460][https-identity], [SNI rules][https-sni]).

## Status quo

Baseline: SDK/HS revision `4c4e350` using Pkarr 8.0.1, and Pkarr revision
`0275a1b` (8.0.2). [Implementation sources](#implementation-sources) identify
the inspected code; compatibility notes are based on source inspection.

```dns
; Signed by K
_pubky.K. 300 IN HTTPS 0 S.
; Signed by S
S.        300 IN HTTPS 1 . port=443
S.        300 IN A 203.0.113.10
```

- **Native:** follows signed service records and verifies a resolved
  endpoint's packet-signing key in raw-key TLS. The HS uses the same Ed25519
  key for packet signing and TLS. There is no TLSA verification.
- **Browser SDK:** resolves an advertised ordinary domain and rewrites the
  transport URL to it, using WebPKI. Native SDK clients can also choose that
  route when a direct endpoint is unavailable. User addressing uses a path or
  `pubky-host`, depending on the API.
- **pkdns:** exposes Pkarr records through DNS; browser TLS verification
  remains unchanged.

Current endpoint resolution follows public-key targets in either HTTPS mode,
and the verifier accepts any resolved endpoint key. It does not bind TLS to
one selected branch or rewrite SNI to the final delegate. Option A is therefore
close to current behavior, but specifies different rules. The SDK's HTTP
transport selection explicitly recognizes bare keys and `_pubky.K`; generic
`app.K` support needs client work.

## Technologies in brief

| Technology                               | Role and existing use                                                                                                                           |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| Pkarr / Mainline DHT                     | Signed DNS packets discovered by public key; used for Pubky discovery.                                                                          |
| HTTPS / SVCB                             | Endpoint and connection parameters, including HTTP/3 discovery; [RFC 9460][https-rr].                                                           |
| CNAME                                    | DNS aliasing; also used for [DANE provider delegation][dane-provider].                                                                          |
| TLSA / DANE                              | Certificate or key bindings, normally authenticated by DNSSEC; used by [Exchange Online][dane-email]. Here, Pkarr signatures authenticate them. |
| Raw-key TLS                              | TLS without X.509 certificates; used by native Pubky clients and supported by [Rustls][rustls-features].                                        |

Short definitions are in the [terminology guide](./delegation-terminology.md).

## Options

| Option | TLS authorization                          | Does a Pubky routing alias change the authority? |
|--------|--------------------------------------------|--------------------------------------------------|
| A      | Final delegate's own raw key               | Yes                                              |
| B      | TLSA set published by the final delegate   | Yes                                              |
| C      | TLSA set selected through a separate chain | No                                               |

In the proposed profiles, `HTTPS 0 target` delegates through the target's
HTTPS records. `HTTPS 1 target` selects an endpoint without following its
HTTPS records; `.` uses the owner's addresses. The distinction is
security-relevant in A and B.

### Option A: HTTPS aliases select the TLS identity

```dns
; Signed by K
K.  300 IN HTTPS 0 K2.
; Signed by K2
K2. 300 IN HTTPS 0 S.
; Signed by S
S.  300 IN HTTPS 0 T.
; Signed by T
T.  300 IN HTTPS 1 . port=443
T.  300 IN A 203.0.113.10
```

The client verifies K -> K2 -> S -> T, sends SNI T and HTTP authority K, and
requires T's raw key. X.509 certificates are excluded on Pubky branches.

**Tradeoff.** One chain controls hosting and TLS identity. S can replace T
without user updates, but a stolen T can also publish records and further
delegate while S still authorizes it. The online TLS key therefore carries
management authority.

An alias to `host.example` that switches verification to WebPKI introduces a
registrar dependency: control of that domain and a valid certificate could
allow serving K without another signed update. Preserving the first
principles requires excluding that transition or explicitly authorizing the
TLS key through K, as in B/C.

**Backward compatibility.** Existing raw keys and simple `_pubky.K -> S`
records can be reused. Clients need the mode distinction, branch-specific
verification, and delegate SNI. A single-key HS can keep its listener;
multiple keys on one port need SNI selection. Retaining the browser domain
route preserves legacy access under WebPKI, with its existing trust model.

### Option B: HTTPS aliases select a TLSA publisher

```dns
; Signed by K
K.           300 IN HTTPS 0 K2.
; Signed by K2
K2.          300 IN HTTPS 0 S.
; Signed by S
S.           300 IN HTTPS 1 edge.example. port=443
_443._tcp.S. 300 IN TLSA 3 1 1 <hash-of-T-spki>
```

The client sends SNI S and HTTP authority K. Ordinary DNS resolves
`edge.example`; its domain certificate cannot substitute for the signed pin.
`TLSA 3 1 1` authorizes SHA-256 of the complete DER-encoded SPKI. T may be
presented as a raw key or in an X.509 certificate and needs no Pkarr packet.

**Tradeoff.** Separating T from S prevents a stolen TLS key from changing
management records. Certificate renewal with the same key needs no pin
update. Routing still selects the trusted publisher: changing a Pubky alias
changes whose TLSA set is accepted.

All pins at one service name form an accepted set, not endpoint/key pairs.
If S lists T1 and T2, either key is valid at every endpoint using that set.
Distinct endpoint policies require distinct service names.

TLSA uses the connection port and transport. For `https://K:8443/` routed to
S on TCP 9443, check `_9443._tcp.S`; HTTP authority remains `K:8443`.
The DANE-EE model ignores certificate names and expiry; this proposal replaces
DNSSEC authentication with Pkarr signatures and DHT updates
([RFC 6698][tlsa-fields], [RFC 7671][dane-ee]).

**Backward compatibility.** Old clients ignore TLSA. They can still connect
if the direct endpoint keeps serving S's raw key while upgraded clients pin
S. Switching to separate T breaks old native verification. The HS needs
independent TLS-key configuration; X.509 support also needs server and client
changes. Browser domain access remains WebPKI and does not enforce the pins.

### Option C: Separate routing and TLS authorization

```dns
; Signed by K
K.            300 IN HTTPS 0 K2.
_443._tcp.K.  300 IN CNAME _443._tcp.K2.
; Signed by K2
K2.           300 IN HTTPS 0 S.
_443._tcp.K2. 300 IN CNAME _443._tcp.S.
; Signed by S
S.            300 IN HTTPS 1 edge.example. port=443
_443._tcp.S.  300 IN TLSA 3 1 1 <hash-of-T-spki>
```

Both chains start at K. HTTPS selects the endpoint; TLSA-name CNAMEs select
the key publisher. Routing can point to R while S controls TLS authorization.
A compromised R can misdirect or block traffic but cannot authorize a key,
provided R does not also control the TLSA chain.

**Tradeoff.** Independent control costs another chain and more records.
Updates can leave routing and authorization temporarily inconsistent; the
client must fail rather than accept a routing-authorized key. Using the same
signing keys for both chains does not isolate a compromised signer.

TLSA CNAME delegation has a [DANE precedent][dane-provider]. Starting strictly
at the original service name is a Pubky restriction; standard DANE can derive
a TLSA base through a DNSSEC-validated hostname CNAME chain
([RFC 7671 section 7][dane-cname]). Ports, QUIC, SNI, and branching rules still
need specification. Authorization links should remain in signed Pkarr packets.

**Backward compatibility.** Old clients ignore the TLSA chain and can connect
while routing still ends at the raw key they expect. Once routing points to R
and TLSA authorizes T, they may reject T. Client verification and publishing
tools need upgrades. Compared with B, C needs no new TLS key format or TLS
handshake; the HS may still need SNI configuration. Compared with today's HS,
a separate T requires independent key configuration. Browser domain access
still uses WebPKI.

## Applying the options to `_pubky`

The starting service name can be `_pubky.K` instead of K. For A, the final
delegate is the TLS identity; for B, it publishes the TLSA set. C starts a
separate lookup at `_443._tcp._pubky.K`:

```dns
; Signed by K
_pubky.K.           300 IN HTTPS 0 S.
_443._tcp._pubky.K. 300 IN CNAME _443._tcp.S.
; Signed by S
S.                 300 IN HTTPS 1 . port=443
S.                 300 IN A 203.0.113.10
_443._tcp.S.        300 IN TLSA 3 1 1 <hash-of-T-spki>
```

This authorizes T for `_pubky.K`; the website at K needs its own records.
A direct request retains HTTP authority `_pubky.K`. Storage addressing,
sessions, and write permissions remain SDK/HS policy. The same rule applies
to `app.K`, with C's TLSA lookup starting at `_443._tcp.app.K`.

The current SDK homeserver helper treats the immediate `_pubky` target as the
HS key. Adding `_pubky.K -> K2 -> S` can make it report K2, even though
endpoint resolution follows the chain. Migration needs an updated helper or
must retain `_pubky.K -> S`. C also needs publication tooling that updates the
TLSA chain alongside homeserver selection.

## Rotation and revocation

### A: Overlap alias branches

During rotation, S publishes `HTTPS 0 T1` and `HTTPS 0 T2`; each key publishes
its own endpoint packet. The T1 branch requires T1 and sends SNI T1; the T2
branch requires T2 and sends SNI T2. A shared IP/port needs SNI key selection,
or the keys can use separate endpoints.

Prepare T2 and its packet, publish both aliases, allow caches to refresh, then
remove T1's alias. Keep T1's endpoint available while old caches drain.
Each branch authorizes only its own key. Exploring all alias branches is a
proposed Pubky rule; standard HTTPS recommends choosing one alias at random
([RFC 9460][https-alias]).

### B/C: Overlap TLSA pins

```dns
; Signed by S
_443._tcp.S. 300 IN TLSA 3 1 1 <hash-of-T1-spki>
_443._tcp.S. 300 IN TLSA 3 1 1 <hash-of-T2-spki>
```

Publish both pins, allow caches to refresh, switch the HS to T2, then remove
T1. The HS presents one key per handshake; the client accepts either pin.
SNI can stay unchanged. With C, publish authorization before routing to an
endpoint that requires it, and handle mixed chain versions without weakening
verification.

### Revocation and connection reuse

Revocation is mostly solved in practice by publishing a newer signed packet.
K2 can replace S1 with S2; K can remove a compromised K2. Mainline nodes holding
newer versions reject older replacements ([BEP 44][bep44]). For a compromised
TLS key, remove authorization promptly rather than keeping a rotation overlap.

Updates take effect as clients refresh parent records. The examples' 300-second
TTL is a cache setting. Refreshed policy must invalidate affected connections
and resumed TLS sessions; early data and cross-origin connection reuse need
explicit rules.

## Browser SDK integration

### Constraint and available paths

The browser SDK uses `fetch()`, which exposes neither TLS negotiation nor a
custom certificate verifier ([Fetch API][fetch-api]). It cannot request
raw-key TLS, inspect the peer's SPKI, or enforce a TLSA pin on that connection.
JavaScript can verify signed Pkarr packets, but cannot turn a
successful WebPKI connection into verified option A/B/C transport. Service
workers and WebAssembly using `fetch()` have the same limitation.

SDK access from an existing web app and browser navigation to `https://K/`
are separate goals. A custom SDK transport can solve the former while the
address bar, cookies, and subresources still use ordinary browser origins.

| Path                          | Browser changes                                           | SDK / server changes                                              | Where authorization is verified                            |
|-------------------------------|-----------------------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------------|
| Existing domain HTTPS         | None                                                      | Keep WebPKI endpoint                                              | Browser verifies domain                                    |
| TLS inside a WebSocket tunnel | None                                                      | SDK TLS implementation plus a byte relay                          | SDK verifies A/B/C end to end                              |
| Pinned WebTransport           | None where the pinning API is supported                   | SDK transport, HS WebTransport endpoint, certificate-hash profile | SDK verifies delegation; browser verifies certificate hash |
| Native helper via extension   | No browser source changes; installation required          | Extension/helper and SDK adapter                                  | Helper verifies A/B/C                                      |
| Local TLS proxy               | No browser source changes; proxy and trust setup required | Local verifier and proxy configuration                            | Trusted proxy verifies A/B/C                               |
| Native browser integration    | Required                                                  | Pkarr discovery and authorization in browser networking           | Browser verifies A/B/C for fetch and navigation            |

These are implementation paths to evaluate, not shipped SDK capabilities.

### Unmodified browser: preserve access or add a custom transport

**Existing domain endpoint.** Keep the current browser route alongside the
native endpoint. Transport confidentiality and server authentication depend
on WebPKI. This route cannot be the sole solution where service authentication
must remain independent of registrars.

**End-to-end TLS tunnel.** A possible SDK adapter runs TLS in JavaScript or
WASM over a binary WebSocket relay that forwards bytes to the HS TCP endpoint.
For `_pubky.K`, the SDK verifies K's delegation, establishes inner TLS to the
authorized key, and sends the storage request inside it. The relay's outer
WebPKI connection carries ciphertext; the relay need not be trusted for the
inner plaintext or server identity, though it can block traffic.

This can preserve A's raw keys or B/C's SPKI pins without changing the HS TLS
listener. It requires TLS/HTTP framing and session handling in the SDK and a
relay protocol. Browser cookies do not automatically become inner HTTP
cookies. Relays must be replaceable, and the app/SDK must have a trusted
bootstrap independent of an untrusted content host. Feasibility and overhead
need a prototype; this is not ordinary `fetch()`.

**Pinned WebTransport.** This API provides streams/datagrams for custom web
protocols. Its `serverCertificateHashes` can authenticate a full certificate
without a CA chain where supported ([WebTransport specification][webtransport]).
B/C could use a dedicated profile: verify signed authorization, then supply an
authorized certificate hash to WebTransport and carry SDK requests on streams.

The API hashes the complete certificate, not SPKI: existing `TLSA 3 1 1` pins
cannot be passed directly. A signed full-certificate pin such as `3 0 1`
needs an explicit service/transport binding ([TLSA selectors][tlsa-fields]).
URL-based SNI also needs to be reconciled with the profile. Certificate
validity must not exceed two weeks. P-256 is the interoperable algorithm;
Ed25519 support is not guaranteed. Renewal changes the certificate hash even
if the key stays the same. This requires publication/rotation changes and a
WebTransport HS endpoint. A's Ed25519 raw-key profile cannot use this API
unchanged. It does not enable normal page navigation to K.

### Unmodified browser with installed local software

An extension can use [native messaging][native-messaging] to call a helper
that resolves Pkarr and establishes A/B/C TLS. The SDK exchanges requests with
the helper; the helper is trusted with plaintext. An extension alone does not
add a custom TLS verifier to ordinary `fetch()`.

A local proxy can instead verify upstream A/B/C connections and present
browser-trusted certificates downstream. It needs installed trust and routing
configuration. Preserving K in normal browser navigation requires configuring
name resolution and proxy routing as well as TLS trust. Proxy choice must stay
under user control; a remote terminating gateway adds an external plaintext
trust boundary and usually changes the origin.

### Browser changes for direct HTTPS and navigation

Native integration needs more than enabling raw keys. Browser networking must
resolve and verify signed Pkarr chains, select the authorization profile,
negotiate raw-key TLS for A or apply pins for B/C, and implement the selected
SNI rules. It must preserve origin isolation under K or `_pubky.K`, including
subresources, redirects, cookies, caching, and connection reuse.

B/C may keep X.509 as the key container, but still need a verifier that accepts
Pkarr authorization instead of requiring a WebPKI name binding. SDK-only access
could use a restricted browser API for authenticated endpoint selection and
pinning; ordinary navigation requires integration into the browser's own
networking and origin model. Failed proof verification must not select WebPKI
fallback. Name resolution through pkdns alone supplies none of these rules.

## Deployment constraints and open decisions

- **Packet space:** 1,000 compressed DNS bytes per signer, plus 104 bytes for
  the key, signature, and timestamp. A/B delegation uses 132 DNS bytes; C uses
  218; an endpoint with two TLSA pins uses 202. Reserve rotation space. See
  [packet capacity](./pkarr-packet-size.md) for measurements and the DHT
  boundary caveat.
- **Bounded failover:** exploring every branch can let a slow H2 exhaust the
  budget despite a usable H1. Decide whether a fully verified candidate may
  be used before all branches finish. A failed delegate lookup must not
  authorize fallback to a parent key.
- **Profile selection:** use authenticated policy or client configuration.
  Missing or invalid TLSA in B/C must not select legacy verification.
- **Practical exit:** routing changes preserve identity but migration still
  needs available data, compatible formats, and usable export/restore.

## Implementation sources

These source snapshots define the status quo used for the compatibility
notes. The notes compare behavior; they are not results of interoperability
tests.

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
[dane-provider]: https://www.rfc-editor.org/rfc/rfc7671.html#section-6
[dane-cname]: https://www.rfc-editor.org/rfc/rfc7671.html#section-7
[tlsa-fields]: https://www.rfc-editor.org/rfc/rfc6698.html#section-2
[https-rr]: https://www.rfc-editor.org/rfc/rfc9460.html
[https-alias]: https://www.rfc-editor.org/rfc/rfc9460.html#section-2.4.2
[dane-email]: https://learn.microsoft.com/en-us/purview/how-smtp-dane-works
[rustls-features]:
  https://rustls.dev/docs/rustls/manual/_04_features/index.html
[bep44]: https://www.bittorrent.org/beps/bep_0044.html#mutable-items
[fetch-api]: https://fetch.spec.whatwg.org/#requestinit
[webtransport]:
  https://www.w3.org/TR/webtransport/#webtransportoptions-dictionary
[native-messaging]:
  https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
