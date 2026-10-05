# Implicit TLS delegation

This proposal uses signed CNAME records to choose who authenticates a TLS
connection: a Pubky key or the CA system for an ICANN domain. No TLSA pin is
required. These rules are proposed, not shipped SDK behavior.

## Shared delegation

`identity` is the user's Pubky name; `provider` is the operator's Pubky name.
Both stand for full public-key names. The identity owner publishes:

```dns
; Signed by identity
identity.           IN HTTPS 0 provider.
_443._tcp.identity. IN CNAME _443._tcp.provider.
```

The HTTPS record says where to connect. The CNAME at `_443._tcp.identity`
delegates TLS authentication for TCP port 443; we call it a **TLS CNAME**.
It covers this service, not its subnames. The provider can change its setup
without changing the identity owner's records.

**SNI** is the hostname sent during the TLS handshake to select a certificate.
For `_443._tcp.provider`, use `provider` for SNI and certificate-name checks.

Proposed rules:

- Verify every Pkarr hop. Missing or invalid packets are errors.
- If TLS delegation ends at a Pubky name, use its key as the TLS authority
  and its service name for certificate matching and SNI.
- A Pubky-signed TLS CNAME to an ICANN hostname explicitly selects CA
  validation for that hostname, including certificate name and expiry checks.
  Ordinary DNS address aliases do not change this selected TLS name.
- Clients requiring Pubky TLS reject CA-only mode. Authentication failure
  never triggers a change of mode.

Selecting the certificate name and SNI through a TLS CNAME is a Pubky
extension to standard DANE ([RFC 7671][tlsa-cname]).

Web apps can verify Pkarr signatures, but browser Fetch requires CA endpoints
and cannot verify Pubky TLS credentials or pins ([Fetch][fetch-options]).

## Pubky key or Pubky-signed certificate

The provider publishes routing records with no further TLS delegation:

```dns
; Signed by provider
provider. IN HTTPS 1 . port=443
provider. IN A 203.0.113.10
```

The `.` target uses the address at `provider`. The client connects there and
sends SNI `provider`. The server can present either:

- **Raw public key:** the client checks that it equals `provider`'s key and
  that the server proves possession of its private key. No certificate expiry
  exists.
- **Pubky-signed X.509 certificate:** the client verifies the signature under
  `provider`, name `provider`, validity, and possession of the certificate's
  TLS private key. The certificate can use a separate server key.

Native requests can retain HTTP authority `identity`; the backend must accept
it. X.509 uses ordinary server certificate settings; raw-key TLS needs
integration. Certificate renewal needs a new issuer signature, but no
identity-owner record update.

## Cloudflare Free Tunnel: CA-only TLS

The provider explicitly chooses CA-only TLS by pointing its TLS CNAME at its
ICANN domain. The HTTPS record routes the connection there too:

```dns
; Signed by provider
provider.           IN HTTPS 1 edge.example. port=443
_443._tcp.provider. IN CNAME _443._tcp.edge.example.

; Ordinary DNS, configured for Cloudflare Tunnel
edge.example.       IN CNAME <tunnel-id>.cfargotunnel.com.
```

Clients use SNI and HTTP authority `edge.example`, validating its CA
certificate, name, and validity. The tunnel's DNS alias does not change the
selected TLS name.

The signed TLS CNAME authorizes this CA endpoint, not a specific TLS key.
Cloudflare Free presents managed edge certificates whose keys rotate; custom
edge certificates require Business or Enterprise
([pinning][cloudflare-pinning], [availability][cloudflare-custom]).

There is no Pubky TLS key check. Certificate renewal or key rotation needs
no Pubky record update.

A web app verifies the Pkarr chain through relays, then Fetches
`https://edge.example/`. Pubky identity stays in the application protocol;
the endpoint must allow cross-origin Fetch through CORS.

## Both Pubky TLS and a CA endpoint

Keep TLS delegation ending at `provider`, and advertise the CA endpoint
separately:

```dns
; Signed by provider
provider. IN HTTPS 1 . port=443
provider. IN A 203.0.113.10
provider. IN TXT "pubky-ca-endpoint=https://edge.example/"
```

The proposed `pubky-ca-endpoint` field advertises a second path:

- Clients supporting Pubky TLS use the HTTPS route and SNI `provider`.
- Web apps verify the signed endpoint declaration, then Fetch at
  `edge.example` with normal browser CA validation. Without a valid field,
  this setup advertises no compatible Fetch endpoint.

On one server, SNI can select the Pubky-issued or CA-issued certificate,
both serving the same backend ([NGINX SNI][nginx-sni]). With Cloudflare Free
for CA HTTPS, Pubky TLS needs a separate route to the operator's TLS server.

## Combined delegation shorthand

When one provider manages both routing and TLS, a signed hostname CNAME could
replace the two identity-owner records:

```dns
; Signed by identity
identity. IN CNAME provider.
```

Under this proposal, follow the provider for both routing and TLS. DNS does
not alias child names such as `_443._tcp.identity`, so this needs an explicit
Pubky rule. DANE has related alias behavior ([RFC 7671][hostname-cname]);
ordinary HTTPS browsers still check the URL name.

## Open details

Specify certificate issuer representation, delegation freshness, and scoped
service names. For the CA endpoint field, define URL validation, path mapping,
redirect policy, and how requests carry Pubky identity. Also define precedence
if a hostname CNAME and a separate TLS CNAME coexist.

[tlsa-cname]: https://www.rfc-editor.org/rfc/rfc7671.html#section-6
[hostname-cname]: https://www.rfc-editor.org/rfc/rfc7671.html#section-7
[cloudflare-pinning]: https://developers.cloudflare.com/ssl/reference/certificate-pinning/
[cloudflare-custom]: https://developers.cloudflare.com/ssl/edge-certificates/custom-certificates/
[fetch-options]: https://developer.mozilla.org/en-US/docs/Web/API/RequestInit
[nginx-sni]: https://nginx.org/en/docs/http/configuring_https_servers.html#sni
