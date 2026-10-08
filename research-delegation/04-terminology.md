# Terminology

## Identity and keys

- **Key pair:** a private key creates signatures; its public key verifies them.
- **Identity key:** anchors the user's identity across host changes.
- **Operational key:** a replaceable key authorized for routine work.
- **Management key:** signs records selecting endpoints or authorizing keys.
- **TLS key:** the key used to prove server identity during the handshake.

## Trust and permissions

- **Trust anchor:** the starting key or fact a verifier already trusts.
- **Authentication:** checks a claimed identity or possession of a key.
  **Authorization** decides what that identity or key may do.
- **Authority:** permission to make a decision, or the party holding it.
- **Delegation:** grants another key permission within a stated scope.

## Discovery and records

- **DHT:** a distributed hash table. Mainline provides Pkarr's discovery
  network.
- **Pkarr:** publishes signed DNS packets discoverable by public key.
- **Resolution:** looking up records for targets, settings, or permissions.
- **Record owner name:** the name a record describes, such as
  `_443._tcp.provider`. This DNS field does not describe who owns the identity.
- **Alias:** redirects a lookup. Its authorization meaning depends on the
  protocol rules.
- **CNAME:** aliases one record name to another.
- **HTTPS / SVCB records:** advertise service targets and connection settings.
  Priority zero is AliasMode; a positive priority is ServiceMode.
- **TXT record:** carries text interpreted by an application or protocol.

## Hosting and addressing

- **Homeserver:** stores and serves a user's data.
- **`_pubky.identity`:** the homeserver service for the user's identity key.
  It is separate from the website at `identity`.
- **Endpoint:** an address, port, and transport used for a connection.
- **Routing:** choosing an endpoint. An address does not prove authorization.
- **Origin:** scheme, hostname, and port. Browsers use it to isolate websites.
- **HTTP authority:** hostname and optional port in `Host` or `:authority`.

## TLS connections

- **TLS:** authenticates peers and protects connection traffic.
- **TLS terminator:** handles TLS and can read the decrypted traffic.
- **SNI:** the name sent during TLS to select server configuration. It is not
  proof of identity. See [RFC 6066][sni].

## Certificates and fingerprints

- **Certificate:** a signed structure containing a public key and claims.
  The server must also prove possession of its private key.
- **Certificate name:** a claimed service name. Standard HTTPS checks it against
  the requested name; see [RFC 9525][identity].
- **Certificate reference name:** the expected name checked against the
  certificate. The Pubky TLS proposal derives it from verified TLS delegation,
  independently of the original SNI.
- **Raw public key:** a key presented in TLS without an X.509 certificate.
- **SPKI:** SubjectPublicKeyInfo, which encodes a key and its algorithm.
- **Hash:** a fingerprint of bytes. A hash alone does not identify their author.
- **Pin:** an expected certificate, public key, or hash checked by the verifier.

## Verification methods

- **WebPKI:** browser HTTPS trust based on certificate authorities.
- **DNSSEC:** signatures and key chains that authenticate DNS record sets.
  A Pkarr packet signature is a different format.
- **TLSA:** a record binding a certificate or key to a service. Its fields
  specify the verification mode, what is matched, and how it is matched.
- **TLSA base name:** the hostname in `_port._transport.hostname`. DANE uses
  it for SNI and certificate-name checks. A TLSA-record CNAME does not change
  it; an authenticated hostname CNAME can ([RFC 7671][dane-cname]).
- **DANE:** a framework using DNSSEC-authenticated TLSA records to verify TLS
  peers. It supports several verification modes ([RFC 7671][dane]).
- **DANE-EE:** DANE's end-entity mode (TLSA usage `3`). It authorizes the
  server's certificate or key directly. CA validation, certificate names,
  and certificate validity dates are not checked.
- **DANE-TA:** DANE's trust-anchor mode (TLSA usage `2`). It authorizes a
  trust anchor for validating the server's certificate chain.
- **PKIX-EE:** TLSA usage `1`. The server certificate must match the pin and
  pass normal CA-chain, hostname, and validity checks, including expiry.

## Updates and freshness

- **TTL:** cache lifetime; it does not prove a record is current.
- **Signed expiry:** a signed deadline after which permission must be rejected.
- **Rotation:** replacing a key, sometimes with an overlap accepting both keys.
- **Revocation:** withdrawing permission.
- **Replay:** reusing an old valid message. **Rollback** makes a client replace
  newer state with older state.

[sni]: https://www.rfc-editor.org/rfc/rfc6066.html#section-3
[identity]: https://www.rfc-editor.org/rfc/rfc9525.html#section-1.5
[dane]: https://www.rfc-editor.org/rfc/rfc7671.html#section-2
[dane-cname]: https://www.rfc-editor.org/rfc/rfc7671.html#section-7
