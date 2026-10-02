# Delegation terminology

Terms used in the [delegation discussion](./delegation-discussion.md).
The definitions describe concepts; the proposed Pubky rules are not
claims of current browser support.

## Keys and permissions

- **Key pair:** a public key that others can know and a private key kept
  secret. The private key signs; the public key verifies those signatures.
- **Identity key:** the key pair that anchors a Pubky identity. Changing
  hosts does not require changing this key.
- **Operational key:** a separate key authorized for routine work, so the
  identity's private key can stay offline, or "cold".
- **Management key:** a key used to sign service records that select endpoints
  and authorize other keys. It need not be the online TLS key.
- **Authority:** permission to make a particular decision, or the party
  holding that permission. A TLSA publisher has authority to select accepted
  TLS keys. Authority should always have a stated scope.
- **Delegation:** granting another key permission to act within a scope.
  It does not share the owner's private key or transfer identity ownership.
- **Authentication:** verifying a claimed identity or possession of a key.
  **Authorization** decides what that identity or key may do.
- **Trust anchor:** the starting point a verifier already trusts. In these
  proposals, the original Pubky public key anchors the delegation chain.

## Names and destinations

- **Record owner name:** the DNS name a record describes, such as
  `_443._tcp.S`. "Owner" here means a record field, not the person controlling
  the key. Several record names can belong to one signed Pkarr packet.
- **Alias:** a record that points a lookup to another name. Whether it also
  delegates permission depends on the proposed authorization rules.
- **Origin:** a scheme, hostname, and port, such as `https://K:443`.
  Paths are not part of the origin. Browsers use origins to separate sites.
- **HTTP authority:** the requested hostname and optional port, carried in
  `Host` or `:authority`. Here, "authority" is an HTTP addressing term,
  not a grant of permission.
- **Endpoint:** a destination for a connection, such as an IP address and
  port over TCP. A service may offer several endpoints.
- **Routing:** choosing where to connect. A destination address alone does
  not prove that the server is authorized to serve the requested origin.
- **Resolution:** looking up and following records to obtain addresses,
  service settings, or authorization data.
- **`_pubky.K`:** the service name used to discover K's homeserver. Its
  records are signed by K. It is separate from the website name K.
- **Homeserver:** a provider's server that stores and serves a user's data.
  Hosting data does not make the provider its owner.

## TLS and verification

- **TLS:** the protocol used to authenticate peers and protect connection
  traffic from reading or modification by outsiders.
- **TLS key:** the server's key pair used to prove its identity during the
  TLS handshake. It can be separate from its management or identity key.
- **TLS terminator:** the component that handles the TLS connection and
  can read its decrypted traffic. It may forward requests to another server.
- **SNI:** Server Name Indication, a name the client sends during the TLS
  handshake to help select server configuration. It is not proof of server
  identity. See [RFC 6066 section 3][sni].
- **Certificate:** a signed structure containing a public key, identity
  claims, and other information. Possessing one is not enough: the server
  must prove possession of the matching private key.
- **Certificate identity:** an informal term for the service names or IP
  addresses claimed in a certificate's Subject Alternative Name field.
  **Reference identifier** is what the client expects; **presented
  identifier** is what the certificate claims. See [RFC 9525][identity].
- **WebPKI:** the system of trusted certificate authorities and certificate
  validation used for ordinary browser HTTPS.
- **Raw public key:** a key presented in TLS without an X.509 certificate.
  The client needs a separate basis for trusting it.
- **SPKI and key pin:** SubjectPublicKeyInfo encodes a public key and its
  algorithm information. A pin fixes an expected key or hash. The proposed
  `TLSA 3 1 1` pin is a SHA-256 hash of the full DER-encoded SPKI.

## Updates and freshness

- **TTL:** a record's cache lifetime. It limits local reuse, but does not
  by itself prove that a signed permission is still current.
- **Signed expiry:** a deadline protected by a signature, after which the
  verifier must reject the permission.
- **Revocation:** withdrawing permission. **Rotation** replaces a key,
  sometimes with an overlap while both old and new keys are accepted.
- **Replay and rollback:** replay reuses an old valid signed message;
  rollback makes a client accept an older state in place of a newer one.

## One example

In option B, `https://K/page` could connect to
`203.0.113.10:443`, send SNI S and HTTP authority K, and authenticate TLS
key T through S's signed TLSA record, after verifying K's delegation to S.
K, S, and T stand for the user, provider, and TLS keys respectively.
The origin, endpoint, SNI, and authenticated key have different roles.
Certificate name matching is not required in this DANE-EE mode; the trusted
TLSA binding authorizes the key. See [RFC 7671 section 5.1][dane].

For PKARR, HTTPS records, TLSA, and DANE, see the
discussion's [short technology guide][technologies].

[sni]: https://www.rfc-editor.org/rfc/rfc6066.html#section-3
[identity]: https://www.rfc-editor.org/rfc/rfc9525.html#section-1.5
[dane]: https://www.rfc-editor.org/rfc/rfc7671.html#section-5.1
[technologies]: ./delegation-discussion.md#technologies-in-brief
