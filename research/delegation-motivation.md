# Motivation for Service Delegation

Delegation lets another key act within granted permissions while the owner
keeps the main private key and ownership, following our
[first principles](./first-principles.md).

This research covers choosing hosts and authorizing TLS keys that authenticate
connections. Login and file-write permissions are separate. The designs are
proposals, not claims of current support.

## Why a user may want delegation

- **Keep the identity key offline.** Let another key manage service records
  between changes to its permissions.
- **Delegate hosting.** Let a homeserver serve files without sharing the user's
  private key.
- **Keep links stable.** Address content by the user's public key and path,
  even when the host changes.

## Why a homeserver operator may want delegation

- **Keep the main service key offline.** Use replaceable keys for routine work.
- **Manage hosting independently.** Change servers or TLS keys within granted
  permissions without asking every user to update their records.
- **Limit damage from a stolen TLS key.** Separate serving from management so
  a serving key cannot change records or authorize more keys. Designs differ
  on whether they provide this separation.

For example, a user authorizes a homeserver management key to choose servers
and TLS keys. The operator can then replace a TLS key without a user update.
The user keeps the same address and can later withdraw permission.

## Requirements

### Delegation and owner control

- Delegates use their own keys. Signatures prove their authority independently
  of domain registrars, and discovery remains available through the DHT.
- Permissions specify the service, allowed decisions, and whether further
  delegation is allowed. State what a stolen TLS key could authorize.
- Owners can revoke or replace delegates without their help by updating signed
  records. Clients need time to refresh those records.
- Users keep their identity, content ownership, and stable links. Independent
  copies and migration to compatible hosts must be practical and affordable.
  Updating routing does not move stored data.

### Clients using delegated services

- Verify the authorized TLS key, even when connecting through an ordinary
  domain. WebPKI, the browser's certificate-authority trust system, alone does
  not prove authorization from the user's key.
- Respect configured proxies and report discovery, connection, and
  authorization failures separately.
- Refresh permissions and apply changes to reused connections. A valid
  signature does not prove that a record is current.
- Limit lookup and retry attempts, keep verification intact, and avoid
  repeating operations whose outcome is uncertain.
- Define transport policy explicitly. Failures must not silently switch to
  WebPKI or plaintext when the service requires the user's key authorization.

## Supporting issues and their applicability

Reviewed on 2026-10-02. All six issues were open; PR #366 was closed without
merging. Reports were not independently reproduced. The relevance to our
research is our assessment under the first and design principles.

- **[Homeserver #18: remote controller][hs-18].** Proposes resolution through
  an intermediary controller. Directly motivates managing service records
  separately from the serving machine.

- **[Homeserver #140: convert keys to provider URLs][hs-140].** Motivates stable
  user addresses with browser access. A provider's HTTPS URL depends on that
  host and WebPKI; it does not verify the user's key authorization.

- **[Homeserver #647: probe bypasses the proxy][hs-647].** Reports delays from
  a connection check that ignores the proxy. Motivates choosing servers through
  the actual request route; delegation alone does not fix proxy handling.

- **[Homeserver #657: unresolved names select PubkyTLS][hs-657].** Reports
  failed lookups becoming transport choices and names a proxy cannot resolve.
  Motivates clear discovery errors and proxy routes that preserve the requested
  service name and verify its authorized TLS key.

- **[Homeserver #29: retry after cache updates][hs-29].** Reports stale records
  pointing to old servers. Motivates refreshing records during host or key
  changes, with bounded retries and full verification.

- **[Homeserver PR #366: HTTP for IP-address testnets][hs-366].** Indirectly
  motivates explicit transport settings: treating IP addresses as plaintext
  HTTP could disable HTTPS. Testnet convenience must not weaken production TLS.

- **[Pkarr #292: standard TLS for ICANN targets][pkarr-292].** Reports a TLS
  failure with an ordinary HTTPS server. Motivates explicit TLS authorization:
  using WebPKI changes the trust model. A certificate can carry an authorized
  key, but its format alone does not prove the owner's permission.

[hs-18]: https://github.com/pubky/pubky-homeserver/issues/18
[hs-140]: https://github.com/pubky/pubky-homeserver/issues/140
[hs-647]: https://github.com/pubky/pubky-homeserver/issues/647
[hs-657]: https://github.com/pubky/pubky-homeserver/issues/657
[hs-29]: https://github.com/pubky/pubky-homeserver/issues/29
[hs-366]: https://github.com/pubky/pubky-homeserver/pull/366
[pkarr-292]: https://github.com/pubky/pkarr/issues/292
