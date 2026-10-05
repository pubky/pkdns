# Motivation for service delegation

Delegation lets another key act within granted permissions while the owner
keeps the main private key and ownership.

This research covers choosing hosts and authorizing TLS keys that authenticate
connections. Login and file-write permissions are separate.

## User needs

- **Keep the identity key offline.** Let another key manage service records
  between changes to its permissions.
- **Delegate hosting.** Let a homeserver serve files without sharing the user's
  private key.
- **Keep links stable.** Address content by the user's public key and path,
  even when the host changes.

## Operator needs

- **Keep the main service key offline.** Use replaceable keys for routine work.
- **Manage hosting independently.** Change servers or TLS keys within granted
  permissions without asking every user to update their records.
- **Limit damage from a stolen TLS key.** Separating serving from management
  can prevent a stolen serving key from changing records or authorizing more
  keys.

For example, a user authorizes a homeserver management key to choose servers
and TLS keys. The operator can replace a TLS key without a user update.
The user keeps the same address and can later withdraw permission.

## Requirements

### Owner control

- Delegates use their own keys. Clients verify signed grants rooted in the
  owner's key, independently of registrars. Discovery remains available
  through the DHT.
- Permissions specify the service, allowed decisions, and whether further
  delegation is allowed. State what a stolen TLS key could authorize.
- Owners can revoke or replace delegates without their help by updating signed
  records. Clients need time to refresh those records.
- Users keep their identity, content, and links. Independent copies and
  migration must be practical and affordable. Updating routing does not move
  stored data.

### Client behavior

- Verify the authorized TLS key, even when an ordinary domain supplies the
  address. Domain-based HTTPS alone does not prove the owner's authorization.
- Respect proxies and distinguish discovery, connection, and authorization
  failures.
- Refresh permissions, including for reused connections. A valid signature
  does not prove that a record is current.
- Bound lookups and retries. Preserve verification and avoid repeating
  operations whose outcome is uncertain.
- Failed checks must not silently switch to domain-based trust or plaintext.

## Supporting issues

Reviewed on 2026-10-02. All six issues were open; PR #366 was closed without
merging. These reports were not independently reproduced. Their relevance is
our assessment.

- **[Homeserver #18: remote controller][hs-18].** Proposes resolution through
  an intermediary controller. Directly motivates managing records separately
  from the serving machine.
- **[Homeserver #140: provider URLs][hs-140].** Motivates browser access while
  retaining stable user addresses. A provider URL depends on that host and
  ordinary browser certificate trust.
- **[Homeserver #647: probe bypasses the proxy][hs-647].** Reports delays from
  a connection check that ignores the proxy. Motivates checking the route the
  request will actually use.
- **[Homeserver #657: failed discovery selects a transport][hs-657].** Reports
  failed lookups being cached as transport choices and requests to names a
  proxy cannot resolve. Motivates explicit errors and usable proxy routes
  that still verify the authorized key.
- **[Homeserver #29: retry after cache updates][hs-29].** Reports stale records
  pointing to old servers. Motivates refresh and safe, bounded retries during
  host or key changes.
- **[Homeserver PR #366: HTTP for IP-address testnets][hs-366].** Shows why
  transport settings should be explicit: an IP-address heuristic could disable
  HTTPS. This is a deployment concern, not a delegation mechanism.
- **[Pkarr #292: standard TLS for ordinary domains][pkarr-292].** Reports a TLS
  failure with an ordinary HTTPS server. Motivates explicit verification
  policy; switching to browser certificate trust changes the trust model.

[hs-18]: https://github.com/pubky/pubky-homeserver/issues/18
[hs-140]: https://github.com/pubky/pubky-homeserver/issues/140
[hs-647]: https://github.com/pubky/pubky-homeserver/issues/647
[hs-657]: https://github.com/pubky/pubky-homeserver/issues/657
[hs-29]: https://github.com/pubky/pubky-homeserver/issues/29
[hs-366]: https://github.com/pubky/pubky-homeserver/pull/366
[pkarr-292]: https://github.com/pubky/pkarr/issues/292
