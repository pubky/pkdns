# Pubky HTTPS service delegation

A Pubky identity can stay the same while its hosting changes. The owner uses
signed DNS records to delegate an HTTPS service without sharing their private
key. Delegates can choose servers or delegate again to a TLS provider; the
original URL remains the service's identity.

**Status:** proposed specification, not yet implemented by all Pubky clients or
pkdns.

## Motivation

A chain such as `K -> K2 -> S -> T` separates everyday operations from long-term
keys:

- **User identity:** K delegates to the user's operational key K2. K's private
  key stays offline while K2 selects or changes the homeserver.
- **Homeserver identity:** the homeserver's stable key S delegates to an online
  TLS key T. S stays offline between delegation changes. Rotating or replacing a
  compromised T requires updating S's packet; users keep their existing records
  pointing to S.
- **Failover and migration:** S can publish aliases to both T1 and T2.  Clients
  can try either endpoint. The operator can prepare T2, authorize both during a
  migration, then remove T1 without users signing new records.  Both endpoints
  must be ready to serve the same service.

Each block below belongs to a PKARR packet: DNS records signed by one key.

```dns
; Signed by K: delegate everyday hosting decisions
K.  300 IN HTTPS 0 K2.

; Signed by K2: choose homeserver S
K2. 300 IN HTTPS 0 S.

; Signed by S: choose TLS terminator T
S.  300 IN HTTPS 0 T.

; Signed by T: publish the endpoint
T.  300 IN HTTPS 1 . port=443
T.  300 IN A     203.0.113.10
```

For `https://K/page`, the client verifies the chain, connects to
`203.0.113.10:443`, authenticates **T's TLS key**, sends SNI T, and requests
`/page` with `Host: K`. Only the TLS terminator needs T's private key.
Delegation authorizes serving the origin; it neither permits signing as K nor
proves that K approved individual responses. Content signatures are outside this
specification.

## Specification

### Names and scope

Accept HTTPS URLs whose hostname ends in a valid Ed25519 public key encoded as a
lowercase z-base-32 DNS label. K, K2, S, T, and similar names are key
placeholders. Validate keys with a Pubky parser, not a length check. The
human-facing prefix `pubky` is not part of the DNS label.

Normalize the hostname and port. A grant covers every path and query at one
origin: scheme, hostname, and URL port. Omitted port and explicit port 443 are
equivalent. Other hostnames and ports require separate records.

For port 443, look up HTTPS at the hostname. For another port, prepend
`_PORT._https`:

| URL | HTTPS lookup name |
|----------------------------------|-----------------------|
| `https://K/` or `https://K:443/` | `K.`  |
| `https://app.K/` | `app.K.`  |
| `https://app.K:8443/` | `_8443._https.app.K.` |
| `https://_pubky.K/` | `_pubky.K.`  |

The last key label selects the packet signer: `app.K` and `_pubky.K` use K's
packet. Match exact names. Version 1 excludes NS/DNAME delegation for these
service lookups.

Wildcard matching is explicitly unsupported: no clear use case has been
identified for this proposal. As [Wikipedia][wildcards] puts it, the original
RFC 1034 rules "are neither intuitive nor clearly specified".  [RFC
4592][wildcard-rfc] later clarified those rules.

### Record meanings

HTTPS records use [RFC 9460][svcb] syntax: priority, target, and optional
parameters.

- **AliasMode, priority 0:** delegate the service and follow the target's HTTPS
  records. A Pubky target selects its key as the TLS identity and may delegate
  further.
- **ServiceMode, positive priority:** resolve the target's A/AAAA addresses,
  keeping the current TLS identity. Do not follow its HTTPS records.

For records signed by S while using Pubky TLS identities:

| Record at S | Next lookup | TLS identity |
|-------------------------|-------------------|------------------------|
| `HTTPS 0 T.`  | T's HTTPS records | T or its final delegate |
| `HTTPS 1 T.`  | T's addresses | S |
| `HTTPS 0 host.example.` | Domain's HTTPS | WebPKI: `host.example` |
| `HTTPS 1 host.example.` | Domain addresses | S |
| `HTTPS 1 .`  | S's addresses | S |

ServiceMode target `.` means the record owner; AliasMode target `.` makes that
branch unavailable.

Only a signed Pubky HTTPS alias to an ordinary domain enters **WebPKI**, using
normal certificate-chain and domain-name checks. The first domain fixes that
branch's TLS identity. Later aliases change routing only, even if they reach a
Pubky name; they cannot restore raw-key authentication.

### Resolution

Keep the original origin, TLS identity, and connection address separate.
Initially, the TLS identity is the key in the URL hostname.

1. **Verify records.** Every Pubky lookup, for HTTPS or addresses, requires the
   complete packet's signature to match the key in the lookup name.  Read only
   that name's records. This also applies after entering WebPKI.  Plain DNS
   answers are not proof of Pubky records. Reject CNAME at Pubky HTTPS lookup
   names; ordinary DNS service lookups may follow CNAMEs.
2. **Follow aliases first.** If any AliasMode records exist, ignore ServiceMode
   records in that set and parameters on the aliases. Follow every target as an
   independent branch, applying the TLS rules above.  Use targets exactly,
   without carrying over subdomains or port prefixes.
3. **Otherwise, use compatible ServiceMode records.** Process increasing
   priorities and shuffle equal priorities. Keep each record's parameters
   together. Use its `port`, or the original URL port if absent. Apply
   `mandatory`, `alpn`, and `no-default-alpn` as RFC 9460 specifies; skip
   incompatible records. HTTP/1.1 over TLS is the baseline transport; clients
   may also support HTTP/2 and HTTP/3.
4. **Use direct addresses only when HTTPS records are absent.** For a verified
   Pubky packet, use A/AAAA at the lookup name and the original URL port. At the
   initial nondefault-port lookup, use the URL hostname for addresses, without
   the port prefix. Ordinary DNS requires a successful lookup with no HTTPS data
   and uses the final name's addresses.

For addresses, follow A/AAAA and address CNAMEs. CNAMEs and address hints never
change the TLS identity. Apply normal destination IP and port restrictions.

Missing or invalid packets, malformed records, unavailable targets, loops, and
depth limits fail the affected path. NXDOMAIN, SERVFAIL, timeout, and DNSSEC
validation failure do not count as absent HTTPS data. Never fall back to an
earlier authority's addresses or ignored ServiceMode records.  Other authorized
branches may still succeed.

Allow at most **eight HTTPS aliases per path** and **eight CNAME steps per
chain**. Detect loops per path; independent paths may reach the same name.
Bound total traversal work and overall resolution time. If either overall limit
prevents completing traversal, return an error rather than a partial plan.

### Connection plans

Return candidates from every usable branch. Shuffle aliases once per owner and
concatenate branch results in that order, preserving ServiceMode ordering within
each branch. Do not compare priorities across delegates or order branches by
network response timing.

Each candidate binds its address and port, HTTP protocol, TLS identity, and
reuse deadline. Keep different identities separate even at the same IP.  The
caller connects and chooses when to try another candidate. Return an error if no
branch yields candidates.

Share packet fetches and use one packet version per key throughout the
attempt. If a required cached packet changes before returning the plan, restart
within the overall timeout.

### TLS and HTTP

For a Pubky identity, require TLS 1.3 with an Ed25519 raw public key using [RFC
7250][rpk]. Match the selected key byte for byte and verify the handshake
signature and Finished message. Reject X.509 certificates.

For WebPKI, validate the certificate chain and fixed domain name with the
client's normal verifier. A TLS failure never permits weaker verification;
verify each candidate before sending HTTP data.

TLS Server Name Indication (SNI) uses the selected key label or WebPKI domain,
without a port or trailing dot. HTTP/1.1 `Host` and HTTP/2 or HTTP/3
`:authority` use the original hostname and nondefault URL port.  Terminators
must serve those HTTP authorities even when they differ from SNI.

Paths, queries, cookies, credentials, caches, and origin checks retain normal
behavior for the original URL. The HTTP `Origin` header identifies the
initiating origin. Resolve redirect URLs separately.

### Caching and reuse

Keep the existing PKARR format. Version 1 has no hard signed expiry, persistent
packet-version store, or rollback checks; TTLs limit local reuse.

A used record expires at its original fetch time plus the smaller of its TTL and
**300 seconds**. Cache reads do not restart that clock. Zero TTL allows the
current attempt only. To cache absent HTTPS records, use the packet's smallest
TTL, capped at 300 seconds; an empty packet uses 300.

A candidate expires at the earliest deadline on its path; failed branches do not
shorten it. The plan expires at its earliest candidate deadline.  Replacing a
cached packet invalidates dependent plans. Refresh expired records before
another request; required refresh failures are errors.

Separate connection pools and TLS resumption by original origin and TLS
identity. After authority changes, stop starting requests on old connections or
reusing their TLS sessions. Version 1 excludes TLS early data, cross-origin
connection sharing, and Alt-Svc endpoint selection.

## Special cases and edge cases

### Address selection and ports

`S. HTTPS 1 T. port=8443` uses T's addresses on port 8443 but requires S's TLS
key. Any HTTPS aliases published by T are irrelevant to that lookup.
Conversely, `K. HTTPS 0 T.` followed by a verified T packet containing only
addresses connects on the original URL port and requires T's key.

For `https://app.K:8443/page`, an alias at `_8443._https.app.K` to S looks up
exactly `S`. If the chain ends at T with `HTTPS 1 . port=9443`, connect on 9443,
authenticate T, send SNI T, and send `Host: app.K:8443`.

### Independent branches

With `K. HTTPS 0 H1.` and `K. HTTPS 0 H2.`, each branch has its own TLS identity
and deadline; both use HTTP authority K. H2 can succeed if H1's lookup or
connection fails. Branches may mix Pubky and WebPKI identities, and converging
paths are not themselves loops.

### Ordinary domain delegation

For `K -> host.example -> edge.example.net`, where K signs the first HTTPS
alias, connect to the final endpoint but require a certificate for
**host.example**. Send SNI `host.example` and HTTP authority K. A certificate
for `edge.example.net` alone fails. The HTTPS alias limit spans the whole chain.

### Pubky storage and homeserver identity

`K` and `_pubky.K` are separate HTTPS origins. To serve both through H, K
explicitly publishes aliases at both names. Assuming H ends the chain, both
authenticate H and send SNI H, while their HTTP authorities remain `K` and
`_pubky.K`. `_pubky` is an application convention, not a separate transport. An
alias to K2 looks up K2; it does not imply `_pubky.K2`.

A chain such as `_pubky.K -> K2 -> H -> T` does not label user, homeserver, or
TLS-provider roles. The client authenticates T if it ends the chain.  An
operator checking delegation to its key H can stop when a verified AliasMode
path reaches H before entering WebPKI, without fetching H's
records. Address-only targets do not count. Answering no requires checking all
paths; a failed or unchecked path leaves the answer unknown.

## How this differs from normal DNS

The record syntax comes from [RFC 9460][svcb], but these rules require a
Pubky-aware client:

- **TLS authority:** standard HTTPS aliases retain the original name for
  certificate validation and SNI. Signed Pubky aliases can select another key or
  a WebPKI domain, so providers need no access to the owner's key.  The HTTP
  origin remains unchanged.
- **Alternatives:** RFC 9460 recommends choosing one AliasMode record at
  random. This proposal resolves all alternatives for failover.
- **CNAME handling:** RFC 9460 follows CNAMEs during HTTPS resolution.
  Pubky HTTPS lookups reject them; only signed HTTPS aliases transfer service
  authority. Address lookups can still follow CNAMEs.
- **Failure handling:** RFC 9460 requires fallback to the original endpoint
  when its alias limit prevents resolution. Here, the affected path fails;
  other authorized branches may still succeed.

[svcb]: https://www.rfc-editor.org/rfc/rfc9460.html
[rpk]: https://www.rfc-editor.org/rfc/rfc7250.html
[wildcards]: https://en.wikipedia.org/wiki/Wildcard_DNS_record
[wildcard-rfc]: https://www.rfc-editor.org/rfc/rfc4592.html
