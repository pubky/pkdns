# Pkarr packet size

Pkarr's Rust builder allows **1,000 bytes of compressed DNS data** per signed
packet. Record count depends on names, record types, parameters, and
compression. The signature is outside that budget.

## Budget and wire formats

Let D be the compressed DNS packet size, including its header
([encoding][base], [Rust API][api]):

| Form | Contents | Size at D = 1,000 |
|------|----------|-------------------|
| DNS packet | Header and records | 1,000 bytes |
| Relay body | 64-byte signature + 8-byte timestamp + D | 1,072 bytes |
| Canonical signed packet | 32-byte public key + relay body | 1,104 bytes |

There is one signature per packet. The relay gets the public key from its URL,
so omits those 32 bytes ([relay format][relays]). DHT, HTTP, UDP, and IP framing
add further network overhead.

Each signer has its own packet. `identity -> controller -> provider` spans
three budgets. All names under `identity` share its budget; adding
`app.identity` does not create another packet. An update replaces the entire
packet.

### DHT boundary

Pkarr 3.8.0 and 8.0.2 accept 1,000 DNS bytes and reject 1,001. The local
Mainline implementation checks raw value length. However, [BEP 44][bep44]
allows rejection of a *bencoded* value larger than 1,000 bytes: a 1,000-byte
string encodes to 1,005 bytes, while 996 bytes encode to exactly 1,000.

Use **996 DNS bytes or less** for that stricter interpretation, and reserve
space for updates. The measurements cover serialization and signature
verification, not acceptance by every public DHT node.

## Encoding costs

DNS starts with a 12-byte header. Each record adds its owner name, 10 fixed
bytes, and record data. A complete 52-character key name takes 54 bytes.
Repeated names can use two-byte compression pointers within one packet
([RFC 1035][dns-compression]).

HTTPS/SVCB targets cannot be compressed ([RFC 9460][svcb-wire]).
A `TLSA 3 1 1` value contains three field bytes and a 32-byte hash; its
hexadecimal display is not its wire size ([RFC 6698][tlsa]).
`TLSA 1 1 1` and `TLSA 3 0 1` have the same size; optional certificate-name
TXT metadata needs its own budget.

Once the owner name has appeared, typical added costs are:

| Record | Owner | Fixed fields | Data | Added bytes |
|--------|-------|--------------|------|-------------|
| A | 2 | 10 | 4 | 16 |
| AAAA | 2 | 10 | 16 | 28 |
| TLSA 3 1 1 | 2 | 10 | 35 | 47 |
| TXT "pubky-tls-name=edge.example" | 2 | 10 | 28 | 40 |
| HTTPS alias to another key | 2 | 10 | 2 + 54 | 68 |

These are incremental costs, not first-record sizes. New names and connection
parameters add space; `port=443`, for example, adds six bytes.

## Recorded measurements

The measurements used real 52-character key labels, TTL 300, and Pkarr's
compressed serializer. Successful packets were signed and verified through
relay serialization. Results matched Pkarr 3.8.0 / simple-dns 0.9.3 and
Pkarr 8.0.2 / simple-dns 0.12.0.

| Packet | Records | DNS bytes | Relay body | Canonical bytes |
|--------|---------|-----------|------------|-----------------|
| One HTTPS alias | 1 | 132 | 204 | 236 |
| C: HTTPS alias and TLSA-name CNAME | 2 | 218 | 290 | 322 |
| A: two rotation aliases | 2 | 200 | 272 | 304 |
| A: HTTPS to `.` with port + A | 2 | 101 | 173 | 205 |
| B/C: endpoint with one TLSA pin | 2 | 155 | 227 | 259 |
| B/C: endpoint with two TLSA pins | 3 | 202 | 274 | 306 |

The C delegation measured was:

```dns
identity.           300 IN HTTPS 0 provider.
_443._tcp.identity. 300 IN CNAME _443._tcp.provider.
```

`identity` and `provider` stand for full key labels. The CNAME adds 86 bytes in
this serializer and record order; this is not a universal minimum. Although
CNAME targets can be compressed, this serializer does not reuse the earlier
HTTPS target.

The B/C endpoint was:

```dns
provider.           300 IN HTTPS 1 edge.example. port=443
_443._tcp.provider. 300 IN TLSA 3 1 1 <32-byte-hash>
```

Ordinary DNS resolves `edge.example`, so its address records are outside
`provider`'s packet. Adding a second pin at the same name costs 47 bytes.

## Capacity examples

Each row starts with a fresh packet. A records contain IPv4 addresses; AAAA
records contain IPv6 addresses. These capacities apply to the measured layouts,
not all possible records.

| Contents | Maximum fitting count | DNS bytes | First rejected size |
|----------|-----------------------|-----------|---------------------|
| A at one owner | 58 records | 992 | 1,008 |
| AAAA at one owner | 33 records | 988 | 1,016 |
| TLSA at one `_443._tcp` owner | 19 pins | 967 | 1,014 |
| One HTTPS endpoint plus TLSA | 18 pins + 1 HTTPS | 954 | 1,001 |
| HTTPS aliases to distinct keys at one owner | 13 records | 948 | 1,016 |
| A at distinct three-character subdomains | 46 records | 984 | 1,004 |
| HTTPS aliases at distinct three-character subdomains | 13 records | 1,000 | 1,072 |
| C pairs at distinct subdomains and delegates | 5 services / 10 records | 854 | 1,012 |
| C pairs at distinct subdomains, one shared delegate | 9 services / 18 records | 990 | 1,086 |

Subdomains were `s00`, `s01`, and so on. Each C service has an HTTPS alias
and a TLSA-name CNAME. Under the conservative 996-byte budget, the 1,000-byte
row fits only 12 aliases.

## Design consequences

- Reserve rotation space: neither the isolated 19-pin packet nor the endpoint
  with 18 pins can add another pin within the builder's limit.
- A shared provider can publish endpoints and TLS pins once for many users.
  Separate customer policies consume extra space.
- Several subnames still share one packet. A separate key gains its own budget
  but requires another delegation and lookup.
- Measure the complete publication, including IPv6, ports, transports, TXT
  metadata, and rotation. Maximum counts from different rows cannot be added
  together.

Keep records within the DHT limit. Use explicit key delegation to distribute
them rather than relying on oversized packets available only through relays.

[base]: https://github.com/pubky/pkarr/blob/main/design/base.md
[api]: https://docs.rs/pkarr/8.0.2/pkarr/struct.SignedPacket.html
[relays]: https://github.com/pubky/pkarr/blob/main/design/relays.md
[bep44]: https://www.bittorrent.org/beps/bep_0044.html#messages
[dns-compression]: https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.4
[svcb-wire]: https://www.rfc-editor.org/rfc/rfc9460.html#section-2.2
[tlsa]: https://www.rfc-editor.org/rfc/rfc6698.html#section-2.1
