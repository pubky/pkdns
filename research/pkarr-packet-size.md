# PKARR packet size and record capacity

PKARR's Rust builder allows **1,000 bytes of compressed DNS data**. The
signature is outside that budget. There is no fixed record count: names,
record types, parameters, and compression determine how many fit.

The examples in the [delegation discussion](./delegation-discussion.md) fit
comfortably. One option C delegation uses 218 DNS bytes, compared with 132
for option A or B. A service endpoint
with two TLSA keys uses 202 bytes. The extra records in option C become
more significant when one key manages many distinct service names.

## What the limit includes

Let D be the size of the compressed DNS packet, including its DNS header.
The [PKARR encoding][base] and [Rust API][api] distinguish these forms:

| Form                    | Contents                                 | Size at D = 1,000 |
|-------------------------|------------------------------------------|-------------------|
| DNS packet              | DNS header and records                   | 1,000 bytes       |
| Relay body              | 64-byte signature + 8-byte timestamp + D | 1,072 bytes       |
| Canonical signed packet | 32-byte public key + relay body          | 1,104 bytes       |

There is **one signature per packet**, not one per DNS record. Adding a
record does not add another signature. The relay already receives the
public key in its request URL, so its body omits those 32 bytes.
See the [relay format][relays].

These sizes are not the complete network message size. A DHT message
also contains bencoding and RPC fields; UDP and IP add headers. An HTTP
relay adds HTTP and transport overhead. Those bytes do not consume the
Rust builder's 1,000-byte DNS budget.

Each signer has its own packet and budget. A chain K -> K2 -> S consists
of separate signed packets; it does not have to fit into one 1,000-byte
packet. Conversely, all names under K share K's packet. Adding `app.K`
does not create another budget, and an update replaces the packet rather
than appending an independently stored record set.

### A small boundary difference

Both PKARR 3.8.0 and 8.0.2 accept exactly 1,000 DNS bytes and reject 1,001.
The local Mainline server implementation also checks the raw value length
against 1,000. However, [BEP 44][bep44] allows nodes to reject a *bencoded*
value larger than 1,000 bytes. A 1,000-byte byte string takes 1,005 bytes
when bencoded; a 996-byte string takes exactly 1,000.

Use **996 DNS bytes or less** if allowing for that stricter reading, and
reserve more room for future changes. This research measures serialization
and signature verification, not acceptance by every public DHT node.
The signature remains outside the value in either interpretation.

## Why record sizes differ

A DNS packet starts with a 12-byte header. Each resource record then has
an owner name, 10 bytes of fixed fields, and its record data. A 52-character
Pubky key label takes 54 bytes as a complete DNS name: one length byte,
52 label bytes, and a terminating zero.

DNS compression can replace repeated names or suffixes with a two-byte
pointer. For example, after the first record at K, another record at K
usually needs only a two-byte owner name. Compression is within one DNS
packet; it does not share names across packets.
See [RFC 1035][dns-compression].

HTTPS and SVCB target names must be written without compression, even
when the same name appears elsewhere in the packet. This makes aliases
to 52-character key labels relatively expensive.
See [RFC 9460 section 2.2][svcb-wire].

For `TLSA 3 1 1`, the record data is three parameter bytes followed by a
32-byte SHA-256 hash. Its 64 hexadecimal characters are only the text
representation. There is no certificate or signature inside that record.
See [RFC 6698][tlsa].

Once an identical owner name has appeared, typical additional costs are:

| Record                           | Owner | Fixed fields | Data   | Added bytes |
|----------------------------------|-------|--------------|--------|-------------|
| A                                | 2     | 10           | 4      | 16          |
| AAAA                             | 2     | 10           | 16     | 28          |
| TLSA 3 1 1                       | 2     | 10           | 35     | 47          |
| HTTPS alias to another Pubky key | 2     | 10           | 2 + 54 | 68          |

These are costs of additional records, not of a packet's first record. New
owner names, longer targets, and extra service parameters add bytes.
For example, `port=443` adds six bytes even though 443 is the default;
omitting an unnecessary parameter saves that space.

## Measured delegation examples

The measurements use real 52-character public-key labels, TTL 300, and
PKARR's normal compressed serializer.
Hashes contain 32 bytes of example data; their contents do not affect size.
All successful packets are signed and verified through relay serialization.

The results are identical with PKARR 3.8.0 and simple-dns 0.9.3, as used
by this repository, and PKARR 8.0.2 with simple-dns 0.12.0.

| Packet contents                               | Records | DNS bytes | Relay body | Canonical bytes |
|-----------------------------------------------|---------|-----------|------------|-----------------|
| One HTTPS alias to another Pubky key          | 1       | 132       | 204        | 236             |
| Option C HTTPS alias plus TLSA-name CNAME     | 2       | 218       | 290        | 322             |
| Option A rotation with two HTTPS aliases      | 2       | 200       | 272        | 304             |
| Option A endpoint: HTTPS to `.` with port + A | 2       | 101       | 173        | 205             |
| Option B/C endpoint with one TLSA pin         | 2       | 155       | 227        | 259             |
| Option B/C endpoint with two TLSA pins        | 3       | 202       | 274        | 306             |

The option C delegation points both records to the same delegate:

```dns
K.           300 IN HTTPS 0 S.
_443._tcp.K. 300 IN CNAME _443._tcp.S.
```

Here K and S stand for full key labels. The CNAME adds 86 bytes with the
tested serializer and record order. CNAME targets can be compressed, but
this serializer does not reuse the earlier uncompressed HTTPS target for
that purpose. Record ordering and compression implementation can affect
results; this is not a universal minimum encoding.

The option B/C endpoint example contains:

```dns
S.           300 IN HTTPS 1 edge.example. port=443
_443._tcp.S. 300 IN TLSA 3 1 1 <32-byte-hash>
```

`edge.example` resolves through ordinary DNS, so its address records are
not in S's packet. Adding addresses or more HTTPS parameters consumes more
space. A second TLSA pin at the same name adds exactly 47 bytes here.

## How many records fit

A records hold IPv4 addresses; AAAA records hold IPv6 addresses.

These are measured capacities for specific examples, not protocol-wide
record limits. Every row starts with a fresh packet. The last column is
the size after adding one more record or service, which the builder rejects.

| Contents                                                   | Maximum fitting count    | DNS bytes | First rejected size |
|------------------------------------------------------------|--------------------------|-----------|---------------------|
| A records at one owner                                     | 58 records               | 992       | 1,008               |
| AAAA records at one owner                                  | 33 records               | 988       | 1,016               |
| TLSA pins at one `_443._tcp` owner                         | 19 records               | 967       | 1,014               |
| One `edge.example` HTTPS endpoint plus TLSA pins           | 18 pins + 1 HTTPS record | 954       | 1,001               |
| HTTPS aliases at one owner to distinct Pubky keys          | 13 records               | 948       | 1,016               |
| A records at distinct three-character subdomains           | 46 records               | 984       | 1,004               |
| HTTPS aliases at distinct three-character subdomains       | 13 records               | 1,000     | 1,072               |
| Option C pairs at distinct subdomains and delegates        | 5 services / 10 records  | 854       | 1,012               |
| Option C pairs at distinct subdomains, one shared delegate | 9 services / 18 records  | 990       | 1,086               |

The subdomains are `s00`, `s01`, and so on. Each option C service has one
HTTPS alias and one TLSA-name CNAME. Only the shared-delegate row reuses
the same target across services. The 1,000-byte row fits the Rust builder
but exceeds the conservative 996-byte budget; under that budget it fits
12 aliases instead.

An isolated 19-pin TLSA packet leaves 33 DNS bytes free. It cannot add a
twentieth pin for rotation. With the measured HTTPS endpoint included,
18 pins fit, but a nineteenth takes the packet to 1,001 bytes. Capacity
planning must include the overlap during key rotation, not just normal use.

## Implications for the delegation design

- **Options B and C have cheap TLS rotation.** Adding the second pin costs
  47 bytes in the example. The TLS key needs no packet of its own.
- **Option C fits a small identity comfortably.** Its separate chain adds
  86 bytes in the simple delegation packet. Many distinct service names
  and delegate keys are where that cost starts to matter.
- **A provider does not need one record per customer.** Users can delegate
  to a shared S; S publishes its endpoints and accepted TLS keys once.
  Separate per-customer key policies would consume additional space.
- **Several names do not mean several packets.** Splitting services under
  `one.S` and `two.S` separates policy but still uses S's single budget.
  A separate public key has its own packet, at the cost of another signed
  delegation and lookup.
- **Keep room for the whole service.** Extra ports, TCP and QUIC key sets,
  IPv6, ALPN parameters, and rotation all share the budget.
  Measure the full packet rather than adding maximum counts from this table.

Do not enlarge the payload beyond what the DHT supports just to fit more
records. Distributing records through explicit key delegation preserves
public-key authority and DHT discovery. Oversized relay-only packets would
need a separate design and would weaken that deployment assumption.

[base]: https://github.com/pubky/pkarr/blob/main/design/base.md
[api]: https://docs.rs/pkarr/8.0.2/pkarr/struct.SignedPacket.html
[relays]: https://github.com/pubky/pkarr/blob/main/design/relays.md
[bep44]: https://www.bittorrent.org/beps/bep_0044.html#messages
[dns-compression]: https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.4
[svcb-wire]: https://www.rfc-editor.org/rfc/rfc9460.html#section-2.2
[tlsa]: https://www.rfc-editor.org/rfc/rfc6698.html#section-2.1
