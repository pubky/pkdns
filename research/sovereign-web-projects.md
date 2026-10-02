# Sovereign web projects

Research date: 2026-10-02.

This report compares projects that address names, discovery, hosting, or
connection authentication without relying entirely on conventional DNS and
public certificate authorities. It covers the projects found in the survey,
including Spaces and fips-pub-domains. Here, a sovereign web means that people
can retain their identity and move their services or data without needing a
single provider's permission. Different projects deliver different parts of that
goal.

The sources are project documentation, specifications, and repositories.
Software was not installed or tested. Implementation claims are attributed to
their projects; browser compatibility and security have not been independently
verified. Repository development branches can differ from released products.

Assessments for Pubky are our interpretation, guided by the
[first principles](./first-principles.md) and
[design principles](./design-principles.md). Examples use fictional people and
illustrative service configurations. They explain the architecture; they are not
deployment instructions or test results.
The report describes other architectures without proposing a replacement for
the current SDK.

## A short introduction

### The problem these projects address

Suppose Alice publishes a website. On the conventional web, several parties help
make it reachable: a registrar maintains her domain registration, DNS servers
provide its address, a certificate authority certifies its TLS key, and a
hosting provider stores the website. These roles can belong to different
companies, but each creates a dependency.

Changing hosting is usually possible while keeping the domain. Keeping that
domain after losing the registration is a different problem. Likewise, keeping a
name does not help if the only copy of the website has disappeared.

The projects below move these responsibilities to different places. Some use a
public key as the name. Some use a blockchain to allocate readable names. Some
distribute data among peers. Some build an encrypted network underneath ordinary
applications. A project can solve one of these problems well without solving all
of them.

### Essential terms

- **Key pair:** a private key kept secret and a public key shared with others.
  A holder of the private key can create signatures that the public key checks.
  The same person may have separate identity, server, and encryption keys.
- **Signature:** evidence that a particular key authorized particular data.
  It does not, by itself, prove that the data is the latest version.
- **Hash:** a compact fingerprint of data. A content hash identifies particular
  bytes; changing those bytes changes their fingerprint. Unlike a signature,
  a hash alone does not identify an author.
- **Authority:** the rule deciding who may change a name or authorize a service.
  It might be a key holder, a blockchain owner, or a conventional DNS owner.
- **Resolution:** looking up a name to obtain an address, key, or content
  pointer.
- **DHT:** a distributed hash table. Many computers share lookup and storage
  work. A DHT can locate signed records without being trusted to create them.
- **Peer:** another participating computer. **Replication** means keeping copies
  on several computers, so one machine need not remain the only source.
- **Gateway:** a service translating one network or protocol into another,
  commonly making P2P content available through an ordinary web URL.
- **Trust anchor:** a key or other starting fact the client already trusts.
  Verification follows a chain from that starting point.

These terms describe different roles. A computer can deliver a record without
having authority to modify it. A host can serve Alice's website without holding
Alice's identity private key.

### DNS, DNSSEC, TLS, and DANE

**DNS** answers questions such as “where is this hostname?” **DNSSEC** adds
signatures to DNS records. A validator checks those signatures through a chain
of keys back to its configured trust anchor. DNSSEC protects the answer's
integrity; it does not encrypt DNS traffic or the website connection.
[DNSSEC introduction](https://www.rfc-editor.org/rfc/rfc4033.html)

**TLS** protects the connection used by HTTPS. On the conventional web, the
server presents a certificate associating its key with a hostname, and the
client checks it under trusted certificate authorities. This conventional
certificate system is called **WebPKI**.
[TLS specification](https://www.rfc-editor.org/rfc/rfc8446.html)

**DANE** lets authenticated DNS records authorize a TLS key or certificate.
Its TLSA record is a rule for the TLS verifier. For example, a record can say
“accept the server key with this fingerprint.” This requires both trustworthy
DNS records and a client that enforces the rule during TLS authentication.
[DANE specification](https://www.rfc-editor.org/rfc/rfc6698.html)

A **certificate** is not always a WebPKI certificate. Tor uses certificates
between its own keys; Spaces uses ownership proofs. Similar terminology does not
make these objects interchangeable with HTTPS certificates.

### Why the browser matters

The browser treats a page as belonging to an **origin**: its scheme, hostname,
and port. Paths do not create separate origins. For example,
`https://gateway.example/alice/` and `https://gateway.example/bob/` share an
origin, while `https://alice.gateway.example/` and
`https://bob.gateway.example/` do not. This matters for separating website
scripts and storage. [Origin definition][web-origin]

There are two distinct browser tasks: verifying the service and isolating its
website from other websites. A gateway can provide valid HTTPS while giving many
publishers one shared origin. An encrypted overlay can verify a peer while the
browser still sees an ordinary HTTP URL.

Throughout this report, ask: **which component checks the owner's authority, and
what identity does the browser actually see?**

## Main findings

- **GNS** is the closest match for public-key namespaces and delegation.
- **Handshake browser tools** offer concrete approaches to DANE and local
  browser integration.
- **Namecoin** addresses both accepting authorized certificates and excluding
  competing certificate authorities.
- **Tor** demonstrates a browser security model rooted in a key-based name.
- **Freenet, Hyphanet, IPFS, and Holepunch** are more relevant to distributing
  applications and data than to authenticating an ordinary HTTPS endpoint.
- **Spaces** verifies readable names through Bitcoin proofs. Its HTTP relay
  verification does not add a capability missing from Pubky discovery.
- **fips-pub-domains** uses conventional DNS authority to bootstrap a mesh
  binding. Offline operation does not make its names independent of DNS.

## What to compare

Four questions need separate answers:

1. **Name ownership:** who can authorize a binding for this name?
2. **Discovery:** how does a client find the current records or service?
3. **Connection authentication:** how does it verify the service it reaches?
4. **Browser integration:** how does that verified service become a web origin?

DNSSEC authenticates DNS records. DANE uses authenticated TLSA records to
authorize a TLS certificate or key. A valid discovery signature alone does
not change a browser's TLS verifier. See
[DNSSEC](https://www.rfc-editor.org/rfc/rfc4033.html) and
[DANE](https://www.rfc-editor.org/rfc/rfc6698.html).

An unchanged browser with installed proxy software is different from an
unchanged browser with no installation. A browser SDK that verifies discovery
records is also different from a browser that authenticates navigation to a
public-key domain.

| Project family | Root of authority | Discovery or delivery | Browser path examined | Main relevance |
| --- | --- | --- | --- | --- |
| GNS | User-selected zone keys | Signed records in a DHT | Local resolver or TLS proxy | Delegation and record binding |
| Handshake | Blockchain name ownership | DNS with an alternative root | Local proxy or dedicated browser | DNSSEC, DANE, and HTTPS integration |
| Namecoin | Blockchain name ownership | Blockchain records through ncdns | Platform certificate integration | Certificate authorization and restrictions |
| Tor onion services | Key in the service name | Tor descriptors and rendezvous | Tor Browser | Authenticated key-based origins |
| Freenet | Contract hash and contract rules | Replicated application state | Browser connected to local node | Distributed applications |
| Hyphanet | Content hashes or publisher keys | Distributed storage | Local FProxy | Publishing and mutable references |
| IPFS / IPNS | Content hashes or naming keys | DHT and gateways | Gateway or native integration | Portable references and origin isolation |
| Holepunch / Pear | Application and peer keys | HyperDHT and replication | Installed application runtime | Connections by key and replicated storage |
| I2P | Cryptographic destination; local alias policy | Address books and overlay routing | Local proxy | Personal names over cryptographic identities |
| ENS | Ethereum ownership; DNS authority for imports | Resolver contracts and gateways | Supported client or gateway | Readable names and content pointers |
| Yggdrasil | Node key-derived address | Mesh routing | Installed IPv6 overlay | Authenticated network identity |
| Spaces | Bitcoin-anchored ownership proofs | Certrelay HTTP network | SDK verification | Readable names with portable proofs |
| fips-pub-domains | DNS binding or explicit local trust | Nostr claims and mesh DNS | Installed mesh and resolver | Offline DNSSEC proof verification |

The sections below can be read independently. Each explains the technology,
walks through its trust model, and assesses the practical tradeoffs. Readers
focused on names and certificates can start with GNS, Handshake, Namecoin, and
Tor. Readers focused on hosting and data can start with the two Freenet
projects, IPFS, and Holepunch.

## 1. GNUnet and the GNU Name System

### What it is and how it works

GNS is a decentralized naming system implemented in GNUnet. A zone, a group of
names under one authority, belongs to a key pair. Users choose their starting
zones, assign personal names, and
delegate to other public-key zones. Signed records are distributed through a
DHT. Direct zone-key names avoid needing a globally registered readable name.
[GNS manual][gns-manual]

Its record format is distinct from DNSSEC. GNS can carry familiar DNS record
types, but their authority comes from GNS zone verification. The `BOX` record
bundles service-specific records, including TLSA, with the name's other
records. The resolver can expose them through the usual service labels.
This makes authentication data inseparable from the associated address set.
[GNS specification][gns-spec]

### Browser and certificate handling

DNS2GNS exposes resolution through a local DNS interface. This alone does not
make a non-DNS name pass browser certificate checks. The alternative GNS
proxy integrates resolution and TLS verification; installation can create a
local CA and generate browser-facing certificates. The manual calls browser
proxy support experimental and reports browser-specific problems.
[Browser integration][gns-manual], [CA installation][gns-install]

### Following a delegation

Consider an illustrative chain: Alice trusts Bob's zone key; Bob's zone contains
a delegation named `hosting` to a provider key; the provider publishes an
address and service authentication records.

1. Alice's resolver starts with Bob's key, obtained through an already trusted
   contact or exchanged directly.
2. It checks Bob's signed delegation before following the provider key.
3. It checks the provider's records under that key.
4. A compatible connection verifier applies the service authentication policy.

The DHT supplies the records but does not decide which key Alice should trust.
The provider controls its delegated zone; Bob controls whether that delegation
remains in his zone. This division is the useful architectural example.

GNS also blinds keys for individual labels: storage peers need not see the
original zone key in each lookup identifier. This does not make predictable
names secret from someone who already knows the zone key and can guess labels.
The specification also lacks authenticated denial of existence: a missing
answer is not a signed guarantee that the name does not exist.
[Privacy and lookup limits][gns-spec]

**Practical implication:** key ownership, lookup privacy, and reliable discovery
are separate properties. A client can reject forged records while still failing
to find a legitimate record.

### Assessment

**Strengths:** user-controlled roots, explicit key delegation, and a clear
distinction between name verification and browser integration.

**Costs:** personal aliases are not globally interchangeable; browser use
requires additional software or configuration. Its cryptographic record format
cannot simply be treated as a DNSSEC-signed Pkarr packet.

**For Pubky:** study delegation semantics and inseparable address/authentication
records. Pkarr already signs a complete packet, so the useful question is what
must be verified together when resolution crosses several packets.

## 2. Handshake and its browser tools

### What Handshake changes

Handshake establishes top-level name ownership through its blockchain. It
replaces the DNS root's authority, while retaining DNS below that root.
Owners can establish DNSSEC chains and use TLSA records to authorize TLS keys.
This separates certificate authorization from a public CA.
[Handshake FAQ][handshake-faq]

### Let's DANE and Fingertip

Let's DANE is an experimental local proxy supporting DANE-EE, the DANE mode
that directly authorizes a server certificate or key, including self-signed
certificates. It verifies the upstream connection and creates a
certificate that the browser accepts through an installed local CA. Ordinary
non-DANE connections can retain their original certificate. Its libunbound
build validates DNSSEC locally; another mode relies on the resolver's
Authenticated Data flag. These modes have different trust assumptions.
[Let's DANE repository][letsdane]

Fingertip packages Handshake resolution with Let's DANE. Its documented stack
uses hnsd, a Handshake resolver, the DANE proxy, and optional Ethereum
resolution support.
[Fingertip repository][fingertip]

### Shakescape and the Rust browser stack

Shakescape documents a mobile browser with local Handshake header and name
proof verification, DNSSEC validation, and TLSA policy enforcement. It has
Android and Apple platform implementations and published release links.
[Mobile browser repository][shakescape]

The related Chromium extension uses a Rust native host. It tunnels browser TLS
unchanged on its defined WebPKI path; where DANE requires TLS termination, it
uses a local CA. This is more than a JavaScript extension changing DNS.
[Extension repository][hns-extension]

The shared engine documents exact-origin checks and policy-bound connection
admission. It also explicitly separates source integration from installed
product qualification. Current repository code is not evidence that every
documented path has been validated in a released application.
[Engine repository][hns-engine]

### What a local DANE proxy actually verifies

Take a fictional site whose owner authorizes server key A through DNSSEC and
TLSA. A terminating proxy creates two connections:

1. **Browser to local proxy:** the browser accepts a certificate issued by the
   locally installed CA. This is the browser's normal certificate check.
2. **Proxy to website:** the proxy validates the DNSSEC chain, obtains the TLSA
   policy, and checks the website's TLS key against that policy.

The proxy translates the result between two trust systems. Installing a CA
without the upstream check would not provide the same protection. The proxy
can see the page's plaintext between the connections, so its correctness and
local access controls matter. This follows from the Let's DANE architecture.
[Proxy design][letsdane]

A resolver's **Authenticated Data (AD)** flag says that the resolver considers
an answer authenticated. Trusting that flag means trusting the resolver and
the path to it. Fetching DNSSEC records and validating them locally instead
lets the local component make that decision from its own trust anchor.
[DNSSEC validation and AD](https://www.rfc-editor.org/rfc/rfc4035.html)

**Practical implication:** an unchanged browser can use an alternative trust
system with a local helper, but the installation is part of the product. The
native host, CA setup, upgrades, and removal need a clear user experience.

### Assessment

**Strengths:** concrete implementations of the missing browser trust bridge;
reuse of DNSSEC, TLSA, and ordinary HTTPS servers.

**Costs:** blockchain synchronization and name lifecycle; local software and
trust installation, or a dedicated browser. A terminating proxy handles
plaintext and becomes part of the user's trusted computing base.

**For Pubky:** the browser integration is useful even if we do not adopt
Handshake naming. An experimental Pubky integration could replace the name-proof
layer with verification rooted in the owner's key, called K in our delegation
designs. Reusing a DNSSEC validator would still require generating actual DNSSEC
signatures and defining K as the trust anchor.

## 3. Namecoin

### Names, records, and lifecycle

Namecoin registers names such as `.bit` on a blockchain. Records are limited in
size, and updates or renewals require transactions. Its FAQ distinguishes
semi-expiration, when resolution stops, from final expiration, when another
party can register the name. This differs from permanent identity derived
directly from a key. [Namecoin FAQ][namecoin-faq]

### Certificate handling and browser integration

Namecoin's certificate tooling documents several authentication formats,
including compressed, hashed, and certified modes. Their support varies by
tool version; the owner guide marks some transitions as future support.
[TLS owner guide][namecoin-owner]

Client integration includes certificate injection, TLS overrides, and
restrictions on other certificate authorities. Its matrix distinguishes
positive overrides, negative overrides, and strict transport security, with
different mechanisms for Windows, NSS, Firefox, Chromium, and Tor Browser.
These are platform integrations, not universal browser DANE support.
[Compatibility matrix][namecoin-tls]

### Acceptance and rejection are different requirements

Suppose Alice's records authorize certificate A. Making the browser accept A
solves only half the problem. If the browser also accepts certificate B from an
unrelated public CA, an attacker able to obtain B may still impersonate Alice. A
complete policy needs to specify both what is accepted and what is excluded.

Namecoin's platform-specific approaches are useful because they expose this
second requirement. For applications using NSS, Firefox's cryptographic library,
its `ncp11` integration uses
a PKCS#11 module, a standard interface through which applications obtain
cryptographic objects. The project lists Firefox and Tor Browser integrations;
this is installed native software rather than JavaScript running in a page.
[Current integration downloads][namecoin-downloads]

A move to another host and a missed name renewal also have different effects. In
an illustrative move, Alice updates the authorized certificate and address while
retaining ownership. If the registration eventually becomes available to another
person, the same readable name can acquire a different owner. The name therefore
identifies current registry ownership, rather than one unchanging public key.

**Practical implication:** applications should not equate a readable blockchain
name with a permanent person without defining ownership-change behavior.

### Assessment

**Strengths:** directly addresses alternative certificate trust in existing
applications; treats excluding competing authorities as a separate problem.

**Costs:** platform-specific integration, blockchain operations, and a name
renewal obligation. The compatibility matrix must be retested for the exact
browser and OS versions we would support.

**For Pubky:** accepting a K-authorized certificate must not leave an unrelated
WebPKI certificate valid for K. Certificate-store approaches also need to handle
updates, removal, and isolation between public-key domains.

## 4. Tor onion services

### Identity and discovery

An onion service name encodes its identity public key. Tor publishes signed
service descriptors through its distributed directory, and clients verify
them before establishing a rendezvous connection. The connection provides
end-to-end encryption and service authentication without DNS or a public CA.
Services can be reachable without an inbound public port.
[Onion service overview][tor-overview]

### Browser and certificate handling

Tor Browser recognizes onion connections as a distinct security model,
including HTTP over the authenticated overlay. HTTPS may still be useful for
application requirements or a network segment between Tor and the web server.
The Tor guide discusses an onion-key certificate proposal separately from
existing CA-issued HTTPS certificates; it should not be reported as deployed.
[HTTPS guidance][tor-https]

### Stable identity, changing connection information

The stable onion name is not a list of current server addresses. Tor uses
service descriptors to tell clients how to reach the service through its
network. Its v3 format separates short-lived descriptor signing keys from
blinded keys and certifies their relationship. Revision counters help
prevent an older descriptor from replacing a newer one at directory servers.
These certificates belong to Tor's protocol, not WebPKI.
[Descriptor specification][tor-descriptors]

For an illustrative migration, Alice keeps her onion identity material,
configures a new service machine, and republishes the required descriptors.
Readers keep the same address. Losing that identity material is a different
failure: a new identity produces a new onion name.

The service's Tor process authenticates the onion connection. The application
behind it might be on the same machine or connected over another network
segment; protection of that segment must be considered separately. HTTPS can
still be useful there. [HTTPS deployment guidance][tor-https]

**Practical implication:** Tor's example works because naming, authenticated
transport, and browser treatment fit together. Copying the appearance of an
onion-style name without those components would not copy its security model.

### Assessment

**Strengths:** a deployed precedent for names that authenticate their own
services, with location hiding and flexible hosting.

**Costs:** Tor software and overlay transport. Its security treatment does not
automatically apply to HTTP over arbitrary public IP addresses.

**For Pubky:** study how a browser associates authenticated transport with an
origin. Tor demonstrates that CA independence is feasible, but includes the
transport and browser integration necessary to make that claim meaningful.

## 5. Modern Freenet

### What it is

Modern Freenet is a platform for replicated application state. A contract is
WebAssembly code plus fixed parameters; its identifier hashes those inputs.
The contract defines valid state and how replicas merge updates.
[2026 whitepaper][freenet-paper]

Local delegates hold private state on the user's device. Browser interfaces
connect to the local node, which manages application state and communication.
[Component overview][freenet-components]

The project currently has no decentralized DNS equivalent. Its FAQ favors
contract identifiers for identification, personal names for readable aliases,
and separate search for discovery. The proposed Atlas discovery layer is
described as being at the design stage. [Freenet FAQ][freenet-faq]

### Security and browser implications

The whitepaper distinguishes hop-by-hop encrypted peer transport from
application-level integrity enforced by contract validation. It identifies
remaining issues around malicious peers, stale state, and resource abuse.
This is not a DNSSEC/DANE chain authenticating a remote HTTPS server.
[Security and implementation sections][freenet-paper]

### A replicated application, step by step

Imagine a shared noticeboard rather than a conventional website database. A
Freenet contract defines the valid noticeboard state and the rules for combining
updates. Participating nodes keep replicas; the application reads and updates
that state through its local node. WebAssembly is the portable code format used
to run the contract's rules.

This changes where application logic lives. A traditional server can decide
which database updates to accept. Replicas instead need compatible rules for
checking and combining updates. Moving an ordinary server application to this
model would require designing those rules, not merely changing its URL.

### Upgrades and portable identity

Changing contract code changes its identifier. Freenet's upgrade guidance
therefore recommends stable user identity based on an owner key. Applications
track predecessor code hashes, recover and validate old state, and carry it into
the new contract. An author-signed successor pointer can help older clients find
an upgrade.

Private delegates need a separate migration path. The guide requires an export
handler from the first version; it cannot be added afterward to already
installed code holding secrets. Its migration library is described as early,
with node-mediated delegate transport still a stub.
[Upgrade guidance][freenet-upgrades]

For an illustrative noticeboard upgrade, a newer interface finds the previous
contract's board state, validates it, and imports it into the new version.
Private credentials require their own export and import. Neither operation is
implied merely by knowing the old contract's identifier.

**Practical implication:** replication can remove one hosting dependency while
creating application upgrade and data migration obligations. Stable user keys
and reproducible data export remain important even in a distributed runtime.

### Assessment

**Strengths:** application availability can be separated from a particular host;
public and private computation have explicit roles.

**Costs:** applications must adopt contract semantics and local-node access. An
identifier incorporates contract code, so upgrades require explicit migration
and a stable identity layer. It is not a drop-in replacement for ordinary HTTP
server APIs.

**For Pubky:** relevant to a future distributed application layer. It offers
little direct help with TLSA-based delegation or browser acceptance of an
owner-authorized TLS key. Adopting its architecture would be a separate research
decision.

## 6. Hyphanet, the original Freenet

### What it is and how names work

The original Freenet continues as Hyphanet; modern Freenet is a different
architecture. [Project history][hyphanet-history]

Hyphanet distributes stored data through its own network. Content Hash Keys
identify content; Signed Subspace Keys associate data with a publisher key;
Updatable Subspace Keys let clients look for later editions under a stable
publisher reference. Browser access uses a local FProxy address such as
`http://localhost:8888/<key>`.
[Hyphanet documentation][hyphanet-docs]

Its Address Resolution Keys are updatable records used when a node's IP address
changes. These are network implementation details rather than a global
readable-name registry. [Key documentation][hyphanet-docs]

### Publishing a new edition

Consider a publisher releasing an informational site:

1. An immutable content reference identifies particular published bytes.
2. A publisher-key reference establishes which publisher authorized an edition.
3. An updatable reference lets readers search for later editions.
4. The local proxy retrieves the data and presents it to the browser.

These are different promises. “These bytes match their identifier” is not the
same as “this is the publisher's newest edition.” A reader could obtain an older
authentic edition while the publisher is unreachable or newer data is hard to
find. That follows from the publication model, without implying that an attacker
can forge the publisher's signature.

For a fictional community archive, distribution lets readers retrieve a
published edition without the original web server staying online. A live
application with private per-user writes would need additional design; a
published archive is not equivalent to an ordinary homeserver API.

**Practical implication:** Hyphanet is a useful model for distributing editions
of public information. Identity portability, update discovery, and interactive
application behavior must each be evaluated separately.

### Assessment

**Strengths:** established approaches to censorship-resistant storage and stable
references across publication updates.

**Costs:** local software and a different publishing model. Searching for a new
edition is different from proving that no newer edition exists. FProxy access
also changes how the browser sees the site's URL and origin.

**For Pubky:** useful background for replicated publication and mutable
references. It does not provide a browser DANE implementation we can directly
reuse, and it should not be confused with modern Freenet's contract runtime.

## 7. IPFS and IPNS

### Content and mutable names

IPFS addresses content by hash. IPNS adds a mutable name derived from a public
key, with signed records pointing to a content path. Records have sequence
numbers, validity periods, and cache settings. Discovery can use a DHT or
PubSub. Regular publication keeps records available despite node churn.
[IPNS documentation][ipns]

IPNS explicitly distinguishes record validity from freshness: a long-lived
record can remain verifiable after a newer record has been published. Its
documentation discusses the tradeoff between availability and obtaining the
newest version. [IPNS lifecycle][ipns]

### Browser and certificate handling

HTTP gateways expose IPFS/IPNS through conventional URLs. Path gateways put
different sites under the same origin; subdomain gateways isolate them.
DNSLink connects ordinary DNS names to content paths. These browser access
patterns are separate from native IPFS/IPNS addressing.
[Web addressing][ipfs-web]

### Moving storage without changing the name

An illustrative publisher has an IPNS name N pointing to site version X. She
uploads version Y, arranges for two independent storage providers to keep it,
and publishes a newer record under N. Readers keep N; the content pointer
changes from X to Y. Storage providers need the data, not her naming private
key, to serve it.

There are two independent failures. If a reader gets an older valid naming
record, it may load X. If it gets the latest record but nobody stores Y, it
cannot load the site. Naming freshness and storage availability therefore need
separate operational checks.

### What a browser gateway guarantees

An ordinary gateway can render a page for an unchanged browser. Its HTTPS
certificate authenticates the gateway. A trustless gateway instead supplies
raw blocks or a CAR, an archive of content-addressed blocks, for a compatible
client to verify before using them. IPFS documents browser libraries that
perform this checking; ordinary browser navigation is not automatically the
same verification path.
[Verified retrieval guide][ipfs-verified]

For fictional publishers Alice and Bob, a path gateway serves both under
`gateway.example`. A subdomain gateway gives their sites different hostnames.
This separates origins, but does not by itself remove the gateway from the
content trust path. Origin isolation and content verification solve different
problems.

**Practical implication:** gateway designs should say who verifies the content,
which origin runs it, and which providers keep it available.

### Assessment

**Strengths:** portable references, multiple storage providers, and explicit
handling of freshness and browser origins.

**Costs:** content must remain available somewhere; valid naming records do not
guarantee storage. A gateway's HTTPS certificate authenticates the gateway, so
verification beyond that requires a separately defined path.

**For Pubky:** useful for hosting and gateway design. IPNS is analogous to
signed mutable discovery in some respects; it does not supply the missing
browser TLS verifier for Pkarr authorization.

## 8. Holepunch, Hypercore, and Pear

### Building blocks

HyperDHT discovers peers and connects to a remote public key. Its connections
use Noise, a framework for authenticated encrypted streams, and support hole
punching. It also provides mutable
and immutable DHT records. [HyperDHT reference][hyperdht]

Hypercore provides authenticated replicated logs, with sparse reads and
optional encryption. Modern core identifiers can identify an authentication
manifest, which describes authorized signers, rather than simply one raw key.
[Hypercore reference][hypercore]

Pear is an installed runtime and deployment platform built on these P2P
components. Applications can be distributed and updated through peers.
Availability still requires a live source with the relevant data; a stable
link alone is insufficient. [Pear overview][pear],
[Availability guide][pear-availability]

### Connection identity versus data authority

Imagine Alice connecting to a peer to read a replicated log. HyperDHT helps find
that peer and establish a key-authenticated encrypted connection. Hypercore
checks the replicated log under its own authentication rules. The machine
delivering the log need not be the writer authorized to extend it. That
separation is why multiple replicas can distribute one author's data.

Hole punching means coordinating peers so that some routers allowing outgoing
traffic also permit a direct connection between them. It is a connectivity
technique, not proof of ownership and not a guarantee of reachability on every
network. Applications still need a strategy for inaccessible peers.

### Keeping an offline user's data reachable

Pear documents blind peers that store and serve replicated cores without
reading encrypted contents. They provide an always-on source while clients
are offline. Applications must still configure encryption and access checks;
blind peering is not a substitute for those rules.
[Blind peering guide][pear-blind]

For a fictional chat application, Alice and Bob can write through their own
clients while a third machine keeps encrypted replicas available. If that
machine disappears, replacement replicas can help, provided somebody still has
the data. Keeping the same public identifiers does not reconstruct lost copies.

**Practical implication:** hosting, writing authority, and reading permission
can be separated. The application must define all three explicitly.

### Assessment

**Strengths:** practical primitives for direct connectivity, replication, and
distribution independent of a single download server.

**Costs:** the runtime and storage model differ from a browser fetching an
ordinary HTTPS origin. Connection keys and replicated-data authority are
separate concepts that applications must handle correctly.

**For Pubky:** potentially useful for provider replication or connectivity
behind NAT. Adopting these transports would require an SDK/host adapter; they do
not make `fetch()` enforce a Pkarr TLSA pin.

## 9. I2P

### Names and resolution

I2P routes to cryptographic destinations. Human-readable names come from a
local address book, which can import entries from selected sources. Different
users can map the same readable name to different destinations. Base32 names
offer an alternative tied to a cryptographic destination.
[Naming and address books][i2p-names]

Its naming document uses the word certificate within destination structures.
That should not be read as a browser-trusted X.509 certificate. Naming and
ordinary HTTPS certificate validation are separate layers.
[Destination format][i2p-names]

### How a destination remains reachable

I2P separates the destination from its temporary routes. Its distributed
network database stores LeaseSets: signed information describing tunnel entry
points and their expiry. The client can locate current routes without treating
one permanent IP address as the destination's identity.
[Network database][i2p-netdb]

For an illustrative visit, Alice first resolves her local alias `bob.i2p` to
Bob's destination. Her I2P software then finds route information and connects
through the overlay. The alias lookup and the authenticated destination are two
distinct decisions.

If Alice imports an address book from a publisher, that publisher can influence
which destination she associates with a readable alias. Exchanging and checking
Bob's cryptographic identifier through another trusted channel avoids relying
solely on that naming source. It does not remove the need to discover working
routes.

**Practical implication:** personal readable names can improve usability while
leaving permanent identity with a key. The interface should show when a trusted
alias changes its cryptographic destination rather than hiding the change.

### Assessment

**Strengths:** separates permanent identifiers from personal names and makes the
source of readable-name trust visible.

**Costs:** address-book distribution can introduce trusted publishers; aliases
are not universally meaningful. Browser use needs I2P access software, and the
naming mechanism itself does not define alternative HTTPS trust.

**For Pubky:** useful if readable names are added above K. An alias can help
users find an identity without becoming the authority that controls it.

## 10. Ethereum Name Service

### Naming and website references

ENS uses Ethereum contracts for names and resolution. It also supports
traditional DNS names using DNSSEC proof paths; those imported names retain
their conventional DNS authority. This is different from native `.eth`
ownership. [Protocol overview][ens-protocol], [DNS integration][ens-dns]

The `contenthash` record identifies resources on systems such as IPFS or
Swarm. ENS documents browser/extension integration and HTTP gateways for
access from browsers without native support.
[Contenthash specification][ens-contenthash], [Website guide][ens-web]

### A name is a pointer, not a hosting service

In a fictional deployment, `alice.eth` has a `contenthash` record pointing to an
IPFS site. A compatible client reads ENS state, obtains that pointer, and
retrieves the content. ENS establishes the record; IPFS or a gateway delivers
the website. Availability of one does not imply availability of the other.

If a remote RPC service supplies blockchain state, the client must specify
whether it trusts that service or verifies the relevant state itself. The
existence of a public blockchain does not make every application's connection to
it independently verified.

### Renewal and changing ownership

The documented ENSv1 `.eth` registrar uses paid registration periods and a
90-day renewal grace period. After that, another person can register the name,
subject to the temporary premium mechanism. ENSv2 documentation describes
different lifecycle rules and warns that its contracts are not yet final.
These versions should not be presented as one interchangeable deployed system.
[ENSv1 registrar][ens-registrar], [ENSv2 development][ens-v2]

For Alice, changing the IPFS pointer while retaining registration preserves the
readable name. Losing registration can transfer that name to someone else. A
contact list using ENS therefore needs a policy for name ownership changes.

**Practical implication:** optional readable names can point to permanent keys,
but applications should preserve the distinction between an alias and identity.

### Assessment

**Strengths:** a clear separation between readable names and resource locations;
interoperable records for several storage systems.

**Costs:** blockchain name authority and its lifecycle, client/RPC access, and
gateway dependencies for ordinary browser use. A readable ENS name does not by
itself authorize a TLS certificate in the browser.

**For Pubky:** useful for optional readable-name discovery and content pointers.
DNSSEC imports should not be mistaken for registrar-independent identity, and
ordinary gateway access should not be mistaken for direct authentication under
K.

## 11. Yggdrasil

### What it provides

Yggdrasil is an encrypted IPv6 overlay network. Node addresses derive from
cryptographic identities and remain independent of the underlying network
location. Existing IPv6 applications can use those addresses once the overlay is
installed. The project describes its routing implementation as experimental.
[Architecture overview][ygg-about]

Traffic is encrypted end to end; the project explains the relationship
between the key pair and network identity in its privacy documentation.
[Identity and encryption][ygg-privacy]

### What moves with the address

Imagine a small server switching from a home connection to a mobile network. Its
conventional IP address may change. With Yggdrasil installed and reachable
through mesh peers, it can retain its key-derived overlay address. This gives
applications a stable network destination across underlying locations.

That address identifies a node key. If Alice shares a host with several other
users, the host's node key is not automatically each user's identity. A service
still needs rules connecting user authority to the node or application key.

Yggdrasil also explicitly distinguishes encryption from anonymity: its privacy
documentation does not describe it as an anonymity network. Encrypted traffic
can still expose network relationships or other metadata.
[Privacy limits][ygg-privacy]

**Practical implication:** an encrypted mesh is useful transport infrastructure.
It does not allocate readable names, establish user delegation, or replace the
browser's HTTPS and origin rules.

### Assessment

**Strengths:** portable network addresses and authenticated transport below
application protocols.

**Costs:** installation and overlay connectivity. A node identity is not
automatically a user identity or delegated service identity. Encryption at the
IP layer also does not make an HTTP URL satisfy browser HTTPS policies.

**For Pubky:** a possible alternative transport underneath a service. It does
not replace our need to specify which provider key K authorizes, nor does it
solve browser certificate verification through DNS resolution alone.

## 12. Spaces Protocol

### Names, proofs, and records

Spaces anchors ownership in Bitcoin state. Clients obtain certificates and
proofs through Certrelay HTTP servers, then verify them locally. Signed
off-chain records include a sequence number and metadata such as website
addresses; record signatures use the BIP340 Schnorr signature standard.
[Resolution documentation][spaces-resolution]

Clients need an appropriate Bitcoin-derived trust anchor. The project
documents obtaining a trust ID through a local Bitcoin-backed process and
using it in clients. This bootstrapping work establishes readable-name
ownership; it is not needed when the root key is already part of the name.
[Trust anchor documentation][spaces-trust]

The former Fabric DHT repository is archived in favor of Certrelay. Current
resolution should not be described using that old architecture.
[Archived repository][spaces-old-dht]

### Browser and certificate implications

The documented flow verifies name ownership and discovery records. Its
certificates are ownership proofs, not TLS certificates. The examined resolution
documentation does not establish a DNSSEC/DANE path for browser HTTPS
authentication. [Resolution flow][spaces-resolution]

### Why a proof-delivery server need not own the name

Consider an illustrative name lookup through a Certrelay server. The server
returns the ownership evidence and signed records. A compatible client checks
them against its Bitcoin-derived trust anchor before accepting the website
address. The relay supplies evidence; it is not allowed to invent ownership.

Three failures remain distinct: the relay can be unreachable; it can supply
invalid evidence that verification rejects; or the client can have an
inappropriate trust anchor. Local signature checking addresses the second case,
not automatically the first or third.

After a verified record points to `https://alice.example`, the browser still
checks that site's ordinary HTTPS certificate. The readable Spaces name has
helped locate the site; the examined protocol does not make the browser accept a
TLS key solely because a Spaces record authorized it.

**Practical implication:** portable proofs reduce the authority required of
lookup servers. Readable-name ownership, reliable proof delivery, and website
connection authentication remain separate responsibilities.

### Assessment

**Strengths:** portable proofs for readable names; delivery servers do not need
to be trusted for authenticity.

**Costs:** Bitcoin-state trust bootstrapping and reliance on reachable relays
for discovery. Verified website metadata is not verified browser TLS under the
name's owner key.

**For Pubky:** the browser SDK already retrieves Pkarr packets through relays
and verifies signatures. That pattern is existing functionality, not a new
lesson from Spaces. Readable-name ownership is the main additional problem
Spaces addresses.

## 13. fips-pub-domains

### DNS-to-mesh binding

This project associates an existing domain with a fips mesh key. The owner
publishes `_fips-dns.example.org TXT` naming that key. Signed Nostr claims
advertise the service; the resolver verifies a binding and pins it for offline
use. DNSSEC provides stronger evidence than the project's unsigned DNS and
explicitly trusted witness paths. [Project README][fips-readme]

Claims can carry the TXT RRset and its DNSSEC chain, including DNSKEY, DS,
and RRSIG records: the keys, delegation links, and signatures needed to check
the chain. A client can validate that package offline against the DNS
root key. Signature expiry limits proof lifetime; the server republishes
fresh proofs. Existing offline pins are a different persistence mechanism.
[Specification][fips-spec]

### Browser and certificate handling

Installed resolver and mesh software expose a mesh IPv6 destination to an
unchanged browser. The mesh authenticates and encrypts traffic. HTTPS remains
necessary for browser policies such as HSTS, which requires HTTPS, and secure
contexts, which gate sensitive browser APIs; the specification
suggests serving the ordinary domain certificate over the mesh as well.
It does not define DANE as the browser certificate solution.
[Security section][fips-spec]

### Offline proof checking versus offline pinning

Suppose a fictional domain owner publishes a DNSSEC-signed TXT binding to mesh
key A. A client receives a bundle containing that record and the signatures and
keys connecting it to the DNS trust anchor. The client can check the bundle
without making fresh DNS queries, while the signatures remain valid.
This illustrates the general proof-transport idea also documented in the
experimental [TLS DNSSEC chain extension][dnssec-chain].

If the signatures later expire, the same bundle no longer supplies time-valid
DNSSEC evidence. A client might still use a previously pinned key A under its
local policy, but that means “keep using the remembered binding.” It does not
mean “the current DNS owner still authorizes A.”

Now suppose the owner changes the online binding to B while the client remains
offline. The client cannot learn that change from its old pin alone. Renewing
proofs and updating pins therefore have different purposes: renewal keeps proofs
usable; refresh discovers changes in authorization.

**Practical implication:** packaging signed records for offline checking is
useful. Continued use after proof expiry needs an explicit local trust policy,
especially if domain ownership or service keys can change.

### Assessment

**Strengths:** concrete packaging of DNSSEC evidence outside live DNS; explicit
separation between fresh proofs and offline pins.

**Costs:** conventional DNS establishes domain authority. Continued offline use
of a pin does not prove that it still matches the current online binding.
Unsigned DNS or witness alternatives add different trust assumptions.

**For Pubky:** proof transport and renewal are worth examining. Conventional DNS
bootstrap should not become the root of authority for K. We also should not copy
indefinite offline pins as a substitute for checking current Pkarr
authorization.

## Comparing practical outcomes

The following comparisons are our analysis of the documented designs. They are
not benchmark results or claims that one project is best for every use.

### Readable names and permanent identity

A globally agreed readable name requires a rule for who gets that spelling.
Handshake, Namecoin, ENS, and Spaces make registry ownership part of that rule.
They can make a name transferable without keeping one public key forever.

A key-derived name avoids competition over spelling, but is difficult to read
and share. Tor onion names and public-key namespaces illustrate this approach.
GNS and I2P also show a third choice: personal aliases. Two people can use
different readable names for the same identity, or the same spelling for
different identities.

For a fictional contact list, Alice might save Bob's permanent key and display
an optional readable name. A registry or address-book update could then change
the displayed name without silently replacing the saved key. If the product
instead follows the name's current owner, it should make that policy explicit.

Neither model supplies automatic key recovery. A key-based identity needs backup
or an explicitly designed recovery mechanism. A blockchain name may allow
changing a resolver or service key while the ownership credential is available;
losing that credential is a separate issue.

### What happens when a provider disappears?

Consider four different events:

- **A lookup relay disappears.** Another relay or direct network lookup can
  help if the protocol and client support it. Signature checking means a
  replacement need not become a new authority.
- **A host disappears.** A new host helps only if the user has the data and can
  update the service binding. Stable identity does not create a backup.
- **A data replica disappears.** Other replicas can serve the data while they
  retain it. If every copy disappears, the identifier cannot recover the bytes.
- **A default bootstrap service disappears.** New clients need some other way
  to enter the network. A decentralized lookup algorithm can still have a
  centralized default configuration.

This suggests a useful exit test: can Alice obtain her complete data, prepare a
replacement provider, update discovery, and have existing readers find it
without approval from the previous provider? A system that merely changes the
URL but strands data or contacts does not pass that test.

### Authenticity, freshness, and availability

Suppose a signed record authorizes host A. Later, its owner authorizes host B. A
client seeing only the old record can verify its signature but may not know that
B exists. Comparing versions helps when both records are available; it cannot
manufacture an unseen update.

Different projects address this with combinations of version counters, expiry,
republication, and lookup policy. These mechanisms have different jobs. Expiry
limits how long evidence is accepted. Republication keeps records reachable.
Version ordering chooses between observed updates.

For Pubky, newer Mainline DHT publication is the practical authorization-update
mechanism already in use. The remaining integration question is how quickly a
browser helper or connection cache adopts that update. This is an operational
requirement, not a reason to invent a separate revocation system.

### An ordinary TLSA key rotation

As a standards-based example, assume a service uses DANE-EE and a TLSA record
pinning its server public key:

1. Publish both the old and new key fingerprints.
2. Wait for old cached policy to age out and confirm the new policy is served.
3. Switch the server to the new key.
4. Remove the old fingerprint when it is no longer needed.

The client accepts a server matching a supported authorized record; the server
normally presents one key for a connection. It does not need to present both.
SNI selects a hostname or service, not a requested key version.

A public-key pin can survive certificate renewal with the same key. Under
DANE-EE, certificate expiry does not govern authentication; DNSSEC signature
validity governs the binding. Other DANE modes have different certificate
validation requirements. These are DANE rules, not automatic guarantees for an
existing Pubky browser path. [DANE operations][dane-operations]

### Privacy and censorship resistance

Encryption protects traffic contents from parties outside its encryption
boundary. It does not necessarily hide the destination, peer relationships,
lookup interest, or the fact that a user participates in a network.

Tor and I2P include routing designed for privacy. Yggdrasil provides encrypted
networking without claiming anonymity. GNS addresses aspects of lookup privacy.
These are different goals and should be evaluated against a named observer: a
local Internet provider, a discovery service, a hosting provider, or a peer.

Censorship resistance also depends on how many routes remain usable. For an
illustrative P2P application, independent replicas are useful, but requiring one
blocked gateway for every browser visit can still prevent access. Verifying a
gateway's response does not make that gateway reachable.

### Costs and evidence to collect next

Decentralization moves work rather than eliminating it. The documented designs
introduce different combinations of registration or transaction costs, local
software, network synchronization, replication storage, and background
publication. No comparable measurements were collected in this survey.

A practical trial should measure first-time setup, time to first usable page,
behavior after a host move, and ongoing bandwidth and storage. Tests should also
cover an offline publisher, an unreachable default relay, expired proofs, and a
server key that does not match the owner's authorization.

For browser integrations, “page loaded” is insufficient evidence. A trial should
verify that the wrong server key is rejected and that redirects, subresources,
origin isolation, and reused connections obey the same policy. A project README
describing these checks is useful design evidence; a released build passing them
is stronger deployment evidence.

## Implications for Pubky

### Browser compatibility has several meanings

Here, **K** means the user's public identity key. **Pkarr** publishes signed
packets under that key through the Mainline DHT. A **homeserver** hosts the
user's data. The current browser SDK can fetch packets through relays and
verify their signatures.

The examined projects use four main integration patterns:

| Pattern | What users need | Where service authentication happens | Relevant examples |
| --- | --- | --- | --- |
| Dedicated browser integration | A compatible browser and network stack | Browser/native networking | Tor Browser, Shakescape |
| Local certificate bridge | Proxy or platform helper plus local trust setup | Local verifier; browser trusts its result | Let's DANE, GNS, Namecoin |
| Gateway or local application interface | Gateway access or an installed node | Depends on the protocol and gateway | IPFS, ENS, Freenet, Hyphanet |
| Encrypted network overlay | Installed overlay and routing | Network layer; HTTPS policy remains separate | I2P, Yggdrasil, fips |

These patterns solve different problems. For our purposes, a browser must either
enforce K's authorization itself or rely on a user-controlled component that
does so. A remote gateway that terminates traffic introduces a separate trust
boundary.

### DNS compatibility does not determine the trust root

For the remaining discussion, **K** means the user's public identity key.
**Pkarr** publishes signed discovery packets under that key through the Mainline
DHT. A **homeserver** hosts the user's data. The current browser SDK can fetch
these packets through relays and verify their signatures.

GNS shows that DNS-like records can be authenticated by an independent protocol.
Handshake shows that standard DNSSEC records can use an alternative root.
fips-pub-domains shows that DNSSEC proofs can travel through another discovery
network.

Our inference: Pkarr transport and DNSSEC representation can be separate
choices. If we want DNSSEC/DANE interoperability, publishing must create valid
DNSKEY and RRSIG data, and verification must explicitly root authority in K.
Changing packet syntax alone does not turn a Pkarr signature into an RRSIG.
DNSSEC keys and signatures also consume space; their encoding needs to fit the
[Pkarr packet limit](./pkarr-packet-size.md).

For `_pubky.K`, the resolver also needs the exact service lookup and TLS
authorization rules. None of these projects defines those Pubky-specific
rules for us. The TLSA-based design called option C still needs its port,
transport, SNI, and alias behavior specified independently. SNI is the hostname
a TLS
client sends so a server can select a service or certificate; it is not proof
that the selected key is authorized. See the
[delegation discussion](./delegation-discussion.md).

### Identity, authorization, and availability have separate lifetimes

A name or key can remain stable while endpoint records, proofs, certificates, or
stored data change. DNSSEC proof expiry, IPNS record validity, blockchain name
renewal, and application seeding are different obligations.

For Pubky, publishing a newer signed Mainline DHT version remains the practical
mechanism for changing or removing delegated authorization. This report treats
that as mostly solved in practice. New integration work must still refresh
policy and apply it to cached or reused connections; it should not introduce an
additional revocation registry without a concrete need.

### Closest follow-up work

The following are proposed investigations, not tested implementation plans:

1. **GNS:** compare its delegation and bundled-record rules with chains across
   Pkarr packets. Identify what prevents partial results from weakening policy.
2. **Let's DANE and the Handshake browser stack:** inspect upstream
   verification, local certificate generation, SNI, redirects, subresources,
   and connection reuse. Establish which paths work in released software.
3. **Namecoin:** examine certificate acceptance and rejection together. Check
   current platform APIs before assuming its compatibility matrix applies.
4. **Tor Browser:** examine origin/security integration for a key-based name,
   particularly where existing web APIs still require HTTPS behavior.
5. **fips-pub-domains:** compare proof packaging and signature renewal with the
   cost of DNSSEC records inside Pkarr's packet limit.

Freenet, Hyphanet, IPFS, and Holepunch merit a separate hosting/replication
study if that becomes part of the scope. Their broader application models should
not be introduced solely to solve certificate verification.

[gns-manual]: https://docs.gnunet.org/latest/users/gns.html
[gns-spec]: https://lsd.gnunet.org/lsd0001/
[gns-install]: https://docs.gnunet.org/latest/installing.html
[handshake-faq]: https://handshake.org/faq/
[letsdane]: https://github.com/buffrr/letsdane
[fingertip]: https://github.com/imperviousinc/fingertip
[shakescape]: https://github.com/handshake-rs/hns-dane-browser-mobile
[hns-extension]: https://github.com/handshake-rs/hns-dane-browser-extension
[hns-engine]: https://github.com/handshake-rs/hns-dane-engine
[namecoin-faq]: https://www.namecoin.org/docs/faq/
[namecoin-owner]: https://www.namecoin.org/docs/name-owners/tls/
[namecoin-tls]: https://www.namecoin.org/docs/tls-client/
[tor-overview]: https://community.torproject.org/onion-services/overview/
[tor-https]: https://community.torproject.org/onion-services/advanced/https/
[freenet-paper]: https://freenet.org/pdf/freenet-whitepaper.pdf
[freenet-faq]: https://freenet.org/faq/
[freenet-components]: https://freenet.org/build/manual/components/overview/
[hyphanet-history]: https://www.hyphanet.org/author/steve-dougherty.html
[hyphanet-docs]: https://www.hyphanet.org/pages/documentation.html
[ipns]: https://docs.ipfs.tech/concepts/ipns/
[ipfs-web]: https://docs.ipfs.tech/how-to/address-ipfs-on-web/
[hyperdht]: https://docs.pears.com/p2p/reference/building-blocks/hyperdht/
[hypercore]: https://docs.pears.com/p2p/reference/building-blocks/hypercore/
[pear]: https://docs.pears.com/
[pear-availability]:
  https://docs.pears.com/pear/explanation/availability-and-blind-peering/
[i2p-names]: https://www.i2p.net/en/docs/overview/naming/
[ens-protocol]: https://docs.ens.domains/learn/protocol/
[ens-dns]: https://docs.ens.domains/learn/dns/
[ens-contenthash]: https://docs.ens.domains/ensip/7/
[ens-web]: https://docs.ens.domains/dweb/intro/
[ygg-about]: https://yggdrasil-network.github.io/about.html
[ygg-privacy]: https://yggdrasil-network.github.io/privacy.html
[spaces-resolution]: https://spacesprotocol.org/docs/learn/resolution/
[spaces-trust]: https://spacesprotocol.org/docs/use/trust-anchor/
[spaces-old-dht]: https://github.com/spacesprotocol/fabric-dht
[fips-readme]: https://github.com/fr34aky/fips-pub-domains/blob/main/README.md
[fips-spec]: https://github.com/fr34aky/fips-pub-domains/blob/main/docs/spec.md

[web-origin]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
[namecoin-downloads]: https://www.namecoin.org/download/betas/
[tor-descriptors]: https://spec.torproject.org/rend-spec/hsdesc-outer.html
[freenet-upgrades]: https://freenet.org/build/manual/upgrading-contracts/
[ipfs-verified]:
  https://docs.ipfs.tech/how-to/replace-public-gateways-with-self-hosted-ipfs/
[pear-blind]: https://docs.pears.com/p2p/explanation/blind-peering/
[i2p-netdb]: https://www.i2p.net/en/docs/overview/network-database/
[ens-registrar]: https://docs.ens.domains/registry/eth/
[ens-v2]: https://docs.ens.domains/ensv2/eth-registrar/

[dane-operations]: https://www.rfc-editor.org/rfc/rfc7671.html

[dnssec-chain]: https://www.rfc-editor.org/rfc/rfc9102.html
