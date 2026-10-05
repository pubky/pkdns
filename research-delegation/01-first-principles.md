# First principles

We build a self-sovereign web where users control their identity, content, and
choice of provider.

1. **Trust public keys and signatures.** Identity comes from a key pair the
   user controls. Signed Pkarr records authorize routing under that identity.
   Ownership must not depend on a domain registrar's permission.

2. **Resist censorship through decentralized discovery.** The Mainline
   distributed hash table (DHT) carries signed discovery records; homeservers
   host content. Stable public-key identity and flexible hosting let users
   route around a censoring provider.

3. **Make exit credible.** Users must be able to change apps or hosts while
   keeping their identity, content, and connections. They need available data
   and a way to publish new routing under the same key. Exit must be practical
   and affordable.

4. **Keep content portable.** Users own their content. Compatible apps and
   hosts should reuse open data formats, and users must be able to keep
   independent copies.
