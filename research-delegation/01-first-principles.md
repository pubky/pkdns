# First principles

We build a self-sovereign web where users control their identity, content, and
choice of provider.

1. **Trust public keys and signatures.** Identity comes from a key pair the
   user controls: a private key signs statements, and its public key lets
   others verify them. Permission to act under that identity must be verifiable
   through signatures. Ownership must not depend on a domain registrar's
   permission.

2. **Resist censorship through decentralized discovery.** A distributed hash
   table (DHT) lets clients find signed records describing where services are
   hosted, without relying on a central directory. Stable public-key identity
   and flexible hosting let users route around a censoring provider.

3. **Make exit credible.** Users must be able to change apps or hosts while
   keeping their identity, content, and connections. They need available data
   and a way to publish new service locations under the same key. Exit must
   be practical and affordable.

4. **Keep content portable.** Users own their content. Compatible apps and
   hosts should reuse open data formats, and users must be able to keep
   independent copies.
