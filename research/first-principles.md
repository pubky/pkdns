# First Principles

We build a self-sovereign web where users control their identity, content, and
choice of provider.

1. **Trust public keys and signatures.** Identity comes from a key pair the user
   controls. Public-key domains derive their authority from that key, and signed
   Pkarr records prove who authorized their routing information. A domain
   registrar's permission is not the foundation of ownership.

2. **Resist censorship through decentralized discovery.** Pkarr publishes signed
   records to the Mainline distributed hash table (DHT), removing the central
   registrar and authoritative nameserver as control points for public-key
   domains. The DHT carries discovery records; homeservers host content.
   Flexible hosting and stable public-key identity let users route around a
   censoring provider.

3. **Make exit credible.** Users must be able to change apps or hosting
   providers while keeping their identity, content, and connections. A move
   should mean taking available data to a new homeserver and publishing updated
   routing records under the same key. Exit must be practical and affordable for
   users.

4. **Users own their content, and it must be portable.** Apps should work with
   data stored under the user's identity on a homeserver they choose, using open
   formats that compatible apps can reuse. Users should be able to keep
   independent copies and carry their content to another provider.
