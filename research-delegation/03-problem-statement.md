# Problem statement

Users and service operators need to make everyday changes without exposing
long-lived keys or giving serving machines more authority than they need.
This research asks how to delegate that work while **keeping users in control**.

## Alice keeps her identity key cold

Alice wants to keep her **identity key offline in cold storage**. She uses a
**replaceable operational key** to update her service records, such as choosing
where her website or homeserver is hosted.

Her public identity and links stay the same. If her operational key is lost
or stolen, she can use her cold identity key to replace it. She can also change
providers without the old provider's permission, keeping her identity,
content, and connections. That requires available copies of her data.

## The operator changes the deployment

Alice's service operator wants to move between servers, change hosting setups,
and **rotate TLS keys without asking Alice** to update her records each time.

TLS keys live on serving machines and may remain in old backups or leaked
copies: this is the “toxic waste” problem. The operator wants each key to have
**limited power and a limited lifetime**. For example, a TLS key should
authenticate one service for a defined period, without permission to change
routing or issue more keys. Keeping an old private key should not preserve its
authority
indefinitely.

## What the research needs to resolve

How can Alice authorize her operational key and service operator, and how can
clients verify that a server is **still authorized**? The design needs to make
updates, key rotation, expiry, and withdrawal of permission work in practice.

The goal is **secure access to Pubky domains in ordinary browsers**, using
familiar web infrastructure where possible. Identity remains rooted in
user-controlled keys and signatures, with discovery through the DHT. The
approaches in this folder are proposals; browser support still needs to be
established.
