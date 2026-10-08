# Problem statement

Users and service operators need to make everyday changes without exposing
long-lived keys or giving serving machines more authority than they need.

## Alice keeps her identity key cold

Alice wants to keep the key that anchors her identity, her **identity key**,
offline in cold storage. For routine changes, such as choosing where her
website is hosted, she wants to use a separate, replaceable **operational
key**.

Replacing the operational key must leave her public identity and links
unchanged. If it is lost or stolen, she needs to be able to authorize a
replacement with her offline identity key and withdraw the old key's
permission.

## The operator changes the deployment

Alice's service operator wants to move between servers, change hosting setups,
and replace server keys without asking Alice to approve each routine change.
These **TLS keys** let servers prove their identity when establishing secure
connections using Transport Layer Security (TLS).

TLS keys live on serving machines and may remain in old backups or leaked
copies. The operator wants each key to have **limited power and a limited
lifetime**. For example, a TLS key should prove a server is authorized to serve
one service for a defined period, without permission to change where that
service is hosted or authorize other keys. Keeping an old private key should
not preserve its authority indefinitely.

## What the research needs to resolve

How can Alice authorize her operational key and service operator, and how can
clients verify that a server is **still authorized**? The design needs to make
updates, key rotation, expiry, and withdrawal of permission work in practice.
