# Research

Research on Pubky service delegation, TLS authentication, and Pkarr limits.
The designs are proposals, not claims of current browser or client support.

Suggested reading order:

1. [First principles](./first-principles.md): the requirements that take
   precedence over all design choices.
2. [Design principles](./design-principles.md): compatibility and implementation
   goals within those requirements.
3. [Delegation motivation](./delegation-motivation.md): why delegation is needed
   and what users should control.
4. [Delegation discussion](./delegation-discussion.md): current behavior,
   possible designs, compatibility, and key rotation.

Use the terminology guide alongside the discussion if the DNS or TLS terms
are unfamiliar.

Supporting references:

- [Delegation terminology](./delegation-terminology.md): short definitions of
  keys, authority, endpoints, SNI, and related terms.
- [Pkarr packet size](./pkarr-packet-size.md): size limits, signature overhead,
  and measured record capacity.
- [Sovereign web projects](./sovereign-web-projects.md): an accessible survey with
  worked examples, trust models, browser integration, operational tradeoffs,
  and lessons for Pubky.
