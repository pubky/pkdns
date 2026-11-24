# Delegation research

How can Pubky users keep identity keys offline while delegating hosting and TLS
management, rotating server keys, and retaining control of their identity?

These documents explore proposals and tradeoffs; client and browser support
still needs assessment. First principles take precedence over compatibility.

Read in this order:

1. [First principles](./01-first-principles.md): what must be preserved.
2. [Design principles](./02-design-principles.md): compatibility and adoption.
3. [Problem statement](./03-problem-statement.md): user and operator needs.
4. [Terminology](./04-terminology.md): key concepts.
5. [Routing and TLS delegation](./05-routing-and-tls-delegation.md): the main
   proposal, separating endpoint selection from authentication authority.
6. [Pkarr packet size](./06-pkarr-packet-size.md): record costs and limits.
7. [Sovereign web projects](./07-sovereign-web-projects.md): approaches and
   lessons from other projects.
8. [TLSA pinning alternative](./09-discussion.md): explicit server key or
   certificate pins instead of the main proposal's TLS authority model.
