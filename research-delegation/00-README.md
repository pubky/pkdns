# Delegation research

This research asks how a Pubky key owner can delegate hosting and TLS
authorization while keeping control of their identity. The design is a
proposal; browser and client support must be assessed separately.

Read in filename order:

1. [First principles](./01-first-principles.md): what must be preserved.
2. [Design principles](./02-design-principles.md): compatibility goals.
3. [Motivation](./03-motivation.md): needs, requirements, and reported problems.
4. [Terminology](./04-terminology.md): the terms used in this research.
5. [Design discussion](./05-discussion.md): separate routing and explicit TLS
   delegation, with deployment tradeoffs.
6. [Packet size](./06-pkarr-packet-size.md): measured Pkarr capacity.
7. [Other projects](./07-sovereign-web-projects.md): relevant approaches and
   lessons for Pubky.
8. [DANE idea](./08-dane-idea.md): a possible DNSSEC compatibility path.
9. [Implicit TLS](./09-implicit-tls.md): TLS CNAME selects Pubky or CA
   authentication, with an explicit CA endpoint for browser clients.
