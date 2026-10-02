# Design Principles

Our [first principles](./first-principles.md) take precedence over these design
principles. Web compatibility must not compromise them.

Our goal is to let users enter a Pubky domain in an unmodified mainstream
browser and securely load it as an ordinary website. This is a design goal, not
a claim of current support.

- **Reuse existing standards and protocols.** Follow established standards and
  preserve their intended behavior wherever possible. Use their extension
  mechanisms when extra behavior is needed. Document any departures from
  standard behavior.
- **Work with the web.** Preserve familiar URLs, navigation, HTTP, TLS, and
  browser security boundaries. Aim to support existing web content, servers, and
  tools.
- **Keep required changes small.** Where compatibility requires changes to
  browsers, resolvers, servers, or deployment infrastructure, keep them as small
  and easy to adopt as practical. State exactly what must change.
- **Keep authority with the key owner.** Secure retrieval must verify that the
  service is operated or authorized by the Pubky key owner. A domain registrar
  must not control that identity. Preserve censorship resistance and the ability
  to change apps or hosts while keeping identity, content, and connections.
