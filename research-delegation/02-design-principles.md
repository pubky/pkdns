# Design principles

The [first principles](./01-first-principles.md) take precedence.

Our goal is to let users enter a Pubky domain in an unmodified mainstream
browser and securely load it as an ordinary website. This is a goal, not
current support.

- **Reuse standards.** Preserve established protocol behavior where possible.
  Use extension mechanisms and document departures.
- **Work with the web.** Preserve familiar URLs, navigation, HTTP, TLS, and
  browser security boundaries. Support existing content, servers, and tools
  within the first principles.
- **Keep changes small.** State what browsers, resolvers, servers, and
  deployment infrastructure must change. Prefer changes that are practical
  to adopt.
