# Delegating a Pubky website

Imagine that K owns a website, S runs it, and T terminates TLS. Each name is a
public key, and each block below is signed by that key:

```dns
; Signed by K
K.  HTTPS  0 S.

; Signed by S
S.  HTTPS  0 T.

; Signed by T
T.  HTTPS  1 . port=443
T.  A      203.0.113.10
```

A Pubky client visiting `https://K/` follows K → S → T, connects to
`203.0.113.10:443`, verifies **T's TLS key**, and sends `Host: K`. K still owns
the website. S can change who serves it without holding K's key. The TLS
terminator needs T's private key; a data server behind it does not.

> [!NOTE]
> Today's Pubky SDK looks up `_pubky.K` for K's homeserver. If the homeserver
> is simply the web server at `https://K/`, `K. HTTPS` is enough: HTTPS
> already identifies the service. `_pubky.K` is a separate Pubky convention,
> not a requirement of HTTPS or PKARR.
>
> A distinct protocol such as `pubky-chat://K` could define an SVCB lookup at
> `_pubky-chat.K`. That would need its own protocol mapping.

## Delegation or endpoint?

Under [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html), priority `0`
is AliasMode: recursively follow the target's HTTPS records. Priority `1`
or higher is ServiceMode: stop HTTPS recursion and use the target as an
endpoint. Resolve its A/AAAA addresses, not its HTTPS records. A target of
`.` means the record owner's addresses. An alias can also end at a target
with addresses but no HTTPS record.

This proposal keeps those lookup rules. It changes the TLS identity when
following an alias:

| Record                     | Next lookup   | Proposed TLS identity  |
|----------------------------|---------------|------------------------|
| `S. HTTPS 0 T.`            | T's HTTPS     | Key at end of chain    |
| `S. HTTPS 1 T.`            | T's A/AAAA    | S                      |
| `S. HTTPS 0 host.example.` | ICANN HTTPS   | WebPKI: `host.example` |
| `S. HTTPS 1 host.example.` | ICANN A/AAAA  | S                      |
| `T. HTTPS 1 . port=443`    | T's A/AAAA    | T                      |

For instance, `S. HTTPS 1 T. port=8443` uses T's address on port 8443 but still
expects **S's** TLS key. To let T terminate TLS with its own key, S publishes
`HTTPS 0 T.`

**The TLS identity transfer is a proposed Pubky rule.** Standard HTTPS keeps
K as the certificate identity even through aliases. Our client verifies the
key reached through the alias chain while keeping the HTTP `Host` as K.
Ordinary browsers would not interpret these records the same way.
