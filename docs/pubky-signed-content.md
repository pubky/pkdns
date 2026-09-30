# Signed content for a Pubky website

In [the delegation example](./pubky-service-delegation.md), S serves K's
website and T handles TLS. K can authorize another public key, C, to sign the
files, so S cannot replace them.

Here is an illustrative response for `https://K/index.html`. The signature
bytes are a dummy value. The backslash wraps one header for display and is
not sent on the wire.

```http
GET /index.html HTTP/1.1
Host: K

HTTP/1.1 200 OK
Content-Type: text/html
Content-Digest: sha-256=:sefumAhon8macEaJOwzdqJ601oxMHYIOMCsjtIpKPHU=:
Signature-Input: c=("@status" "content-type" "content-digest" \
  "@method";req "@authority";req "@path";req);expires=1790812800;keyid="C"
Signature: c=:AA==:

<h1>Hello from K</h1>
```

C signs the requested method, host, and path, plus the response status,
content type, and body digest. The client verifies the signature, then
recomputes `Content-Digest` from the received body and compares it with the
signed header. Both checks must pass. Serving this response at `/about.html`
or changing its body bytes fails verification.

`Signature-Input`, `Signature`, and `keyid` are from
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html). Here, `C` stands for
C's public key; the chosen fields and K's permission for C are Pubky design
choices.

## Finding C's permission

The client sees C's key ID and checks its cache. If needed, it fetches:

```text
GET https://K/.well-known/pubky/content-signers/C
```

S can serve a proof signed by K:

```text
K authorizes public key C to sign https://K/* until 2027-01-01.
Signature by K: ...
```

The client verifies K's proof, then C's response. It caches the proof no
longer than its **signed expiry**. S can replay an old proof until then;
faster revocation could use a current proof hash in K's PKARR packet.

The `/*` grant lets C sign files at new paths. To approve each placement
personally, K could sign a path-to-digest list instead. Other options are to
bundle the proof with each response, serve one signed signer list, or let a
separate key manage short-lived permissions while K stays offline.

## Requiring signatures

S could omit both the content signature and K's proof. K could require signed
responses for selected paths in its own PKARR packet:

```dns
; Signed by K
K. TXT (
  "v=pubky-content1; require=signature; exact=/index.html; prefix=/pages/"
)
```

A client requires a signature for `/index.html` and everything under
`/pages/`, including redirects from those paths. Signed redirects must cover
`Location`. If a query changes the content, the signature must also cover
`"@query";req`. K should list `/` too if it serves the site's entry page.

> [!NOTE]
> For these paths, S can still withhold content or return an unsigned `404`.
> The client treats that as unavailability, not proof that K removed the file.
> S can also replay a still-valid signed response until its expiry.

The TXT record is a proposal, not an existing standard. An older signed
packet without the policy could hide it, so clients need rollback protection,
such as remembering K's requirement once seen.

[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) defines
`Content-Digest`. The `/.well-known/pubky/` path is a proposal; a standard
name would need [registration](https://www.rfc-editor.org/rfc/rfc8615.html).

## Subresource Integrity

A signed `index.html` can use
[Subresource Integrity (SRI)](https://www.w3.org/TR/sri/) for external CSS
and JavaScript. S cannot replace an asset without breaking SRI, or change
its expected hash without breaking the page's signature.

For example, a signed page could include this script tag (illustrative hash):

```html
<script src="https://example.com/example-framework.js"
  integrity=
  "sha384-Li9vy3DqF8tnTXuiaAJuML3ky+er10rcgNR/VqsVpcw+ThHmYcwiB1pbOxEbzJr7"
  crossorigin="anonymous"></script>
```
