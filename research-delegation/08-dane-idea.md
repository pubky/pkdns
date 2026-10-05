1. **Browsers:** add DANE support for HTTPS certificate verification.
2. **DNSSEC validator:** derive the trust anchor from K, in the resolver or browser.
3. **Resolver:** add Pkarr/DHT resolution alongside ICANN resolution.
4. **Pkarr publisher:** generate DNSKEY, RRSIG, TLSA, and option C’s CNAME records, with signature renewal.
5. **Homeserver:** support a TLS certificate/key matching the TLSA pin.
6. **Browser/resolver integration:** implement option C’s lookup and SNI rules, including `_pubky.K`.
