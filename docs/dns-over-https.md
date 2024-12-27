# DNS over HTTPS (DoH)

> ⚠️ Experimental support only.

## What is DoH?

DNS over HTTPS (DoH) encrypts DNS queries by sending them over HTTPS instead of plain UDP or TCP. This enhances privacy and security by preventing eavesdropping and tampering of DNS traffic.

Popular web browsers like Firefox, Chrome, Brave, and Edge support DoH out of the box. It is a convenient way to enable Public Key Domains (PKD) in your browser without changing your system dns.

## Enable DoH In PKDNS

pkdns supports [RFC8484](https://datatracker.ietf.org/doc/html/rfc8484) with the `--doh {ip:port}` argument.

1. Start pkdns with `pkdns --doh 127.0.0.1:3000`. This makes pkdns listen for HTTP (not HTTPS) requests on http://127.0.0.1/dns-query.
2. Use a reverse proxy like NGINX to add HTTPS to the DoH socket. See this [tutorial](https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-22-04).
3. Forward the nginx requests to pkdns.

```
	location / {
		proxy_pass http://127.0.0.1:3000;
	}
```
4. [Configure your browser](https://support.privadovpn.com/kb/article/848-how-to-enable-doh-on-your-browser/) with your new url. Example: https://example.com/dns-query.
5. Test if everything is working with [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./).


