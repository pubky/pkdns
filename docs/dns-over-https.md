# DNS over HTTPS (DoH)

## What is DoH?

DNS over HTTPS (DoH) encrypts DNS queries by sending them over HTTPS instead of plain UDP or TCP. This enhances privacy and security by preventing eavesdropping and tampering of DNS traffic.

Popular web browsers like Firefox, Chrome, Brave, and Edge support DoH out of the box. It is a convenient way to enable Public Key Domains (PKD) in your browser without changing your system dns.

## Use A Hosted DoH Server In Your Browser

1. Pick a DNS-over-HTTPS URL from our public [servers.txt](../servers.txt) list.
2. Configure your browser. See [this guide](https://support.privadovpn.com/kb/article/848-how-to-enable-doh-on-your-browser/).
3. Test if everything is working with [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).



## Enable DoH In PKDNS

pkdns supports [RFC8484](https://datatracker.ietf.org/doc/html/rfc8484).

1. Start pkdns with `dns_over_http_socket = "127.0.0.1:3000"` in pkdns.toml. This makes pkdns listen for HTTP (not HTTPS) requests on http://127.0.0.1/dns-query.
2. Use a reverse proxy like NGINX to add HTTPS to the DoH socket. See this [tutorial](https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-22-04).
3. Forward the nginx requests to pkdns. Example configuration:

```
location / {
	proxy_set_header X-Forwarded-For $remote_addr;
	proxy_pass http://127.0.0.1:3000;
}
```
4. Configure your browser with your new doh url.
5. Test if everything is working with [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).



