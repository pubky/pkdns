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

1. Set `dns_over_http_socket = "127.0.0.1:3000"` under `[general]` in
   `~/.pkdns/config.toml`, or in `config.toml` under the directory passed
   to `--pkdns-dir`. Restart pkdns to start the HTTP listener at
   `http://127.0.0.1:3000/dns-query`.
2. Use a reverse proxy like NGINX to add HTTPS to the DoH socket. See this [tutorial](https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-22-04).
3. In the proxy's HTTPS server block, forward `/dns-query` to pkdns:

```nginx
location = /dns-query {
	proxy_set_header X-Forwarded-For $remote_addr;
	proxy_pass http://127.0.0.1:3000;
}
```
4. In your browser, enter the proxy's full HTTPS URL, including `/dns-query`
   (for example, `https://dns.example.com/dns-query`). The certificate must
   be trusted by the browser and match the hostname in that URL.
5. Test if everything is working with [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).

## Run Alongside a Resolver on Port 53

If a resolver such as `systemd-resolved` already listens on port 53, keep
it running and give pkdns a different UDP port. For local testing, use a
loopback address in your pkdns `config.toml`:

```toml
[general]
socket = "127.0.0.1:5300"
dns_over_http_socket = "127.0.0.1:3000"
```

Replace the keys in your existing `[general]` section. Restart pkdns and
test the UDP listener:

```sh
dig @127.0.0.1 -p 5300 example.com
```

For browser DoH, use the reverse proxy's HTTPS URL from the previous
section. The browser connects to the proxy, which forwards the request
to the HTTP listener on port 3000.
