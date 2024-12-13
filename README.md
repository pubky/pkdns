# pkdns

[![GitHub Release](https://img.shields.io/github/v/release/pubky/pkdns)](https://github.com/pubky/pkdns/releases/latest/)
[![Demo](https://img.shields.io/badge/Demo-7fmjpc-green)](http://pkdns-demo.pubky.app/)
[![Telegram Chat Group](https://img.shields.io/badge/Chat-Telegram-violet)](https://t.me/pubkycore)

A DNS server providing self-sovereign and censorship-resistant domain names. It resolves records hosted on the [Mainline DHT](https://en.wikipedia.org/wiki/Mainline_DHT), the biggest DHT on the planet with ~15M nodes that services torrents since 15 years.


## Getting Started

### Hosted DNS

Use one of the [hosted DNS servers](./servers.txt) to try out pkdns quickly.

- [Verify](#verify-pkdns-is-working) the server is working.
- [Configure](#change-your-system-dns) your system dns.
- [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


### Pre-Built Binaries

1. Download the [latest release](https://github.com/pubky/pkdns/releases/latest/) for your plattform.
2. Extract the tar file. Should be something like `tar -xvf tarfile.tar.gz`.
3. Run `pkdns -f 8.8.8.8`.
4. [Verify](#verify-pkdns-is-working) the server is working. Your dns server ip is `127.0.0.1`.
5. [Configure](#change-your-system-dns) your system dns.
6. [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


### Build It Yourself

Make sure you have the [Rust toolchain](https://rustup.rs/) installed.

1. Clone repository `git clone https://github.com/pubky/pkdns.git`.
2. Switch directory `cd pkdns`.
3. Run `cargo run --package=pkdns -- -f 8.8.8.8`.
4. [Verify](#verify-pkdns-is-working) the server is working. Your server ip is `127.0.0.1`.
6. [Configure](#change-your-system-dns) your system dns.
7. [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


## Guides

### Change your System DNS

Follow one of the guides to change your DNS server on your system:
- [MacOS guide](https://support.apple.com/en-gb/guide/mac-help/mh14127)
- [Ubuntu guide](https://www.ionos.com/digitalguide/server/configuration/change-dns-server-on-ubuntu/)
- [Windows guide](https://www.windowscentral.com/how-change-your-pcs-dns-settings-windows-10)


Verify your server with this domain [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./).

### Verify pkdns is working

#### Pkarr Domains
Verify the server resolves pkarr domains. Replace `PKDNS_SERVER_IP` with your pkdns server IP address.

```bash 
nslookup 7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy PKDNS_SERVER_IP
```

> *Troubleshooting* If this does not work then the pkdns server is likely not running.


#### ICANN Domains

Verify it resolves regular ICANN domains. Replace `PKDNS_SERVER_IP` with your pkdns server IP address.

```bash
nslookup example.com PKDNS_SERVER_IP
```

> *Troubleshooting* If this does not work then you need to change your ICANN fallback server with
> `pkdns -f REGULAR_DNS_SERVER_IP`. Or use the Google DNS server: `pkdns -f 8.8.8.8`.

### Browse the Self-Sovereign Web

Here are some example pkarr domains:


- [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./)
- [http://pkdns.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./](http://pkdns.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy./)


Hint: Always add a `./` to the end of a pkarr domain. Otherwise browsers will search instead of resolve the website.

### Address already in use

Other services might occupy the port 53 already. For example, [Docker Desktop](https://github.com/docker/for-mac/issues/7008) uses the port 53 on MacOS. [systemd-resolved](https://www.linuxuprising.com/2020/07/ubuntu-how-to-free-up-port-53-used-by.html) is using it on Ubuntu. Make sure to free those.

## Options

```
Usage: pkdns [OPTIONS]

Options:
  -f, --forward <forward>
          ICANN fallback DNS server. IP:Port [default: 8.8.8.8:53]
  -s, --socket <socket>
          Socket the server should listen on. IP:Port [default: 0.0.0.0:53]
  -v, --verbose
          Show verbose output.
      --min-ttl <min-ttl>
          Minimum number of seconds a value is cached for before being refreshed. [default: 300]
      --max-ttl <max-ttl>
          Maximum number of seconds before a cached value gets auto-refreshed. [default: 86400]
      --cache-mb <cache-mb>
          Maximum size of the pkarr packet cache in megabytes. [default: 100]
      --query-rate-limit <query-rate-limit>
          Maximum number of queries per second one IP address can make before it is rate limited. 0 is disabled. [default: 0]
      --query-rate-limit-burst <query-rate-limit-burst>
          Short term burst size of the query-rate-limit. 0 is disabled. [default: 0]
      --dht-rate-limit <dht-rate-limit>
          Maximum number of queries per second one IP address can make to the DHT before it is rate limited. 0 is disabled. [default: 5]
      --dht-rate-limit-burst <dht-rate-limit-burst>
          Short term burst size of the dht-rate-limit. 0 is disabled. [default: 25]
  -h, --help
          Print help
  -V, --version
```

For extended logs, see [here](./docs/logging.md).

## Announce Your Own Records

Use the `pkdns-cli` to inspect and announce your pkarr records on the Mainline DHT. Download the [latest release](https://github.com/pubky/pkdns/releases/latest/) for your plattform.

> The cli currently only supports `A`, `AAAA`, `TXT`, `CNAME`, `NS`, and `MX` records.


**Inspect records by public key** List all records published by a public key.

```bash
./pkdns-cli resolve 7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy
```

**Generate seed** Generate a zbase32 seed to publish your own records.

```bash
./pkdns-cli generate > seed.txt
```

**Publish your own records** Create a dns zone file and publish its content. See [example](./cli/sample/) for more details.

```bash
./pkdns-cli publish seed.txt pkarr.zone
```


> ⚠️ pkdns caches DHT packets for at least 5 minutes to improve latency. Run your own instance with `pkdns --max-ttl 0` to disable caching.

## Limitations

### Recursion

pkdns does only partially support recursive lookups. Recursion only works
- For a `CNAME` pointing directly to another record in the same pkarr packet.
- For a `NS` delegating the whole pkarr zone to a name server.

For anything more fancy than simple `A` and `TXT` records, it is recommended to use a [bind9](https://ubuntu.com/server/docs/service-domain-name-service-dns) name server and point your zone to there `@   NS   {BIND9IP}`.
bind9 is a fully fledged name server and should be able to handle recursion and all record types.

### Record Types

Currently, pkdns only supports `A`, `AAAA`, `TXT`, `CNAME`, and `MX` records. For any other types, use bind9.

## Future Developments Ideas

- Regular ICANN DNS <> pkdns bridge. `{publicKey}.example.com`?
- TLS/HTTPS


---

May the power ⚡ be with you. Powered by [pkarr](https://github.com/pubky/pkarr).
