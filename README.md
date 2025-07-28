# pkdns

[![GitHub Release](https://img.shields.io/github/v/release/pubky/pkdns)](https://github.com/pubky/pkdns/releases/latest/)
[![Demo](https://img.shields.io/badge/Demo-7fmjpc-green)](http://pkdns-demo.pubky.app/)
[![Docker](https://img.shields.io/badge/Image-Docker-red)](https://hub.docker.com/r/synonymsoft/pkdns)
[![Telegram Chat Group](https://img.shields.io/badge/Chat-Telegram-violet)](https://t.me/pubkycore)

A DNS server providing self-sovereign and censorship-resistant domain names. It resolves records hosted on the [Mainline DHT](https://en.wikipedia.org/wiki/Mainline_DHT), the biggest DHT on the planet with ~10M nodes that services torrents since 15 years.


## Getting Started

### Hosted DNS

Use one of the [hosted DNS servers](./servers.txt) to try out pkdns quickly.

- [Verify](#verify-pkdns-is-working) the server is working.
- Configure your [browser](#use-dns-over-https-in-your-browser) or [system dns](#change-your-system-dns).
- [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


### Pre-Built Binaries

1. Download the [latest release](https://github.com/pubky/pkdns/releases/latest/) for your plattform.
2. Extract the tar file. Should be something like `tar -xvf tarfile.tar.gz`.
3. Run `pkdns --verbose`.
4. [Verify](#verify-pkdns-is-working) the server is working. Your dns server ip is `127.0.0.1`.
5. Configure your [browser](#use-dns-over-https-in-your-browser) or [system dns](#change-your-system-dns).
6. [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


### Build It Yourself

Make sure you have the [Rust toolchain](https://rustup.rs/) installed.

1. Clone repository `git clone https://github.com/pubky/pkdns.git`.
2. Switch directory `cd pkdns`.
3. Run `cargo run --package=pkdns`.
4. [Verify](#verify-pkdns-is-working) the server is working. Your server ip is `127.0.0.1`.
6. Configure your [browser](#use-dns-over-https-in-your-browser) or [system dns](#change-your-system-dns).
7. [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


### Use Docker Compose

See [compose.yaml](./compose.yaml).

## Guides

### Use DNS-over-HTTPS in your Browser

1. Pick a DNS-over-HTTPS URL from our public [servers.txt](./servers.txt) list.
2. Configure your browser. See [this guide](https://support.privadovpn.com/kb/article/848-how-to-enable-doh-on-your-browser/).


Verify your server with this domain [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).

### Change your System DNS

Upgrade your whole machine to pkdns by setting it as your primary system DNS.

Follow one of the guides to change your DNS server on your system:
- [MacOS guide](https://support.apple.com/en-gb/guide/mac-help/mh14127)
- [Ubuntu guide](https://www.ionos.com/digitalguide/server/configuration/change-dns-server-on-ubuntu/)
- [Windows guide](https://www.windowscentral.com/how-change-your-pcs-dns-settings-windows-10)


Verify your server with this domain [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).

### Verify pkdns is working

#### PKDNS Domains
Verify the server resolves pkdns domains. Replace `PKDNS_SERVER_IP` with your pkdns server IP address.

```bash 
nslookup 7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy PKDNS_SERVER_IP
```

> *Troubleshooting* If this does not work then the pkdns server is likely not running or misconfigured.


#### ICANN Domains

Verify it resolves regular ICANN domains. Replace `PKDNS_SERVER_IP` with your pkdns server IP address.

```bash
nslookup example.com PKDNS_SERVER_IP
```

> *Troubleshooting* If this does not work then you need to change your ICANN fallback server with
> `pkdns -f REGULAR_DNS_SERVER_IP`. Or use the Google DNS server: `pkdns -f 8.8.8.8`.

### Browse the Self-Sovereign Web

Here are some example pkdns domains:

- [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/)
- [http://pkdns.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://pkdns.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/)


Hint: Always add a `./` to the end of a pkarr domain. Otherwise browsers will search instead of resolve the website.

### Address already in use

Other services might occupy the port 53 already. For example, [Docker Desktop](https://github.com/docker/for-mac/issues/7008) uses the port 53 on MacOS. [systemd-resolved](https://www.linuxuprising.com/2020/07/ubuntu-how-to-free-up-port-53-used-by.html) is using it on Ubuntu. Make sure to free those.

## Configuration

### Options

```
Usage: pkdns [OPTIONS]

Options:
  -f, --forward <FORWARD>      ICANN fallback DNS server. Format: IP:Port. [default: 8.8.8.8:53]
  -v, --verbose                Show verbose output. [default: false]
  -c, --config <CONFIG>        The path to pkdns configuration file. This will override the pkdns-dir config path
  -p, --pkdns-dir <PKDNS_DIR>  The base directory that contains pkdns's data, configuration file, etc [default: ~/.pkdns]
  -h, --help                   Print help
  -V, --version                Print version
```

### Config File

`~/.pkdns/pkdns.toml` is used for all extended configurations. An example can be found in [sample-config.toml](./server/sample-config.toml).


## FAQs

- [How Censorship-Resistant is Mainline DHT?](https://medium.com/pubky/mainline-dht-censorship-explained-b62763db39cb)
- [How Censorship-Resistant are Public Key Domains](https://medium.com/pubky/public-key-domains-censorship-resistance-explained-33d0333e6123)
- [How to publish a Public Key Domain Website?](https://medium.com/pubky/how-to-host-a-public-key-domain-website-v0-6-0-ubuntu-24-04-57e6f2cb6f77)
- [How can I run my own DNS over HTTPS endpoint?](./docs/dns-over-https.md)
- [How to configure DynDNS?](./docs/dyn-dns.md)

## Related Tools

- [pkarr zone explorer](https://pkdns.net/)
- [pkdns-vanity](https://github.com/jphastings/pkdns-vanity)
- [awesome-pubky](https://github.com/aljazceru/awesome-pubky)

### Record Types

Currently, pkdns only supports `A`, `AAAA`, `TXT`, `CNAME`, and `MX` records. For any other types, use bind9.


---

May the power ⚡ be with you. Powered by [pkarr](https://github.com/pubky/pkarr).
