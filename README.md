# pkdns

DNS server resolving [pkarr](https://github.com/nuhvi/pkarr) self-sovereign domains.

## Getting Started



### Build Yourself

1. Run `cargo run`.
2. Configure you system to send DNS requests to `127.0.0.1:53`.
3. Test by going to [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).


## Options

```
Usage: pkdns [OPTIONS]

Options:
  -f, --forward <forward>      ICANN fallback DNS server. IP:Port [default: 192.168.1.1:53]
  -s, --socket <socket>        Socket the server should listen on. IP:Port [default: 0.0.0.0:53]
  -v, --verbose                Show verbose output.
      --no-cache               Disable DHT packet caching.
      --threads <threads>      Number of threads to process dns queries. [default: 4]
  -d, --directory <directory>  pknames source directory. [default: ~/.pknames]
  -h, --help                   Print help
  -V, --version                Print version
```