## pkdns-cli sample

This is an example on how to announce your own records on the mainline DHT.

- `seed.txt` contains a 64 character hex encoded seed that the records are published under. You can generate one with `./pkdns-cli generate > seed.txt`.
- `pkarr.zone` is a dns zone file without the SOA record.

Publish the records by pointing to the seed and zone files.

> ⚠️ pkdns caches DHT packets for at least 60 seconds to improve latency. Run your own instance with `pkdns --max-ttl 0` to disable caching.

```bash
$ ./pkdns-cli publish seed.txt pkarr.zone

Packet 8qhdp5s8jjmxmqam3bpg9kzeg7x8teztuwrfgxw5ikn9z5bt15uy
Name                 TTL     Type   Data
@                    60      A      127.0.0.1                
dynv4                60      A      213.55.243.129           
dynv6                60      AAAA   2a04:ee41:0:819d:1905:9907:f695:41f3
text                 60      TXT    hero=satoshi2  

Announce every 60min. Stop with Ctrl-C...
2024-08-05 14:30:03.612747 +02:00 Successfully announced.
```

## Verify the Public Key Domain

- Lookup the domain on pkdns.net: https://pkdns.net/?id=8qhdp5s8jjmxmqam3bpg9kzeg7x8teztuwrfgxw5ikn9z5bt15uy
- Lookup the domain with nslookup: `nslookup 8qhdp5s8jjmxmqam3bpg9kzeg7x8teztuwrfgxw5ikn9z5bt15uy 34.65.109.99`. 34.65.109.99 is the IP of our hosted pkdns server.