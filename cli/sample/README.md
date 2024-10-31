## pkdns-cli sample

This is an example on how to announce your own records on the mainline DHT.

- `seed.txt` contains a 32 bytes zbase32 encoded seed that the records are published under. You can generate one with `./pkdns-cli generate > seed.txt`.
- `pkarr.zone` is a dns zone file without the SOA record. The SOA record is optional.

Publish the records by pointing to the seed and zone files.
```bash
$ ./pkdns-cli publish seed.txt pkarr.zone

> ⚠️ The mainline DHT will take some minutes to propagate your changes. In the meantime, pkdns might return a mix of old and new packages. This is normal.

Packet eqa3q4o3dixqow5e6k75ifx5dwkahjyg7rx3j8eoh1s1fescys6o
@                    NS     dns1.example.com
@                    NS     dns2.example.com
@                    MX     10 - mail.example.com
@                    MX     20 - mail2.example.com
@                    A      127.0.0.1 
test                 A      127.0.0.1 
dns1                 A      10.0.1.1  
dns2                 A      10.0.1.2  
bitcoin              TXT    "testsev"=

Announce every 60min. Stop with Ctrl-C...
2024-08-05 14:30:03.612747 +02:00 Successfully announced.
```