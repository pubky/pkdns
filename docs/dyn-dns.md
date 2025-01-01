# DynDNS

DynDNS (Dynamic Domain Name System) is a service that allows users to assign a fixed domain name to a device with a dynamic IP address. This is particularly useful for home networks, servers, or remote devices that do not have a static IP from their Internet Service Provider (ISP).

Key Purposes:
- Remote Access – Enables access to home or office networks remotely using a consistent domain name.
- Hosting Services – Supports hosting websites, game servers, or other services from a dynamic IP.
- Simplified Configuration – Automatically updates DNS records when the IP address changes, avoiding manual reconfiguration.

Essentially, DynDNS bridges the gap between dynamic IP addresses and the need for reliable remote access.

## How does PKDNS Enable DynDNS?

While publishing the `pkarr.zone` with `pkdns-cli`, the cli replaces the variables `{external_ipv4}` and `{external_ipv6}` with your actual external IP address. In combination with publishing your Public Key Domain (PKD)
every 60 minutes, your PKD keeps pointing to the correct IP address.


See [cli/sample/pkarr.zone](../cli/sample/pkarr.zone) as an example to use your external IPv4 address and [this guide](https://medium.com/pubky/how-to-host-a-public-key-domain-website-v0-6-0-ubuntu-24-04-57e6f2cb6f77) on how to publish it.