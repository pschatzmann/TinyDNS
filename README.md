# TinyDNSClient

Header-only DNS resolver for Arduino that talks DNS over a generic
[`Client`](https://www.arduino.cc/reference/en/libraries/client/) instead of
`UDP`. Because it only depends on `Client`, it works with:

- `WiFiClient` / `EthernetClient` — plain DNS-over-TCP (port 53)
- `WiFiClientSecure` (or any TLS `Client`) — DNS-over-TLS (port 853), e.g.
  against `1.1.1.1:853` or `8.8.8.8:853`

Messages are framed per RFC 1035 §4.2.2 (2-byte big-endian length prefix).

## Usage

```cpp
#include <WiFiClient.h>
#include <TinyDNSClient.h>

WiFiClient net;
DNSResolver dns(net, IPAddress(1, 1, 1, 1));  // server, port defaults to 53

IPAddress ip;
if (dns.resolve("example.com", ip)) {
  Serial.println(ip);
}
```

For AAAA (IPv6) lookups, use `resolveV6(hostname, uint8_t[16])` — the raw
16-byte address is returned directly rather than via `IPAddress`, since
IPv6 support in `IPAddress` differs across Arduino cores.

```cpp
uint8_t addr6[16];
if (dns.resolveV6("example.com", addr6)) { ... }
```

## Configuration

- `DNSResolver::setTimeout(ms)` — per-query timeout (default 5000 ms).
- `DNSResolver::lastResult()` — returns a `DNSResult` describing the last
  failure (`ConnectFailed`, `Timeout`, `ServerError`, `NotFound`, ...).
- `TINY_DNS_MAX_PACKET_SIZE` (define before including the header) — size of
  the internal message buffer, default 512 bytes.

## Notes

- Each `resolve()` call opens a fresh connection to the DNS server and
  closes it when done, so the `Client` you pass in can be reused elsewhere
  between calls.
- Only the first matching answer record is returned (no CNAME chasing).
