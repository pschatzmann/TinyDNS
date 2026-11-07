# TinyDNS

[![Arduino Library](https://img.shields.io/badge/Arduino-Library-blue.svg)](https://www.arduino.cc/reference/en/libraries/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Header-only DNS library for Arduino that talks DNS over a generic
[`Client`](https://www.arduino.cc/reference/en/libraries/client/) instead of
`UDP`. It provides:

- **`TinyDNSClient`**: a resolver client (A and AAAA lookups).
- **`TinyDNSServer`**: a caching DNS server that answers A/AAAA queries from
  an **LRU cache** and forwards cache misses to an upstream `TinyDNSClient`.
- **`TinyDNSLRUCache<N>`**: the fixed-size, allocation-free LRU cache used by
  the server.

Because it only depends on `Client`, it works with:

- `WiFiClient` / `EthernetClient`: plain DNS-over-TCP (port 53)
- `WiFiClientSecure` (or any TLS `Client`): DNS-over-TLS (port 853), e.g.
  against `1.1.1.1:853` or `8.8.8.8:853`

Messages are framed per RFC 1035 §4.2.2 (2-byte big-endian length prefix).

Include everything with:

```cpp
#include <TinyDNS.h>
```

## Usage

```cpp
#include <WiFiClient.h>
#include <TinyDNSClient.h>

WiFiClient net;
TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));  // server, port defaults to 53

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

To resolve a hostname embedded in a URL in place, use the `String&`
overload — it rewrites just the hostname portion and leaves any
scheme/port/path untouched:

```cpp
String url = "http://example.com:8080/status";
if (dns.resolve(url)) {
  Serial.println(url);  // http://93.184.216.34:8080/status
}
```

## Server usage (with LRU cache)

`TinyDNSServer` accepts TCP connections on a server socket, answers each
query from its cache, and forwards misses to an upstream resolver. The
upstream resolver must use a **different** `Client` than the incoming
connection.

```cpp
WiFiClient upstreamNet;
TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
TinyDNSHost hosts[] = {
    {"esp32.local", IPAddress(192, 168, 1, 50)},
};
TinyDNSServer dnsServer(upstream, hosts);  // static host table is optional
WiFiServer listener(53);

void loop() {
  WiFiClient client = listener.available();
  if (client) {
    dnsServer.handle(client);  // one query per connection
    client.stop();
  }
}
```

Static host table: names in the `TinyDNSHost` array are answered first, with
no upstream query and no cache entry. A query for an IPv4-only name returns
an empty AAAA answer (NODATA). The array must outlive the server. You can
also use `TinyDNSServer(upstream, ptr, count)` or `setHosts(ptr, count)`.

Cache behaviour:

- Entries are keyed by `(name, qtype)`; names are case-insensitive.
- When the cache is full, the least recently used entry is evicted.
- Records expire according to the TTL returned by the upstream server,
  capped by `setMaxTtl()`.
- Only A and AAAA questions are answered; other types get `NOTIMP`.

See `examples/DNSServer` for a complete sketch.

## Configuration

- `TinyDNSClient::setTimeout(ms)`: per-query timeout (default 5000 ms).
- `TinyDNSClient::lastResult()`: returns a `DNSResult` describing the last
  failure (`ConnectFailed`, `Timeout`, `ServerError`, `NotFound`, ...).
- `TinyDNSClient::lastTtl()`: TTL (seconds) of the last successful answer.
- `TinyDNSServer::setTimeout(ms)`: time allowed to read a query.
- `TinyDNSServer::setMaxTtl(seconds)`: upper bound for cached TTLs (default 3600).
- `TinyDNSServer::clearCache()`, `cacheSize()`, `cacheCapacity()`,
  `cacheHits()`, `cacheMisses()`: cache management and statistics.

Defines (set before including the header):

- `TINY_DNS_MAX_PACKET_SIZE`: internal message buffer size (default 512 bytes).
- `TINY_DNS_DEFAULT_TIMEOUT_MS`: default resolver timeout (default 5000).
- `TINY_DNS_CACHE_SIZE`: default number of LRU cache entries (default 16, max 254).
  The cache is allocated by `dnsServer.begin()` (or `TinyDNSLRUCache::begin()`),
  not by the constructor, so call it from `setup()` after the board is
  initialized. On ESP32 boards with PSRAM (`BOARD_HAS_PSRAM`)
  it is placed in PSRAM, and on RP2350 boards with PSRAM (`RP2350_PSRAM_CS`,
  arduino-pico) it is allocated with `pmalloc()`. Define `TINY_DNS_NO_PSRAM`
  to force internal RAM.
  Use `TinyDNSServer::setCacheCapacity(n)` to change the size at runtime.
- `TINY_DNS_MAX_TTL`: default maximum cached TTL in seconds (default 3600).

## Notes

- Each `resolve()` call opens a fresh connection to the DNS server and
  closes it when done, so the `Client` you pass in can be reused elsewhere
  between calls.
- Only the first matching answer record is returned (no CNAME chasing).
- The server is TCP-only; clients must be configured to use DNS over TCP.
- Migrating from `TinyDNSClient`: `#include <TinyDNSClient.h>` still works,
  but `#include <TinyDNS.h>` is the new entry point.
