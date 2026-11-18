# TinyDNS

[![Arduino Library](https://img.shields.io/badge/Arduino-Library-blue.svg)](https://www.arduino.cc/reference/en/libraries/)
[![Build: CMake](https://img.shields.io/badge/Build-CMake-064F8C.svg?logo=cmake)](CMakeLists.txt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

TinyDNS is a header-only DNS library for Arduino. It sends DNS queries over any
Arduino `Client`, so it works with plain DNS over TCP (port 53) and DNS over
TLS (port 853).

It provides:

- **[`TinyDNSClient`](https://pschatzmann.github.io/TinyDNS/class_tiny_d_n_s_client.html)**: resolves A and AAAA records.
- **[`TinyDNSServer`](https://pschatzmann.github.io/TinyDNS/class_tiny_d_n_s_server.html)**: a caching DNS server with a static host table and an
  LRU cache. Cache misses are forwarded to an upstream [`TinyDNSClient`](https://pschatzmann.github.io/TinyDNS/class_tiny_d_n_s_client.html).
- **`TinyDNSBlocklist`**: a suffix-matching blocklist and allowlist. Rules
  for `ads.example.com` also cover its subdomains. Lists can be loaded from
  hosts, AdBlock (`||domain^`) or plain-domain text. Allow rules override block rules.
- **`TinyDNSHuffmanStore`**: a read-only, Huffman-coded blocklist kept in
  flash (PROGMEM) and read in place. It holds about 250k domains in roughly
  1.8 MB. Attach it to the server's blocklist with `attachStore()`.
- The server answers blocked names with a configurable sinkhole policy
  (`Sinkhole`, `NXDomain` or `Refused`).

The server speaks DNS over TCP only. Clients that send UDP queries on port 53
will not reach it.

## Ad blocking

To block ads and trackers, see the wiki page
[Ad blocking](https://github.com/pschatzmann/TinyDNS/wiki/AdBlocking). It covers
the RAM and flash blocklists, the generator, the sinkhole policies, and the
`examples/AdBlocker` sketch.

## Installation

### Arduino IDE

Download the library as a ZIP file and add it with *Sketch → Include Library →
Add .ZIP Library…*, or clone it into your Arduino libraries folder:

```bash
cd ~/Documents/Arduino/libraries
git clone https://github.com/pschatzmann/TinyDNS.git
```

### PlatformIO

```ini
lib_deps = https://github.com/pschatzmann/TinyDNS.git
```

## Documentation

- [Wiki](https://github.com/pschatzmann/TinyDNS/wiki): usage guides for
  the client, server, configuration (including PSRAM), and testing.
- [Doxygen API reference](https://pschatzmann.github.io/TinyDNS/annotated.html).
- [`examples/`](examples/): `DNSClient`, `DNSServer` and `AdBlocker` sketches.

## License

Released under the MIT License. See [LICENSE](LICENSE).
