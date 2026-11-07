# TinyDNS

[![Arduino Library](https://img.shields.io/badge/Arduino-Library-blue.svg)](https://www.arduino.cc/reference/en/libraries/)
[![Build: CMake](https://img.shields.io/badge/Build-CMake-064F8C.svg?logo=cmake)](CMakeLists.txt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

TinyDNS is a header-only DNS library for Arduino. It sends DNS queries over any
Arduino `Client`, so it works with plain DNS over TCP (port 53) and DNS over
TLS (port 853).

It provides:

- **`TinyDNSClient`**: resolves A and AAAA records.
- **`TinyDNSServer`**: a caching DNS server with a static host table and an
  LRU cache. Cache misses are forwarded to an upstream `TinyDNSClient`.

## Installation

### Arduino IDE

Download the library as a ZIP file and add it with *Sketch → Include Library →
Add .ZIP Library…*, or clone it into your Arduino libraries folder:

```bash
cd ~/Documents/Arduino/libraries
git clone https://github.com/pschatzmann/TinyDNSClient.git
```

### PlatformIO

```ini
lib_deps = https://github.com/pschatzmann/TinyDNSClient.git
```

## Quick start

```cpp
#include <WiFi.h>
#include <TinyDNS.h>

WiFiClient net;
TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));  // Cloudflare, TCP port 53

void setup() {
  IPAddress ip;
  if (dns.resolve("example.com", ip)) {
    Serial.println(ip);
  }
}
```

## Documentation

- [Wiki](https://github.com/pschatzmann/TinyDNSClient/wiki): usage guides for
  the client, server, configuration (including PSRAM), and testing.
- [Doxygen API reference](https://pschatzmann.github.io/TinyDNSClient/).
- [`examples/`](examples/): `DNSClient` and `DNSServer` sketches.

## License

Released under the MIT License. See [LICENSE](LICENSE).
