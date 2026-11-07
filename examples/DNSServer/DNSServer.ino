// Caching DNS server (DNS-over-TCP, port 53) backed by an LRU cache.
// Cache hits are answered locally; misses are forwarded to TINY_DNS_UPSTREAM_IP
// (Google 8.8.8.8 by default).
// Configure clients on the same network to use this board's IP as DNS
// server. Note: this server speaks DNS over TCP only.
#include <WiFi.h>
#include <TinyDNS.h>

const char *ssid = "your-ssid";
const char *password = "your-password";

WiFiClient upstreamNet;  // used only for forwarding cache misses
TinyDNSClient upstream(upstreamNet, DNS_GOOGLE_PRIMARY);

// Static names answered locally, before the cache and upstream.
// Add your own entries here. The array must stay alive while the server runs.
TinyDNSHost hosts[] = {
    {"esp32.local", IPAddress(192, 168, 1, 50)},
    {"gateway.local", IPAddress(192, 168, 1, 1)},
};

TinyDNSServer dnsServer(upstream, hosts);
WiFiServer listener(53);

void setup() {
  Serial.begin(115200);
#if defined(ESP32)
  WiFi.setSleep(false);  // disable WiFi powersave so the server stays reachable
#endif
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.print("DNS server running at ");
  Serial.println(WiFi.localIP());

  dnsServer.setTimeout(3000);
  dnsServer.setMaxTtl(600);
  if (!dnsServer.begin()) Serial.println("cache allocation failed");
  listener.begin();
}

void loop() {
  WiFiClient client = listener.available();
  if (!client) return;

  bool ok = dnsServer.handle(client);
  client.stop();

  Serial.print("query ");
  Serial.println(ok ? "answered" : "failed");
  Serial.print("cache entries: ");
  Serial.print(dnsServer.cacheSize());
  Serial.print("/");
  Serial.print(dnsServer.cacheCapacity());
  Serial.print("  hits: ");
  Serial.print(dnsServer.cacheHits());
  Serial.print("  misses: ");
  Serial.println(dnsServer.cacheMisses());
}
