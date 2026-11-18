// Ad blocker: a DNS server (DNS-over-TCP, port 53) that answers blocked
// domains with a sinkhole address and forwards everything else upstream.
//
// The blocklist is compiled into the sketch from blocklist_data.h, a
// Huffman-coded store kept in flash (PROGMEM). It was generated from the
// HaGeZi Multi PRO list (see data/README.md). To use another list, regenerate
// the header and its binary tables from any hosts, AdBlock or plain file
// (plain or .gz). Keep the generated .bin files next to the header:
//
//   python3 tools/gen_huffman_blocklist.py <list> \
//       -o examples/AdBlocker/blocklist_data.h --name adblock_store --format incbin
//
// On ESP32, select Tools > Partition Scheme > "Huge APP (3MB)" (PartitionScheme=huge_app):
// the image is about 2.7 MB and does not fit the default partition.
// Point the devices on your network at this board's IP as their DNS server.
//
// Note: this server speaks DNS over TCP only, so clients that use UDP port 53
// will not reach it. Use a DNS-over-TCP capable client, or add a UDP listener.
#include <WiFi.h>
#include <TinyDNS.h>

#include "blocklist_data.h"  // generated: defines adblock_store (PROGMEM data)

const char *ssid = "your-ssid";
const char *password = "your-password";

TinyDNSHuffmanStore blocklistStore(adblock_store);

WiFiClient upstreamNet;  // used only for forwarding non-blocked cache misses
TinyDNSClient upstream(upstreamNet, DNS_GOOGLE_PRIMARY);
TinyDNSServer dnsServer(upstream);
WiFiServer listener(53);

void setup() {
  Serial.begin(115200);
#if defined(ESP32)
  WiFi.setSleep(false);  // disable WiFi powersave so the server stays reachable
#endif

  if (!blocklistStore.begin()) {
    Serial.println("built-in blocklist is invalid; regenerate blocklist_data.h");
    while (true) delay(1000);
  }
  dnsServer.blocklist().attachStore(&blocklistStore);
  Serial.print("blocked domains: ");
  Serial.println(blocklistStore.count());

  // Sinkhole (default): blocked A queries get 0.0.0.0, other types get NODATA.
  dnsServer.setBlockPolicy(TinyDNSBlockPolicy::Sinkhole);
  dnsServer.setSinkholeAddress(IPAddress(0, 0, 0, 0));
  dnsServer.setSinkholeTtl(60);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.print("ad blocker running at ");
  Serial.println(WiFi.localIP());

  dnsServer.setTimeout(3000);
  dnsServer.setMaxTtl(600);
  if (!dnsServer.begin()) Serial.println("cache allocation failed");
  listener.begin();
}

void loop() {
  WiFiClient client = listener.available();
  if (!client) return;

  uint32_t blockedBefore = dnsServer.blockedCount();
  bool ok = dnsServer.handle(client);
  client.stop();

  Serial.print("query ");
  Serial.print(ok ? "answered" : "failed");
  Serial.print(dnsServer.blockedCount() != blockedBefore ? " (blocked)" : "");
  Serial.print("  blocked total: ");
  Serial.print(dnsServer.blockedCount());
  Serial.print("  cache hits: ");
  Serial.print(dnsServer.cacheHits());
  Serial.print("  misses: ");
  Serial.println(dnsServer.cacheMisses());
}
