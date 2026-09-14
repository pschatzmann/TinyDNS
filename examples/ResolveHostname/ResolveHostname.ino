// Resolves a hostname using DNS-over-TCP against 1.1.1.1:53.
// Swap WiFiClient for WiFiClientSecure + port 853 to use DNS-over-TLS.
#include <WiFi.h>
#include <TinyDNSClient.h>

const char *ssid = "your-ssid";
const char *password = "your-password";

WiFiClient net;
DNSResolver dns(net, IPAddress(1, 1, 1, 1));  // Cloudflare DNS, plain TCP:53

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");

  IPAddress ip;
  if (dns.resolve("example.com", ip)) {
    Serial.print("example.com -> ");
    Serial.println(ip);
  } else {
    Serial.print("resolve failed, error=");
    Serial.println((int)dns.lastResult());
  }
}

void loop() {}
