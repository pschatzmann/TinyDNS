// Resolves a hostname using DNS-over-TCP against TINY_DNS_SERVER_IP
// (Google 8.8.8.8 by default) on port 53.
// Swap WiFiClient for WiFiClientSecure + port 853 to use DNS-over-TLS.
#include <WiFi.h>
#include <TinyDNSClient.h>

const char *ssid = "your-ssid";
const char *password = "your-password";

WiFiClient net;
TinyDNSClient dns(net, DNS_GOOGLE_PRIMARY);

void setup() {
  Serial.begin(115200);
#if defined(ESP32)
  WiFi.setSleep(false);  // disable WiFi powersave for reliable DNS replies
#endif
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
