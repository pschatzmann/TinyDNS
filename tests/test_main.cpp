// Host-side unit tests for TinyDNS. Run with: ctest --test-dir build
#include <Arduino.h>
#include <Client.h>
#include <IPAddress.h>
#include <TinyDNS.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

uint32_t g_mockMillis = 0;

// ---------------------------------------------------------------------------
// Minimal test framework
// ---------------------------------------------------------------------------

static int g_failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      ++g_failures;                                                          \
      fprintf(stderr, "  %s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                        \
  } while (0)

struct TestCase {
  const char *name;
  void (*fn)();
};

static std::vector<TestCase> &registry() {
  static std::vector<TestCase> r;
  return r;
}

struct Registrar {
  Registrar(const char *name, void (*fn)()) { registry().push_back({name, fn}); }
};

#define TEST(name)                          \
  static void name();                       \
  static Registrar reg_##name(#name, name); \
  static void name()

// ---------------------------------------------------------------------------
// Fake transport and DNS message helpers
// ---------------------------------------------------------------------------

// In-memory Client. `in` is what the peer sends; `out` is what we wrote.
class FakeClient : public Client {
 public:
  bool connectOk = true;
  int connects = 0;
  std::vector<uint8_t> in;
  std::vector<uint8_t> out;
  size_t readPos = 0;

  int connect(IPAddress, uint16_t) override {
    connects++;
    return connectOk ? 1 : 0;
  }
  size_t write(const uint8_t *b, size_t n) override {
    out.insert(out.end(), b, b + n);
    return n;
  }
  int available() override { return (int)(in.size() - readPos); }
  int read(uint8_t *b, size_t n) override {
    size_t k = std::min(n, in.size() - readPos);
    memcpy(b, in.data() + readPos, k);
    readPos += k;
    return (int)k;
  }
  // Reports disconnected once the peer's data is drained, so reads terminate.
  bool connected() override { return readPos < in.size(); }
  void stop() override {}
};

static void put16(std::vector<uint8_t> &v, uint16_t x) {
  v.push_back((uint8_t)(x >> 8));
  v.push_back((uint8_t)(x & 0xFF));
}

static void put32(std::vector<uint8_t> &v, uint32_t x) {
  put16(v, (uint16_t)(x >> 16));
  put16(v, (uint16_t)(x & 0xFFFF));
}

static std::vector<uint8_t> encodeName(const char *name) {
  std::vector<uint8_t> v;
  const char *p = name;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t len = dot ? (size_t)(dot - p) : strlen(p);
    v.push_back((uint8_t)len);
    v.insert(v.end(), p, p + len);
    p += len;
    if (*p == '.') p++;
  }
  v.push_back(0);
  return v;
}

// Builds a TCP-framed query (2-byte length prefix + message).
static std::vector<uint8_t> makeQueryFramed(uint16_t id, const char *name,
                                            uint16_t qtype) {
  std::vector<uint8_t> msg;
  put16(msg, id);
  put16(msg, 0x0100);  // RD set
  put16(msg, 1);       // QDCOUNT
  put16(msg, 0);
  put16(msg, 0);
  put16(msg, 0);
  std::vector<uint8_t> qname = encodeName(name);
  msg.insert(msg.end(), qname.begin(), qname.end());
  put16(msg, qtype);
  put16(msg, 1);  // IN

  std::vector<uint8_t> framed;
  put16(framed, (uint16_t)msg.size());
  framed.insert(framed.end(), msg.begin(), msg.end());
  return framed;
}

// Builds a TCP-framed response. An empty rdata produces no answer record.
static std::vector<uint8_t> makeResponse(uint16_t id, const char *name,
                                         uint16_t qtype,
                                         const std::vector<uint8_t> &rdata,
                                         uint32_t ttl, uint8_t rcode = 0) {
  std::vector<uint8_t> msg;
  put16(msg, id);
  put16(msg, (uint16_t)(0x8180 | rcode));  // QR, RD, RA, RCODE
  put16(msg, 1);
  put16(msg, rdata.empty() ? 0 : 1);
  put16(msg, 0);
  put16(msg, 0);
  std::vector<uint8_t> qname = encodeName(name);
  msg.insert(msg.end(), qname.begin(), qname.end());
  put16(msg, qtype);
  put16(msg, 1);
  if (!rdata.empty()) {
    put16(msg, 0xC00C);  // pointer to the question name
    put16(msg, qtype);
    put16(msg, 1);
    put32(msg, ttl);
    put16(msg, (uint16_t)rdata.size());
    msg.insert(msg.end(), rdata.begin(), rdata.end());
  }

  std::vector<uint8_t> framed;
  put16(framed, (uint16_t)msg.size());
  framed.insert(framed.end(), msg.begin(), msg.end());
  return framed;
}

// ---------------------------------------------------------------------------
// TinyDNSLRUCache
// ---------------------------------------------------------------------------

TEST(lru_begin_rejects_invalid_capacity) {
  TinyDNSLRUCache c;
  CHECK(!c.begin(0));
  CHECK(!c.begin(TinyDNSLRUCache::kMaxCapacity + 1));
  CHECK(c.begin(4));
  CHECK(c.capacity() == 4);
}

TEST(lru_get_is_case_insensitive_and_keyed_by_qtype) {
  TinyDNSLRUCache c;
  c.begin(4);
  const uint8_t a[4] = {1, 2, 3, 4};
  CHECK(c.put("Example.COM", 1, a, 4, 1000));

  const TinyDNSLRUCache::Entry *e = c.get("example.com", 1, 0);
  CHECK(e != nullptr);
  if (e) CHECK(e->rdlen == 4 && e->rdata[0] == 1);
  CHECK(c.get("example.com", 28, 0) == nullptr);
}

TEST(lru_evicts_least_recently_used) {
  TinyDNSLRUCache c;
  c.begin(2);
  const uint8_t a[4] = {1, 1, 1, 1}, b[4] = {2, 2, 2, 2}, d[4] = {3, 3, 3, 3};
  c.put("a.test", 1, a, 4, 1000);
  c.put("b.test", 1, b, 4, 1000);
  CHECK(c.get("a.test", 1, 0) != nullptr);  // a becomes most recent
  c.put("c.test", 1, d, 4, 1000);           // evicts b
  CHECK(c.get("b.test", 1, 0) == nullptr);
  CHECK(c.get("a.test", 1, 0) != nullptr);
  CHECK(c.get("c.test", 1, 0) != nullptr);
  CHECK(c.size() == 2);
}

TEST(lru_expired_entries_are_dropped) {
  TinyDNSLRUCache c;
  c.begin(2);
  const uint8_t a[4] = {5, 5, 5, 5};
  c.put("x.test", 1, a, 4, 100);
  CHECK(c.get("x.test", 1, 99) != nullptr);
  CHECK(c.get("x.test", 1, 100) == nullptr);
  CHECK(c.size() == 0);
}

TEST(lru_put_rejects_invalid_arguments) {
  const uint8_t a[4] = {1, 2, 3, 4};
  TinyDNSLRUCache c;
  c.begin(2);
  CHECK(!c.put("", 1, a, 4, 1000));
  CHECK(!c.put("x", 1, a, 0, 1000));
  CHECK(!c.put("x", 1, a, 17, 1000));

  TinyDNSLRUCache unallocated;  // begin() never called
  CHECK(!unallocated.put("x", 1, a, 4, 1000));
  CHECK(unallocated.get("x", 1, 0) == nullptr);
}

TEST(lru_resize_drops_entries) {
  TinyDNSLRUCache c;
  c.begin(2);
  const uint8_t a[4] = {1, 2, 3, 4};
  c.put("x.test", 1, a, 4, 1000);
  CHECK(c.resize(4));
  CHECK(c.size() == 0);
  CHECK(c.capacity() == 4);
}

// ---------------------------------------------------------------------------
// TinyDNSClient
// ---------------------------------------------------------------------------

TEST(client_resolves_a_record) {
  FakeClient net;
  net.in = makeResponse(1, "example.com", 1, {93, 184, 216, 34}, 300);
  TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));

  IPAddress ip;
  CHECK(dns.resolve("example.com", ip));
  CHECK(ip[0] == 93 && ip[3] == 34);
  CHECK(dns.lastTtl() == 300);
  CHECK(dns.lastResult() == DNSResult::Ok);
  CHECK(net.connects == 1);
}

TEST(client_resolves_aaaa_record) {
  FakeClient net;
  std::vector<uint8_t> v6(16, 0);
  v6[0] = 0x20;
  v6[1] = 0x01;
  v6[15] = 1;
  net.in = makeResponse(1, "example.com", 28, v6, 60);
  TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));

  uint8_t out[16] = {0};
  CHECK(dns.resolveV6("example.com", out));
  CHECK(out[0] == 0x20 && out[1] == 0x01 && out[15] == 1);
}

TEST(client_reports_not_found) {
  FakeClient net;
  net.in = makeResponse(1, "example.com", 1, {}, 0);
  TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));

  IPAddress ip;
  CHECK(!dns.resolve("example.com", ip));
  CHECK(dns.lastResult() == DNSResult::NotFound);
}

TEST(client_reports_server_error) {
  FakeClient net;
  net.in = makeResponse(1, "example.com", 1, {}, 0, 3);
  TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));

  IPAddress ip;
  CHECK(!dns.resolve("example.com", ip));
  CHECK(dns.lastResult() == DNSResult::ServerError);
}

TEST(client_reports_connect_failure) {
  FakeClient net;
  net.connectOk = false;
  TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));

  IPAddress ip;
  CHECK(!dns.resolve("example.com", ip));
  CHECK(dns.lastResult() == DNSResult::ConnectFailed);
}

TEST(client_rewrites_hostname_in_url) {
  FakeClient net;
  net.in = makeResponse(1, "example.com", 1, {93, 184, 216, 34}, 300);
  TinyDNSClient dns(net, IPAddress(1, 1, 1, 1));

  String url = "http://example.com:8080/status";
  CHECK(dns.resolve(url));
  CHECK(std::string(url.c_str()) == "http://93.184.216.34:8080/status");
}

// ---------------------------------------------------------------------------
// TinyDNSServer
// ---------------------------------------------------------------------------

TEST(server_answers_from_host_table_without_upstream) {
  TinyDNSHost hosts[] = {{"esp32.local", IPAddress(192, 168, 1, 50)}};
  FakeClient upstreamNet;
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream, hosts);

  FakeClient peer;
  peer.in = makeQueryFramed(7, "ESP32.local", 1);
  CHECK(server.handle(peer));
  CHECK(upstreamNet.connects == 0);

  const std::vector<uint8_t> &o = peer.out;
  CHECK(o.size() >= 4);
  CHECK(o[2] == 0 && o[3] == 7);          // reply ID matches query
  CHECK(o[6] == 0 && o[7] == 1);          // ANCOUNT = 1
  CHECK(o[o.size() - 4] == 192 && o[o.size() - 1] == 50);
}

TEST(server_caches_upstream_answers) {
  FakeClient upstreamNet;
  upstreamNet.in = makeResponse(1, "example.com", 1, {1, 2, 3, 4}, 300);
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream);
  CHECK(server.begin(8));

  FakeClient peer1;
  peer1.in = makeQueryFramed(9, "example.com", 1);
  CHECK(server.handle(peer1));
  CHECK(server.cacheMisses() == 1 && server.cacheHits() == 0);
  CHECK(server.cacheSize() == 1);

  // Second query is served from the cache; upstream is not contacted again.
  FakeClient peer2;
  peer2.in = makeQueryFramed(10, "example.com", 1);
  CHECK(server.handle(peer2));
  CHECK(upstreamNet.connects == 1);
  CHECK(server.cacheHits() == 1);
  const std::vector<uint8_t> &o = peer2.out;
  CHECK(o.size() >= 4 && o[o.size() - 4] == 1 && o[o.size() - 1] == 4);
}

TEST(server_returns_nxdomain_when_upstream_has_no_record) {
  FakeClient upstreamNet;
  upstreamNet.in = makeResponse(1, "nope.test", 1, {}, 0);
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream);
  CHECK(server.begin(8));

  FakeClient peer;
  peer.in = makeQueryFramed(11, "nope.test", 1);
  CHECK(server.handle(peer));
  // Offset 2 skips the TCP length prefix; RCODE is the low nibble of byte 3.
  CHECK(peer.out.size() >= 6);
  CHECK((peer.out[5] & 0x0F) == 3);  // RCODE = NXDOMAIN
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

int main() {
  int failedTests = 0;
  for (const TestCase &t : registry()) {
    int before = g_failures;
    t.fn();
    bool ok = g_failures == before;
    if (!ok) failedTests++;
    printf("[%s] %s\n", ok ? " OK " : "FAIL", t.name);
  }
  printf("%zu tests, %d failed\n", registry().size(), failedTests);
  return failedTests ? 1 : 0;
}
