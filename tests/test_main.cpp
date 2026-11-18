// Host-side unit tests for TinyDNS. Run with: ctest --test-dir build
#include <Arduino.h>
#include <Client.h>
#include <IPAddress.h>
#include <TinyDNS.h>

#include "data/test_store.h"

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
// TinyDNSBlocklist
// ---------------------------------------------------------------------------

// Minimal Stream stand-in: available()/read() like Arduino Stream or File.
struct MemStream {
  std::string data;
  size_t pos = 0;
  explicit MemStream(const std::string &s) : data(s) {}
  int available() { return (int)(data.size() - pos); }
  int read() { return pos < data.size() ? (uint8_t)data[pos++] : -1; }
};

TEST(blocklist_suffix_match) {
  TinyDNSBlocklist bl;
  CHECK(bl.blockDomain("ads.example.com"));
  CHECK(bl.check("ads.example.com") == TinyDNSBlockAction::Block);
  CHECK(bl.check("a.b.ads.example.com") == TinyDNSBlockAction::Block);
  CHECK(bl.check("ADS.Example.COM") == TinyDNSBlockAction::Block);
  CHECK(bl.check("ads.example.com.") == TinyDNSBlockAction::Block);
  CHECK(bl.check("example.com") == TinyDNSBlockAction::None);
  CHECK(bl.check("xads.example.com") == TinyDNSBlockAction::None);
  CHECK(bl.check("ads.example.com.evil.net") == TinyDNSBlockAction::None);
  CHECK(bl.isBlocked("x.ads.example.com"));
  CHECK(bl.size() == 1);
}

TEST(blocklist_allow_beats_parent_block) {
  TinyDNSBlocklist bl;
  bl.blockDomain("ads.com");
  bl.allowDomain("good.ads.com");
  CHECK(bl.check("good.ads.com") == TinyDNSBlockAction::Allow);
  CHECK(bl.check("x.good.ads.com") == TinyDNSBlockAction::Allow);
  CHECK(bl.check("ads.com") == TinyDNSBlockAction::Block);
  CHECK(bl.check("bad.ads.com") == TinyDNSBlockAction::Block);
}

TEST(blocklist_more_specific_block_under_allow) {
  TinyDNSBlocklist bl;
  bl.allowDomain("ads.com");
  bl.blockDomain("t.ads.com");
  CHECK(bl.check("t.ads.com") == TinyDNSBlockAction::Block);
  CHECK(bl.check("x.t.ads.com") == TinyDNSBlockAction::Block);
  CHECK(bl.check("u.ads.com") == TinyDNSBlockAction::Allow);
}

TEST(blocklist_same_name_allow_wins_and_remove_clears) {
  TinyDNSBlocklist bl;
  bl.blockDomain("x.com");
  bl.allowDomain("x.com");
  CHECK(bl.check("x.com") == TinyDNSBlockAction::Allow);
  CHECK(bl.size() == 1);
  CHECK(bl.removeDomain("X.com"));
  CHECK(bl.check("x.com") == TinyDNSBlockAction::None);
  CHECK(bl.size() == 0);
  CHECK(!bl.removeDomain("x.com"));
}

TEST(blocklist_parses_hosts_format) {
  const std::string text =
      "# StevenBlack-style hosts file\r\n"
      "127.0.0.1 localhost\r\n"
      "::1 ip6-localhost\r\n"
      "0.0.0.0 broadcasthost\n"
      "192.168.1.10 nas.lan\n"          // not a sinkhole address: skipped
      "0.0.0.0\tads.one.org  # comment\n"
      "127.0.0.1   *.tracker.net\n"     // wildcard prefix stripped
      "0.0.0.0 bad..name\n"             // invalid: skipped
      "0.0.0.0 under_score.test\n"
      "0.0.0.0 last.example";           // no trailing newline
  TinyDNSBlocklist bl;
  MemStream in(text);
  CHECK(bl.loadHosts(in) == 4);
  CHECK(bl.isBlocked("ads.one.org"));
  CHECK(bl.isBlocked("www.tracker.net"));
  CHECK(bl.isBlocked("under_score.test"));
  CHECK(bl.isBlocked("last.example"));
  CHECK(!bl.isBlocked("localhost"));
  CHECK(!bl.isBlocked("nas.lan"));
  CHECK(bl.size() == 4);
}

TEST(blocklist_plain_lists_and_allowlist_loading) {
  TinyDNSBlocklist bl;
  MemStream block("ads.plain.net\n# comment\n\ntrack.plain.net\n");
  CHECK(bl.loadHosts(block) == 2);
  CHECK(bl.isBlocked("ads.plain.net"));
  CHECK(bl.isBlocked("sub.track.plain.net"));

  MemStream allow("good.plain.net\n0.0.0.0 ads.plain.net\n");
  CHECK(bl.loadAllowList(allow) == 2);
  CHECK(bl.check("good.plain.net") == TinyDNSBlockAction::Allow);
  CHECK(bl.check("ads.plain.net") == TinyDNSBlockAction::Allow);
  CHECK(bl.check("track.plain.net") == TinyDNSBlockAction::Block);
}

TEST(blocklist_parses_adblock_format) {
  const std::string text =
      "[Adblock Plus]\r\n"
      "! Title: test list\n"
      "||telemetry.001-studio.com^\n"
      "||ad.001zb.com^\r\n"
      "||plain.example^   \n"
      "||with.option.example^$third-party\n"   // options: skipped
      "||with.path.example/ads^\n"             // path: skipped
      "example.com##.ad-banner\n"              // cosmetic: must not block example.com
      "example.org#@#.ad\n"                    // cosmetic exception: skipped
      "@@||allowed.ad.example^\n";             // allow rule
  TinyDNSBlocklist bl;
  MemStream in(text);
  CHECK(bl.loadHosts(in) == 4);
  CHECK(bl.isBlocked("telemetry.001-studio.com"));
  CHECK(bl.isBlocked("sub.ad.001zb.com"));
  CHECK(bl.isBlocked("plain.example"));
  CHECK(bl.check("with.option.example") == TinyDNSBlockAction::None);
  CHECK(bl.check("with.path.example") == TinyDNSBlockAction::None);
  CHECK(bl.check("example.com") == TinyDNSBlockAction::None);
  CHECK(bl.check("example.org") == TinyDNSBlockAction::None);
  CHECK(bl.check("allowed.ad.example") == TinyDNSBlockAction::Allow);
  CHECK(bl.check("x.allowed.ad.example") == TinyDNSBlockAction::Allow);
  CHECK(bl.size() == 4);  // three blocks plus one allow rule
}

TEST(blocklist_skips_overlong_lines) {
  std::string longLine = "0.0.0.0 ";
  longLine += std::string(300, 'a') + ".com";
  MemStream in(longLine + "\n0.0.0.0 ok.test\n");
  TinyDNSBlocklist bl;
  CHECK(bl.loadHosts(in) == 1);
  CHECK(bl.isBlocked("ok.test"));
  CHECK(bl.size() == 1);
}

TEST(blocklist_rejects_invalid_names) {
  TinyDNSBlocklist bl;
  CHECK(!bl.blockDomain(""));
  CHECK(!bl.blockDomain("."));
  CHECK(!bl.blockDomain("a..b"));
  CHECK(!bl.blockDomain(".a"));
  CHECK(!bl.blockDomain("a b"));
  CHECK(!bl.blockDomain("*.x"));
  CHECK(!bl.blockDomain(nullptr));
  CHECK(bl.size() == 0);
  CHECK(bl.check("a..b") == TinyDNSBlockAction::None);
}

TEST(blocklist_grows_and_supports_removal) {
  TinyDNSBlocklist bl;
  char name[32];
  for (int i = 0; i < 1000; i++) {
    snprintf(name, sizeof(name), "d%d.test", i);
    CHECK(bl.blockDomain(name));
  }
  CHECK(bl.size() == 1000);
  for (int i = 0; i < 1000; i++) {
    snprintf(name, sizeof(name), "h.d%d.test", i);
    CHECK(bl.isBlocked(name));
  }
  CHECK(bl.removeDomain("d500.test"));
  CHECK(bl.check("d500.test") == TinyDNSBlockAction::None);
  CHECK(bl.isBlocked("d501.test"));
  CHECK(bl.size() == 999);
  CHECK(bl.blockDomain("d500.test"));
  CHECK(bl.size() == 1000);
  bl.clear();
  CHECK(bl.size() == 0);
  CHECK(bl.check("d1.test") == TinyDNSBlockAction::None);
}

// Reply layout from sendReply(): out[0..1] is the TCP prefix, out[2..3] the
// ID, out[5] the RCODE (low nibble), out[8..9] the ANCOUNT.
static int replyRcode(const std::vector<uint8_t> &o) { return o[5] & 0x0F; }
static int replyAnswers(const std::vector<uint8_t> &o) {
  return (o[8] << 8) | o[9];
}

TEST(server_sinkhole_answers_blocked_a_without_upstream) {
  FakeClient upstreamNet;
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream);
  CHECK(server.blocklist().blockDomain("ads.test"));

  FakeClient peer;
  peer.in = makeQueryFramed(21, "tracker.ads.test", 1);
  CHECK(server.handle(peer));
  CHECK(upstreamNet.connects == 0);
  CHECK(server.blockedCount() == 1);
  const std::vector<uint8_t> &o = peer.out;
  CHECK(replyRcode(o) == 0);
  CHECK(replyAnswers(o) == 1);
  CHECK(o[o.size() - 4] == 0 && o[o.size() - 1] == 0);  // 0.0.0.0
  // Sinkhole TTL (default 60 s) sits 10 bytes before the end of the message
  CHECK(o[o.size() - 10] == 0 && o[o.size() - 9] == 0 &&
        o[o.size() - 8] == 0 && o[o.size() - 7] == 60);
}

TEST(server_sinkhole_custom_address_ttl_and_nodata) {
  FakeClient upstreamNet;
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream);
  server.blocklist().blockDomain("ads.test");
  server.setSinkholeAddress(IPAddress(10, 0, 0, 1));
  server.setSinkholeTtl(5);

  FakeClient a;
  a.in = makeQueryFramed(22, "ads.test", 1);
  CHECK(server.handle(a));
  CHECK(replyAnswers(a.out) == 1);
  CHECK(a.out[a.out.size() - 4] == 10 && a.out[a.out.size() - 1] == 1);
  CHECK(a.out[a.out.size() - 7] == 5);

  FakeClient aaaa;
  aaaa.in = makeQueryFramed(23, "ads.test", 28);
  CHECK(server.handle(aaaa));
  CHECK(replyRcode(aaaa.out) == 0);
  CHECK(replyAnswers(aaaa.out) == 0);  // NODATA

  FakeClient https;  // HTTPS/SVCB must not bypass the sinkhole
  https.in = makeQueryFramed(24, "ads.test", 65);
  CHECK(server.handle(https));
  CHECK(replyRcode(https.out) == 0);
  CHECK(replyAnswers(https.out) == 0);
  CHECK(upstreamNet.connects == 0);
  CHECK(server.blockedCount() == 3);
}

TEST(server_nxdomain_and_refused_policies) {
  FakeClient upstreamNet;
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream);
  server.blocklist().blockDomain("ads.test");

  server.setBlockPolicy(TinyDNSBlockPolicy::NXDomain);
  CHECK(server.blockPolicy() == TinyDNSBlockPolicy::NXDomain);
  FakeClient a;
  a.in = makeQueryFramed(31, "ads.test", 1);
  CHECK(server.handle(a));
  CHECK(replyRcode(a.out) == 3);
  CHECK(replyAnswers(a.out) == 0);

  server.setBlockPolicy(TinyDNSBlockPolicy::Refused);
  FakeClient aaaa;
  aaaa.in = makeQueryFramed(32, "ads.test", 28);
  CHECK(server.handle(aaaa));
  CHECK(replyRcode(aaaa.out) == 5);
  CHECK(upstreamNet.connects == 0);
  CHECK(server.blockedCount() == 2);
}

TEST(server_allowlisted_name_reaches_upstream) {
  FakeClient upstreamNet;
  upstreamNet.in = makeResponse(1, "ok.ads.test", 1, {1, 2, 3, 4}, 300);
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream);
  CHECK(server.begin(8));
  server.blocklist().blockDomain("ads.test");
  server.blocklist().allowDomain("ok.ads.test");

  FakeClient peer;
  peer.in = makeQueryFramed(41, "ok.ads.test", 1);
  CHECK(server.handle(peer));
  CHECK(upstreamNet.connects == 1);
  CHECK(server.blockedCount() == 0);
  CHECK(peer.out[peer.out.size() - 4] == 1 && peer.out[peer.out.size() - 1] == 4);
}

TEST(server_blocklist_precedes_host_table) {
  TinyDNSHost hosts[] = {{"esp32.local", IPAddress(192, 168, 1, 50)}};
  FakeClient upstreamNet;
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream, hosts);
  server.blocklist().blockDomain("esp32.local");

  FakeClient peer;
  peer.in = makeQueryFramed(51, "esp32.local", 1);
  CHECK(server.handle(peer));
  CHECK(peer.out[peer.out.size() - 4] == 0);  // sinkhole, not 192.168.1.50
  CHECK(server.blockedCount() == 1);
}

// ---------------------------------------------------------------------------
// TinyDNSHuffmanStore
// ---------------------------------------------------------------------------

static TinyDNSHuffmanStore makeTestStore() {
  return TinyDNSHuffmanStore(test_store);
}

TEST(store_begin_and_count) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(!store.ready());
  CHECK(store.begin());
  CHECK(store.ready());
  CHECK(store.count() == test_store_names_count);
}

TEST(store_contains_every_member) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(store.begin());
  for (unsigned i = 0; i < test_store_names_count; i++) {
    if (!store.contains(test_store_names[i])) {
      fprintf(stderr, "  missing: %s\n", test_store_names[i]);
      CHECK(false);
    }
  }
}

TEST(store_rejects_non_members) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(store.begin());
  CHECK(!store.contains("example.com"));
  CHECK(!store.contains("com"));
  CHECK(!store.contains("ads.example"));
  CHECK(!store.contains("ads.example.com.evil"));
  CHECK(!store.contains("xads.example.com"));
  CHECK(!store.contains("x.ads.example.com"));  // contains() is exact-match
  CHECK(!store.contains("same.prefix"));
  CHECK(!store.contains("a.b.c.d.evil"));
  CHECK(!store.contains("zz.example.com"));
  CHECK(!store.contains("bad..name"));
  CHECK(!store.contains("*.x"));
  CHECK(!store.contains(""));
  CHECK(!store.contains(nullptr));
}

TEST(store_is_case_insensitive_and_ignores_trailing_dot) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(store.begin());
  CHECK(store.contains("ADS.Example.COM."));
  CHECK(store.contains("Tracker.NET"));
}

TEST(store_rejects_corrupt_layout) {
  // Zero block size
  TinyDNSHuffmanStoreData d = test_store;
  d.blockSize = 0;
  TinyDNSHuffmanStore a(d);
  CHECK(!a.begin());
  CHECK(!a.contains("tracker.net"));

  // Block count inconsistent with count / blockSize
  d = test_store;
  d.blockCount += 1;
  TinyDNSHuffmanStore b(d);
  CHECK(!b.begin());

  // Code length above the 15-bit limit
  uint8_t badLens[256];
  memcpy(badLens, test_store_prefix_lens, sizeof(badLens));
  for (int i = 0; i < 256; i++) {
    if (badLens[i]) { badLens[i] = 16; break; }
  }
  d = test_store;
  d.prefixLens = badLens;
  TinyDNSHuffmanStore c(d);
  CHECK(!c.begin());

  // Over-subscribed code: every symbol has length 1
  uint8_t fullLens[256];
  memset(fullLens, 1, sizeof(fullLens));
  d = test_store;
  d.suffixLens = fullLens;
  TinyDNSHuffmanStore e(d);
  CHECK(!e.begin());
}

TEST(blocklist_uses_attached_store) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(store.begin());
  TinyDNSBlocklist bl;
  bl.attachStore(&store);
  CHECK(bl.check("ads.example.com") == TinyDNSBlockAction::Block);
  CHECK(bl.check("sub.ads.example.com") == TinyDNSBlockAction::Block);
  CHECK(bl.check("www.wild.example.net") == TinyDNSBlockAction::Block);
  CHECK(bl.check("example.com") == TinyDNSBlockAction::None);
  CHECK(bl.size() == 0);  // store entries are not RAM rules
}

TEST(blocklist_ram_allow_overrides_store) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(store.begin());
  TinyDNSBlocklist bl;
  bl.attachStore(&store);
  CHECK(bl.allowDomain("ads.example.com"));
  CHECK(bl.check("ads.example.com") == TinyDNSBlockAction::Allow);
  CHECK(bl.check("x.ads.example.com") == TinyDNSBlockAction::Allow);
  CHECK(bl.check("tracker.net") == TinyDNSBlockAction::Block);
}

TEST(blocklist_ram_and_store_rules_combine) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(store.begin());
  TinyDNSBlocklist bl;
  bl.attachStore(&store);
  CHECK(bl.blockDomain("other.net"));
  CHECK(bl.isBlocked("other.net"));
  CHECK(bl.isBlocked("tracker.net"));
  CHECK(bl.size() == 1);
  bl.attachStore(nullptr);
  CHECK(!bl.isBlocked("tracker.net"));
  CHECK(bl.isBlocked("other.net"));
}

TEST(server_sinkholes_names_from_store) {
  TinyDNSHuffmanStore store = makeTestStore();
  CHECK(store.begin());
  FakeClient upstreamNet;
  TinyDNSClient upstream(upstreamNet, IPAddress(1, 1, 1, 1));
  TinyDNSServer server(upstream);
  server.blocklist().attachStore(&store);

  FakeClient peer;
  peer.in = makeQueryFramed(61, "tracker.net", 1);
  CHECK(server.handle(peer));
  CHECK(upstreamNet.connects == 0);
  CHECK(server.blockedCount() == 1);
  CHECK(replyAnswers(peer.out) == 1);
  CHECK(peer.out[peer.out.size() - 4] == 0);  // sinkhole 0.0.0.0
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
