/**
 * @file TinyDNSBlocklist.h
 * @brief Suffix-matching domain blocklist and allowlist for TinyDNSServer.
 *
 * A rule for "ads.example.com" also covers every subdomain
 * ("a.b.ads.example.com"). Lookups walk the query name from the full name
 * toward the TLD, and the first (most specific) rule that matches decides:
 * - an allowlist rule returns TinyDNSBlockAction::Allow
 * - a blocklist rule returns TinyDNSBlockAction::Block
 * - if the same name is in both lists, the allowlist wins
 *
 * So with "block ads.com" and "allow good.ads.com", good.ads.com and its
 * subdomains are allowed, while ads.com and other subdomains are blocked.
 *
 * Rules are stored in an open-addressing hash table with FNV-1a hashes.
 * Each domain costs roughly its length plus 1 byte in a string pool and
 * 12 bytes of table slot at a 75% maximum load factor. On boards with PSRAM
 * (ESP32 with BOARD_HAS_PSRAM, RP2350 with RP2350_PSRAM_CS) both the table and
 * the pool are allocated there; see TinyDNSMemory.h. Define TINY_DNS_NO_PSRAM
 * to keep them in internal RAM. Create the blocklist after PSRAM is initialized,
 * for example as a member of the server built in setup().
 *
 * Lists are read in hosts-file format, the same as StevenBlack and similar
 * lists:
 * @code
 * 0.0.0.0 ads.example.com
 * 127.0.0.1 tracker.example.net   # trailing comments are allowed
 * 0.0.0.0 *.ads.example.org       # leading "*." is stripped
 * @endcode
 * AdBlock lists are accepted too: "||ads.example.com^" blocks a domain and
 * "@@||ads.example.com^" allows it. Rules with options ("$...") or cosmetic
 * filters ("##") are skipped.
 *
 * Plain lists with one domain per line (no address) are accepted too. Lines
 * whose address is not a sinkhole address (0.0.0.0, 127.0.0.1, ::, ::1) are
 * skipped, so a line like "192.168.1.10 nas" is not blocked. Localhost-style
 * names from hosts files (localhost, broadcasthost, ip6-*, ...) are skipped.
 *
 * Usage:
 * @code
 * TinyDNSServer server(upstream);
 * File f = SD.open("/blocklist/hosts.txt");
 * server.blocklist().loadHosts(f);
 * f.close();
 * server.blocklist().allowDomain("api.example.com");
 * @endcode
 *
 * @author Phil Schatzmann
 */
#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "TinyDNSHuffmanStore.h"
#include "TinyDNSMemory.h"

/** @brief Result of TinyDNSBlocklist::check(). */
enum class TinyDNSBlockAction : uint8_t {
  None = 0,   ///< No rule matches; resolve normally.
  Allow = 1,  ///< An allowlist rule matches; resolve normally, never block.
  Block = 2,  ///< A blocklist rule matches; apply the sinkhole policy.
};

/**
 * @brief Suffix-matching set of blocked and allowed domain names.
 *
 * Names are case-insensitive and may have a trailing dot. The class is not
 * thread-safe. Modify the lists from the same task that calls
 * TinyDNSServer::handle().
 */
class TinyDNSBlocklist {
 public:
  /** @brief Longest accepted domain name, in characters (RFC 1035). */
  static const size_t kMaxNameLen = 253;
  /** @brief Longest line read from a hosts-format file; longer lines are skipped. */
  static const size_t kMaxLineLen = 256;

  TinyDNSBlocklist() = default;
  ~TinyDNSBlocklist() { clear(); }
  TinyDNSBlocklist(const TinyDNSBlocklist &) = delete;
  TinyDNSBlocklist &operator=(const TinyDNSBlocklist &) = delete;

  /**
   * @brief Add a domain (and all its subdomains) to the blocklist.
   * @return true if the domain was valid and stored.
   */
  bool blockDomain(const char *domain) { return addRule(domain, kFlagBlock); }

  /**
   * @brief Add a domain (and all its subdomains) to the allowlist.
   * @return true if the domain was valid and stored.
   */
  bool allowDomain(const char *domain) { return addRule(domain, kFlagAllow); }

  /**
   * @brief Remove both block and allow rules for exactly this domain.
   * Subdomains and parent domains are not affected.
   * @return true if the domain had a rule.
   */
  bool removeDomain(const char *domain) {
    char buf[kMaxNameLen + 1];
    size_t len = 0;
    if (!normalize(domain, buf, sizeof(buf), len)) return false;
    Slot *s = findSlot(buf, hashString(buf));
    if (!s || s->flags == 0) return false;
    s->flags = 0;
    active_--;
    return true;
  }

  /**
   * @brief Load blocked domains from hosts-format text.
   * @param in Any object with `int available()` and `int read()`, such as
   *           Arduino Stream, File, or a test double. Read until available()
   *           returns 0 or read() returns a negative value. With a network
   *           Client, read only the data that is currently available.
   * @return Number of domain entries accepted (duplicates are counted).
   */
  template <typename StreamT>
  size_t loadHosts(StreamT &in) {
    return parseStream(in, kFlagBlock);
  }

  /**
   * @brief Load allowed domains from hosts-format or plain text. Same
   * parsing rules as loadHosts().
   * @return Number of domain entries accepted (duplicates are counted).
   */
  template <typename StreamT>
  size_t loadAllowList(StreamT &in) {
    return parseStream(in, kFlagAllow);
  }

  /**
   * @brief Find the most specific rule matching @p name.
   * @param name Query name, e.g. "a.b.ads.example.com".
   * @return Allow or Block for the first matching suffix, or None.
   */
  /**
   * @brief Attach a read-only Huffman-coded store of blocked domains. It is
   * consulted after the RAM rules at each suffix, so RAM allow rules still
   * override it. The store must outlive this blocklist.
   */
  void attachStore(const TinyDNSHuffmanStore *store) { store_ = store; }

  TinyDNSBlockAction check(const char *name) const {
    if (!name || (active_ == 0 && !store_)) return TinyDNSBlockAction::None;
    char buf[kMaxNameLen + 1];
    size_t len = 0;
    if (!normalize(name, buf, sizeof(buf), len)) return TinyDNSBlockAction::None;

    size_t pos = 0;
    while (true) {
      const char *suffix = buf + pos;
      const Slot *s = findSlot(suffix, hashString(suffix));
      if (s && s->flags) {
        return (s->flags & kFlagAllow) ? TinyDNSBlockAction::Allow
                                       : TinyDNSBlockAction::Block;
      }
      if (store_ && store_->contains(suffix)) return TinyDNSBlockAction::Block;
      const char *dot = strchr(suffix, '.');
      if (!dot) break;
      pos = (size_t)(dot - buf) + 1;
    }
    return TinyDNSBlockAction::None;
  }

  /** @brief True if @p name is blocked (matches a block rule, not allowed). */
  bool isBlocked(const char *name) const {
    return check(name) == TinyDNSBlockAction::Block;
  }

  /** @brief Number of domains that currently have a block or allow rule. */
  size_t size() const { return active_; }

  /** @brief Remove all rules and release the memory. */
  void clear() {
    tinyDnsFree(slots_);
    tinyDnsFree(pool_);
    slots_ = nullptr;
    pool_ = nullptr;
    cap_ = used_ = active_ = 0;
    poolLen_ = poolCap_ = 0;
  }

 protected:
  static const uint8_t kFlagBlock = 1;
  static const uint8_t kFlagAllow = 2;
  static const uint32_t kEmptyOff = 0xFFFFFFFFUL;

  /** Open-addressing slot. flags == 0 means the entry is a removed rule. */
  struct Slot {
    uint32_t hash;
    uint32_t off;  ///< Offset of the NUL-terminated name in pool_.
    uint8_t flags;
  };

  const TinyDNSHuffmanStore *store_ = nullptr;  ///< Optional read-only store.
  Slot *slots_ = nullptr;  ///< Hash table; size cap_ (power of 2).
  size_t cap_ = 0;
  size_t used_ = 0;        ///< Occupied slots, including removed rules.
  size_t active_ = 0;      ///< Slots with flags != 0.
  char *pool_ = nullptr;   ///< Storage for the domain names.
  size_t poolLen_ = 0;
  size_t poolCap_ = 0;

  static uint32_t hashString(const char *s) {
    uint32_t h = 2166136261UL;  // FNV-1a
    for (; *s; s++) {
      h ^= (uint8_t)*s;
      h *= 16777619UL;
    }
    return h;
  }

  static bool isNameChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
  }

  /**
   * @brief Lower-case @p in into @p out, drop one trailing dot, and reject
   * empty labels or characters that cannot appear in a hostname.
   */
  static bool normalize(const char *in, char *out, size_t cap, size_t &outLen) {
    size_t n = strlen(in);
    if (n > 0 && in[n - 1] == '.') n--;
    if (n == 0 || n >= cap) return false;
    for (size_t i = 0; i < n; i++) {
      char c = in[i];
      if (c >= 'A' && c <= 'Z') c = c + 32;
      if (c == '.') {
        if (i == 0 || in[i - 1] == '.') return false;
      } else if (!isNameChar(c)) {
        return false;
      }
      out[i] = c;
    }
    out[n] = 0;
    outLen = n;
    return true;
  }

  Slot *findSlot(const char *name, uint32_t h) const {
    if (!slots_) return nullptr;
    size_t mask = cap_ - 1;
    size_t i = h & mask;
    while (slots_[i].off != kEmptyOff) {
      Slot &s = slots_[i];
      if (s.hash == h && strcmp(pool_ + s.off, name) == 0) return &s;
      i = (i + 1) & mask;
    }
    return nullptr;
  }

  static void insertRaw(Slot *table, size_t cap, const Slot &s) {
    size_t mask = cap - 1;
    size_t i = s.hash & mask;
    while (table[i].off != kEmptyOff) i = (i + 1) & mask;
    table[i] = s;
  }

  /** Make room for one more slot, growing (and rehashing) at 75% load. */
  bool reserveSlot() {
    if (cap_ && (used_ + 1) * 4 <= cap_ * 3) return true;
    size_t newCap = cap_ ? cap_ * 2 : 64;
    Slot *table = (Slot *)tinyDnsAlloc(newCap * sizeof(Slot));
    if (!table) return false;
    for (size_t i = 0; i < newCap; i++) table[i].off = kEmptyOff;
    for (size_t i = 0; i < cap_; i++) {
      if (slots_[i].off != kEmptyOff) insertRaw(table, newCap, slots_[i]);
    }
    tinyDnsFree(slots_);
    slots_ = table;
    cap_ = newCap;
    return true;
  }

  bool intern(const char *s, size_t len, uint32_t &offOut) {
    size_t need = poolLen_ + len + 1;
    if (need > poolCap_) {
      // Grow by copying: PSRAM blocks cannot be resized with realloc().
      size_t newCap = poolCap_ ? poolCap_ * 2 : 1024;
      while (newCap < need) newCap *= 2;
      char *p = (char *)tinyDnsAlloc(newCap);
      if (!p) return false;
      if (poolLen_) memcpy(p, pool_, poolLen_);
      tinyDnsFree(pool_);
      pool_ = p;
      poolCap_ = newCap;
    }
    memcpy(pool_ + poolLen_, s, len);
    pool_[poolLen_ + len] = 0;
    offOut = (uint32_t)poolLen_;
    poolLen_ = need;
    return true;
  }

  bool addRule(const char *domain, uint8_t flag) {
    char buf[kMaxNameLen + 1];
    size_t len = 0;
    if (!domain || !normalize(domain, buf, sizeof(buf), len)) return false;
    uint32_t h = hashString(buf);
    Slot *s = findSlot(buf, h);
    if (s) {
      if (s->flags == 0) active_++;
      s->flags |= flag;
      return true;
    }
    if (!reserveSlot()) return false;
    uint32_t off = 0;
    if (!intern(buf, len, off)) return false;
    Slot ns = {h, off, flag};
    insertRaw(slots_, cap_, ns);
    used_++;
    active_++;
    return true;
  }

  static bool isIpLiteral(const char *t) {
    if (strchr(t, ':')) return true;
    bool dot = false;
    for (const char *p = t; *p; p++) {
      if (*p == '.') {
        dot = true;
      } else if (*p < '0' || *p > '9') {
        return false;
      }
    }
    return dot;
  }

  static bool isSinkholeAddress(const char *t) {
    return strcmp(t, "0.0.0.0") == 0 || strcmp(t, "127.0.0.1") == 0 ||
           strcmp(t, "::") == 0 || strcmp(t, "::1") == 0;
  }

  static bool equalsIgnoreCase(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
      char x = *a, y = *b;
      if (x >= 'A' && x <= 'Z') x += 32;
      if (y >= 'A' && y <= 'Z') y += 32;
      if (x != y) return false;
    }
    return *a == *b;
  }

  /** Names that hosts files use for the local machine, not for ads. */
  static bool isReservedName(const char *t) {
    static const char *const kReserved[] = {
        "localhost",         "localhost.localdomain", "local",
        "localdomain",       "broadcasthost",         "ip6-localhost",
        "ip6-loopback",      "ip6-localnet",          "ip6-mcastprefix",
        "ip6-allnodes",      "ip6-allrouters",        "ip6-allhosts",
    };
    for (const char *r : kReserved) {
      if (equalsIgnoreCase(t, r)) return true;
    }
    return false;
  }

  /** Next whitespace-separated token in @p p, or nullptr at end of line. */
  static char *nextToken(char **p) {
    char *s = *p;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (*s == 0) {
      *p = s;
      return nullptr;
    }
    char *start = s;
    while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n') s++;
    if (*s) *s++ = 0;
    *p = s;
    return start;
  }

  /**
   * AdBlock domain rule: "||domain^" (block) or "@@||domain^" (allow). Only
   * the plain form is accepted; rules with options ("$...") or paths are
   * skipped, since they cannot be expressed as a whole-domain rule.
   * @param s Text after the "||" prefix, with trailing whitespace removed.
   */
  size_t addAdblockRule(char *s, uint8_t flag) {
    size_t n = strlen(s);
    if (n < 2 || s[n - 1] != '^') return 0;
    s[n - 1] = 0;
    return addRule(s, flag) ? 1 : 0;
  }

  /** Parse one NUL-terminated line in place. Returns entries accepted. */
  size_t processLine(char *line, uint8_t flag) {
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    size_t n = strlen(p);
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r')) {
      p[--n] = 0;
    }
    if (*p == 0 || *p == '!' || *p == '[') return 0;  // AdBlock comment/header

    if (strncmp(p, "@@||", 4) == 0) return addAdblockRule(p + 4, kFlagAllow);
    if (strncmp(p, "||", 2) == 0) return addAdblockRule(p + 2, flag);

    // Cosmetic filters (example.com##.ad) are not domain rules; without this
    // check the '#' stripping below would turn them into blocks.
    if (strstr(p, "##") || strstr(p, "#@#") || strstr(p, "#?#")) return 0;

    char *hash = strchr(p, '#');
    if (hash) *hash = 0;

    char *cursor = p;
    char *tok = nextToken(&cursor);
    if (!tok) return 0;

    if (isIpLiteral(tok)) {
      // Hosts format: only sinkhole addresses mark a line as a block entry
      if (!isSinkholeAddress(tok)) return 0;
      tok = nextToken(&cursor);
    }

    size_t added = 0;
    for (; tok; tok = nextToken(&cursor)) {
      if (tok[0] == '*' && tok[1] == '.') tok += 2;  // "*.ads.com" -> "ads.com"
      if (isReservedName(tok)) continue;
      if (addRule(tok, flag)) added++;
    }
    return added;
  }

  template <typename StreamT>
  size_t parseStream(StreamT &in, uint8_t flag) {
    char line[kMaxLineLen];
    size_t n = 0;
    bool tooLong = false;
    size_t added = 0;

    while (in.available() > 0) {
      int c = in.read();
      if (c < 0) break;
      if (c == '\n') {
        if (!tooLong) {
          line[n] = 0;
          added += processLine(line, flag);
        }
        n = 0;
        tooLong = false;
      } else if (n < kMaxLineLen - 1) {
        line[n++] = (char)c;
      } else {
        tooLong = true;
      }
    }
    // Last line without a trailing newline
    if (!tooLong && n > 0) {
      line[n] = 0;
      added += processLine(line, flag);
    }
    return added;
  }
};
