/**
 * @file TinyDNSServer.h
 * @brief Caching DNS-over-TCP server for Arduino, backed by an LRU cache.
 *
 * Accepts DNS queries on a stream Client (e.g. a WiFiClient obtained from
 * a WiFiServer listening on port 53), answers A/AAAA questions from an
 * LRU cache and forwards cache misses to an upstream TinyDNSClient.
 *
 * @author Phil Schatzmann
 */
#pragma once

#include <Arduino.h>
#include <Client.h>
#include <string.h>

#include "TinyDNSClient.h"
#include "TinyDNSLRUCache.h"

#ifndef TINY_DNS_CACHE_SIZE
#define TINY_DNS_CACHE_SIZE 16
#endif

#ifndef TINY_DNS_MAX_TTL
#define TINY_DNS_MAX_TTL 3600
#endif

/**
 * @brief A static name-to-IPv4 mapping served authoritatively by
 * TinyDNSServer, ahead of the cache and upstream lookups.
 */
struct TinyDNSHost {
  const char *name;  ///< Hostname (case-insensitive), e.g. "esp32.local".
  IPAddress ip;      ///< IPv4 address returned for A queries.
};

/**
 * @brief Caching DNS server that answers queries from an LRU cache and
 * forwards misses to an upstream TinyDNSClient.
 *
 * Usage: accept a connection on a server socket and pass the client to
 * handle(). Each call reads exactly one query and writes one response.
 * The upstream client must use a different Client than the incoming
 * connection, and must outlive this server.
 *
 * An optional static host table (see the constructors) is checked
 * first; its entries are answered without touching the cache or the
 * upstream server. The host table array must outlive this server.
 */
class TinyDNSServer {
 public:
  using Cache = TinyDNSLRUCache;

  /**
   * @brief Create a server that forwards cache misses to @p upstream.
   * @param upstream Client used for cache misses. Must outlive this server.
   */
  explicit TinyDNSServer(TinyDNSClient &upstream) : upstream_(upstream) {}

  /**
   * @brief Create a server with a static host table.
   * @param upstream Client used for cache misses. Must outlive this server.
   * @param hosts Array of name/IPv4 pairs. Must outlive this server.
   * @param count Number of entries in @p hosts.
   */
  TinyDNSServer(TinyDNSClient &upstream, const TinyDNSHost *hosts, size_t count)
      : upstream_(upstream), hosts_(hosts), hostCount_(count) {}

  /**
   * @brief Create a server with a static host table declared as an array.
   * Example: `TinyDNSHost hosts[] = {{"esp32.local", IPAddress(192,168,1,10)}};`
   * @param upstream Client used for cache misses. Must outlive this server.
   * @param hosts Array of name/IPv4 pairs. Must outlive this server.
   */
  template <size_t N>
  TinyDNSServer(TinyDNSClient &upstream, const TinyDNSHost (&hosts)[N])
      : upstream_(upstream), hosts_(hosts), hostCount_(N) {}

  /**
   * @brief Replace the static host table.
   * @param hosts Array of name/IPv4 pairs. Must outlive this server.
   * @param count Number of entries in @p hosts.
   */
  void setHosts(const TinyDNSHost *hosts, size_t count) {
    hosts_ = hosts;
    hostCount_ = count;
  }

  /** @brief Timeout for reading a query from the incoming client, in ms. */
  void setTimeout(uint32_t timeoutMs) { timeoutMs_ = timeoutMs; }

  /** @brief Upper bound applied to cached record TTLs, in seconds. */
  void setMaxTtl(uint32_t seconds) { maxTtl_ = seconds; }

  /** @brief Drop all cached records. */
  void clearCache() { cache_.clear(); }

  /**
   * @brief Allocate the cache. Call from setup(), after PSRAM is ready.
   * @param entries Number of cache entries.
   * @return true if the cache was allocated.
   */
  bool begin(size_t entries = TINY_DNS_CACHE_SIZE) { return cache_.begin(entries); }

  /**
   * @brief Reallocate the cache with a new number of entries (drops all
   * cached records). Uses PSRAM on ESP32 boards that have it.
   * @return true if the new cache was allocated.
   */
  bool setCacheCapacity(size_t entries) { return cache_.resize(entries); }

  /** @brief Number of records currently cached. */
  size_t cacheSize() const { return cache_.size(); }

  /** @brief Maximum number of records the cache can hold. */
  size_t cacheCapacity() const { return cache_.capacity(); }

  /** @brief Number of queries answered from the cache. */
  uint32_t cacheHits() const { return hits_; }

  /** @brief Number of queries that required an upstream lookup. */
  uint32_t cacheMisses() const { return misses_; }

  /**
   * @brief Read one DNS query from @p client and send the response.
   * @param client Connected stream client carrying a TCP-framed query.
   * @return true if a response was sent, false if the query could not be
   * read or answered.
   */
  bool handle(Client &client) {
    uint32_t deadline = millis() + timeoutMs_;

    uint8_t lenPrefix[2];
    if (!readExact(client, lenPrefix, 2, deadline)) return false;
    size_t msgLen = ((size_t)lenPrefix[0] << 8) | lenPrefix[1];
    if (msgLen < 12 || msgLen > sizeof(query_)) return false;
    if (!readExact(client, query_, msgLen, deadline)) return false;

    uint16_t id = ((uint16_t)query_[0] << 8) | query_[1];
    if (query_[2] & 0x80) return false;  // not a query, ignore
    uint8_t opcode = (query_[2] >> 3) & 0x0F;
    uint16_t qdcount = ((uint16_t)query_[4] << 8) | query_[5];

    if (opcode != 0) return sendReply(client, id, RCODE_NOTIMP, 0, 0, nullptr, 0, 0);
    if (qdcount != 1) return sendReply(client, id, RCODE_FORMERR, 0, 0, nullptr, 0, 0);

    char name[Cache::kMaxNameLen];
    uint16_t qtype = 0;
    size_t qEnd = 0;
    if (!parseQuestion(msgLen, name, sizeof(name), qtype, qEnd)) {
      return sendReply(client, id, RCODE_FORMERR, 0, 0, nullptr, 0, 0);
    }
    size_t questionLen = qEnd - 12;

    if (qtype != kTypeA && qtype != kTypeAAAA) {
      return sendReply(client, id, RCODE_NOTIMP, questionLen, qtype, nullptr, 0, 0);
    }

    // Static host table: authoritative, bypasses cache and upstream
    const TinyDNSHost *host = findHost(name);
    if (host) {
      if (qtype == kTypeA) {
        uint8_t ip4[4] = {host->ip[0], host->ip[1], host->ip[2], host->ip[3]};
        return sendReply(client, id, RCODE_OK, questionLen, qtype, ip4, 4, maxTtl_);
      }
      // Host exists but has no IPv6 address: NODATA (NOERROR, no answer)
      return sendReply(client, id, RCODE_OK, questionLen, qtype, nullptr, 0, 0);
    }

    // Cache lookup
    uint32_t now = millis();
    const Cache::Entry *e = cache_.get(name, qtype, now);
    if (e) {
      hits_++;
      uint32_t remaining = (uint32_t)(e->expiresMs - now) / 1000UL;
      return sendReply(client, id, RCODE_OK, questionLen, qtype, e->rdata,
                       e->rdlen, remaining);
    }

    // Cache miss: ask upstream
    misses_++;
    uint8_t rdata[16];
    uint8_t rdlen = 0;
    bool ok = false;
    if (qtype == kTypeA) {
      IPAddress ip;
      ok = upstream_.resolve(name, ip);
      if (ok) {
        for (int k = 0; k < 4; k++) rdata[k] = ip[k];
        rdlen = 4;
      }
    } else {
      ok = upstream_.resolveV6(name, rdata);
      if (ok) rdlen = 16;
    }

    if (!ok) {
      uint8_t rcode = upstream_.lastResult() == DNSResult::NotFound
                          ? RCODE_NXDOMAIN
                          : RCODE_SERVFAIL;
      return sendReply(client, id, rcode, questionLen, qtype, nullptr, 0, 0);
    }

    uint32_t ttl = upstream_.lastTtl();
    if (ttl > maxTtl_) ttl = maxTtl_;
    if (ttl > 0) {
      cache_.put(name, qtype, rdata, rdlen, millis() + ttl * 1000UL);
    }
    return sendReply(client, id, RCODE_OK, questionLen, qtype, rdata, rdlen, ttl);
  }

 protected:
  static const uint16_t kTypeA = 1;      ///< DNS QTYPE for A records.
  static const uint16_t kTypeAAAA = 28;  ///< DNS QTYPE for AAAA records.

  static const uint8_t RCODE_OK = 0;
  static const uint8_t RCODE_FORMERR = 1;
  static const uint8_t RCODE_SERVFAIL = 2;
  static const uint8_t RCODE_NXDOMAIN = 3;
  static const uint8_t RCODE_NOTIMP = 4;

  TinyDNSClient &upstream_;
  Cache cache_;
  const TinyDNSHost *hosts_ = nullptr;
  size_t hostCount_ = 0;
  uint32_t timeoutMs_ = TINY_DNS_DEFAULT_TIMEOUT_MS;
  uint32_t maxTtl_ = TINY_DNS_MAX_TTL;
  uint32_t hits_ = 0;
  uint32_t misses_ = 0;
  uint8_t query_[TINY_DNS_MAX_PACKET_SIZE];  ///< Incoming query buffer.
  uint8_t reply_[TINY_DNS_MAX_PACKET_SIZE];  ///< Outgoing response buffer.

  /**
   * @brief Find a static host entry by name (case-insensitive).
   * @return Pointer to the matching entry, or nullptr.
   */
  const TinyDNSHost *findHost(const char *name) const {
    if (!hosts_) return nullptr;
    for (size_t i = 0; i < hostCount_; i++) {
      const char *a = hosts_[i].name;
      const char *b = name;
      if (!a) continue;
      while (*a && *b && lowerChar(*a) == lowerChar(*b)) {
        a++;
        b++;
      }
      if (*a == 0 && *b == 0) return &hosts_[i];
    }
    return nullptr;
  }

  static char lowerChar(char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

  /**
   * @brief Block until @p n bytes are read or the deadline passes.
   */
  static bool readExact(Client &client, uint8_t *dst, size_t n, uint32_t deadline) {
    size_t got = 0;
    while (got < n) {
      int avail = client.available();
      if (avail > 0) {
        int r = client.read(dst + got, n - got);
        if (r > 0) got += r;
      } else if (!client.connected()) {
        return false;
      }
      if (got < n && (int32_t)(millis() - deadline) >= 0) return false;
    }
    return true;
  }

  /**
   * @brief Decode the single question of the query in query_.
   * @param msgLen Length of the query message.
   * @param name Receives the dotted, NUL-terminated hostname.
   * @param nameCap Capacity of @p name.
   * @param qtype Receives the QTYPE.
   * @param qEnd Receives the offset just past the question.
   * @return true on success.
   */
  bool parseQuestion(size_t msgLen, char *name, size_t nameCap, uint16_t &qtype,
                     size_t &qEnd) const {
    size_t pos = 12;
    size_t nlen = 0;
    while (true) {
      if (pos >= msgLen) return false;
      uint8_t l = query_[pos];
      if (l == 0) {
        pos++;
        break;
      }
      if ((l & 0xC0) || l > 63) return false;  // compression not expected here
      if (pos + 1 + l > msgLen) return false;
      if (nlen + l + 1 >= nameCap) return false;
      if (nlen > 0) name[nlen++] = '.';
      memcpy(name + nlen, query_ + pos + 1, l);
      nlen += l;
      pos += 1 + l;
    }
    if (nlen == 0) return false;
    name[nlen] = 0;
    if (pos + 4 > msgLen) return false;
    qtype = ((uint16_t)query_[pos] << 8) | query_[pos + 1];
    qEnd = pos + 4;
    return true;
  }

  /**
   * @brief Build and send a TCP-framed response.
   * @param questionLen Bytes of question to echo from query_ (0 = none).
   * @param rdata Answer RDATA, or nullptr for no answer section.
   * @return true if all bytes were written.
   */
  bool sendReply(Client &client, uint16_t id, uint8_t rcode, size_t questionLen,
                 uint16_t qtype, const uint8_t *rdata, uint8_t rdlen,
                 uint32_t ttl) {
    bool hasAnswer = questionLen > 0 && rdata != nullptr && rdlen > 0;
    size_t pos = 0;

    reply_[pos++] = id >> 8;
    reply_[pos++] = id & 0xFF;
    reply_[pos++] = 0x81;                    // QR=1 (response), RD=1
    reply_[pos++] = 0x80 | (rcode & 0x0F);   // RA=1, RCODE
    reply_[pos++] = 0x00;
    reply_[pos++] = questionLen > 0 ? 1 : 0;  // QDCOUNT
    reply_[pos++] = 0x00;
    reply_[pos++] = hasAnswer ? 1 : 0;        // ANCOUNT
    reply_[pos++] = 0x00;
    reply_[pos++] = 0x00;                    // NSCOUNT
    reply_[pos++] = 0x00;
    reply_[pos++] = 0x00;                    // ARCOUNT

    if (questionLen > 0) {
      memcpy(reply_ + pos, query_ + 12, questionLen);
      pos += questionLen;
    }

    if (hasAnswer) {
      reply_[pos++] = 0xC0;  // name: pointer to question at offset 12
      reply_[pos++] = 0x0C;
      reply_[pos++] = qtype >> 8;
      reply_[pos++] = qtype & 0xFF;
      reply_[pos++] = 0x00;  // CLASS = IN
      reply_[pos++] = 0x01;
      reply_[pos++] = (uint8_t)(ttl >> 24);
      reply_[pos++] = (uint8_t)(ttl >> 16);
      reply_[pos++] = (uint8_t)(ttl >> 8);
      reply_[pos++] = (uint8_t)(ttl & 0xFF);
      reply_[pos++] = 0x00;  // RDLENGTH
      reply_[pos++] = rdlen;
      memcpy(reply_ + pos, rdata, rdlen);
      pos += rdlen;
    }

    uint8_t lenPrefix[2] = {(uint8_t)(pos >> 8), (uint8_t)(pos & 0xFF)};
    size_t written = client.write(lenPrefix, 2);
    written += client.write(reply_, pos);
    client.flush();
    return written == pos + 2;
  }
};
