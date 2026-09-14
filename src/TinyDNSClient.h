/**
 * @file TinyDNSClient.h
 * @brief Header-only DNS-over-TCP/TLS resolver for Arduino.
 *
 * Resolves hostnames by speaking DNS over a stream Client (RFC 1035
 * section 4.2.2 TCP framing: each DNS message is prefixed by a 2-byte
 * big-endian length). Because it only relies on the generic Arduino
 * Client interface, it works with any Client implementation:
 * WiFiClient/EthernetClient (plain DNS-over-TCP, port 53) or
 * WiFiClientSecure (DNS-over-TLS, port 853) against a resolver that
 * supports it (e.g. 1.1.1.1:853, 8.8.8.8:853).
 *
 * @code
 * WiFiClient net;
 * DNSResolver dns(net, IPAddress(1, 1, 1, 1));
 * IPAddress ip;
 * if (dns.resolve("example.com", ip)) { ... }
 * @endcode
 *
 * @author Phil Schatzmann
 */
#pragma once

#include <Arduino.h>
#include <Client.h>
#include <IPAddress.h>
#include <string.h>

#ifndef TINY_DNS_MAX_PACKET_SIZE
#define TINY_DNS_MAX_PACKET_SIZE 512
#endif

#ifndef TINY_DNS_DEFAULT_TIMEOUT_MS
#define TINY_DNS_DEFAULT_TIMEOUT_MS 5000
#endif

/**
 * @brief Outcome of the most recent DNSResolver query, retrievable via
 * DNSResolver::lastResult().
 */
enum class DNSResult : uint8_t {
  Ok = 0,           ///< Query succeeded and a matching record was found.
  NotConfigured,    ///< begin() was never called, or hostname was null.
  ConnectFailed,    ///< Client::connect() to the DNS server failed.
  SendFailed,       ///< Writing the query to the Client failed.
  Timeout,          ///< No complete response was received in time.
  InvalidResponse,  ///< The response was malformed or the framing was invalid.
  ServerError,      ///< The server replied with a non-zero RCODE.
  NotFound,         ///< The response contained no matching A/AAAA record.
};

/**
 * @brief Header-only DNS resolver that queries over a generic Arduino
 * Client rather than UDP.
 *
 * DNSResolver speaks DNS-over-TCP framing (RFC 1035 section 4.2.2) on
 * top of whatever Client implementation is supplied, so it works with
 * WiFiClient/EthernetClient (plain DNS-over-TCP, port 53) as well as
 * WiFiClientSecure (DNS-over-TLS, port 853). Each call to resolve() /
 * resolveV6() connects, sends one query, reads the response, and
 * disconnects again, so the Client can be reused for other purposes
 * between calls.
 */
class DNSResolver {
 public:
  /** @brief Construct an unconfigured resolver; call begin() before use. */
  DNSResolver() = default;

  /**
   * @brief Construct and configure a resolver in one step.
   * @param client Stream Client used to talk to the DNS server (e.g.
   * WiFiClient, EthernetClient, WiFiClientSecure). Must outlive this
   * resolver.
   * @param server IP address of the DNS server.
   * @param port TCP port of the DNS server (53 for plain DNS, 853 for
   * DNS-over-TLS).
   */
  DNSResolver(Client &client, IPAddress server, uint16_t port = 53) {
    begin(client, server, port);
  }

  /**
   * @brief Bind the resolver to a Client and DNS server.
   *
   * The Client is only connected for the duration of a resolve() call
   * and stopped afterwards, so it may be reused for other purposes in
   * between.
   * @param client Stream Client used to talk to the DNS server. Must
   * outlive this resolver.
   * @param server IP address of the DNS server.
   * @param port TCP port of the DNS server (53 for plain DNS, 853 for
   * DNS-over-TLS).
   */
  void begin(Client &client, IPAddress server, uint16_t port = 53) {
    client_ = &client;
    server_ = server;
    port_ = port;
  }

  /**
   * @brief Set the timeout applied to each resolve()/resolveV6() call.
   * @param timeoutMs Maximum time, in milliseconds, to wait for a
   * complete response before failing with DNSResult::Timeout.
   */
  void setTimeout(uint32_t timeoutMs) { timeoutMs_ = timeoutMs; }

  /**
   * @brief Resolve a hostname to an IPv4 (A) address.
   * @param hostname Null-terminated hostname to resolve.
   * @param result Set to the resolved address on success; left
   * unmodified on failure.
   * @return true if an A record was found and @p result was set, false
   * otherwise (see lastResult() for the reason).
   */
  bool resolve(const char *hostname, IPAddress &result) {
    uint8_t rdata[4];
    if (!resolveType(hostname, kTypeA, rdata, sizeof(rdata))) return false;
    result = IPAddress(rdata[0], rdata[1], rdata[2], rdata[3]);
    return true;
  }

  /**
   * @brief Resolve a hostname to an IPv6 (AAAA) address.
   *
   * The address is returned as 16 raw bytes (network byte order)
   * rather than via IPAddress, since IPv6 support in IPAddress differs
   * across Arduino cores.
   * @param hostname Null-terminated hostname to resolve.
   * @param result Buffer of 16 bytes, filled with the resolved address
   * on success; left unmodified on failure.
   * @return true if an AAAA record was found and @p result was filled,
   * false otherwise (see lastResult() for the reason).
   */
  bool resolveV6(const char *hostname, uint8_t result[16]) {
    return resolveType(hostname, kTypeAAAA, result, 16);
  }

  /**
   * @brief Resolve the hostname embedded in a URL (or a bare hostname)
   * in place, replacing it with its resolved IPv4 address.
   *
   * Recognizes an optional "scheme://" prefix and an optional
   * ":port" or "/path" suffix; only the hostname portion between them
   * is replaced, everything else is left untouched. For example
   * "http://example.com:8080/foo" becomes
   * "http://93.184.216.34:8080/foo".
   * @param io String holding a hostname or URL; rewritten in place on
   * success, left unmodified on failure.
   * @return true if the hostname resolved successfully and @p io was
   * updated, false otherwise (see lastResult() for the reason).
   */
  bool resolve(String &io) {
    size_t hostStart = 0;
    int schemeEnd = io.indexOf("://");
    if (schemeEnd >= 0) hostStart = (size_t)schemeEnd + 3;

    size_t hostEnd = io.length();
    int slashIdx = io.indexOf('/', hostStart);
    int colonIdx = io.indexOf(':', hostStart);
    if (slashIdx >= 0 && (size_t)slashIdx < hostEnd) hostEnd = (size_t)slashIdx;
    if (colonIdx >= 0 && (size_t)colonIdx < hostEnd) hostEnd = (size_t)colonIdx;

    if (hostEnd <= hostStart) return fail(DNSResult::NotConfigured);

    String hostname = io.substring(hostStart, hostEnd);
    IPAddress ip;
    if (!resolve(hostname.c_str(), ip)) return false;

    io = io.substring(0, hostStart) + ip.toString() + io.substring(hostEnd);
    return true;
  }

  /**
   * @brief Get the outcome of the most recent resolve()/resolveV6() call.
   * @return The DNSResult describing success or the reason for failure.
   */
  DNSResult lastResult() const { return lastResult_; }

 protected:
  static const uint16_t kTypeA = 1;      ///< DNS QTYPE/RTYPE for A records.
  static const uint16_t kTypeAAAA = 28;  ///< DNS QTYPE/RTYPE for AAAA records.

  Client *client_ = nullptr;    ///< Client used to reach the DNS server.
  IPAddress server_;            ///< DNS server address, set via begin().
  uint16_t port_ = 53;          ///< DNS server port, set via begin().
  uint32_t timeoutMs_ = TINY_DNS_DEFAULT_TIMEOUT_MS;  ///< Per-query timeout.
  uint16_t nextId_ = 1;         ///< Next DNS transaction ID to use.
  uint8_t buffer_[TINY_DNS_MAX_PACKET_SIZE];  ///< Scratch query/response buffer.
  DNSResult lastResult_ = DNSResult::Ok;      ///< Outcome of the last query.

  /**
   * @brief Record a failure outcome.
   * @param r Result code to store for lastResult().
   * @return Always false, so this can be used as `return fail(...)`.
   */
  bool fail(DNSResult r) {
    lastResult_ = r;
    return false;
  }

  /**
   * @brief Run one full query/response cycle for a given record type.
   * @param hostname Null-terminated hostname to resolve.
   * @param qtype DNS QTYPE to query (kTypeA or kTypeAAAA).
   * @param rdataOut Buffer to receive the matching record's raw RDATA.
   * @param rdataLen Expected RDATA length (4 for A, 16 for AAAA); also
   * used to match the correct answer record.
   * @return true on success with @p rdataOut filled, false on failure.
   */
  bool resolveType(const char *hostname, uint16_t qtype, uint8_t *rdataOut,
                    size_t rdataLen) {
    if (!client_ || !hostname) return fail(DNSResult::NotConfigured);

    if (!client_->connect(server_, port_)) return fail(DNSResult::ConnectFailed);

    uint16_t id = nextId_++;
    size_t len = buildQuery(buffer_, sizeof(buffer_), id, hostname, qtype);
    if (len == 0) {
      client_->stop();
      return fail(DNSResult::InvalidResponse);
    }

    uint8_t lenPrefix[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    size_t written = client_->write(lenPrefix, 2);
    written += client_->write(buffer_, len);
    if (written != len + 2) {
      client_->stop();
      return fail(DNSResult::SendFailed);
    }

    bool ok = readAndParse(id, qtype, rdataOut, rdataLen);
    client_->stop();
    return ok;
  }

  /**
   * @brief Encode a single-question DNS query message (no TCP length
   * prefix).
   * @param buf Destination buffer.
   * @param bufSize Capacity of @p buf.
   * @param id Transaction ID to embed in the header.
   * @param hostname Null-terminated hostname to encode as QNAME.
   * @param qtype QTYPE to encode (kTypeA or kTypeAAAA).
   * @return Number of bytes written, or 0 if @p buf was too small or
   * @p hostname contained an invalid label.
   */
  size_t buildQuery(uint8_t *buf, size_t bufSize, uint16_t id,
                     const char *hostname, uint16_t qtype) {
    size_t pos = 0;
    if (bufSize < 12) return 0;

    buf[pos++] = id >> 8;
    buf[pos++] = id & 0xFF;
    buf[pos++] = 0x01;  // flags hi: recursion desired
    buf[pos++] = 0x00;  // flags lo
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;  // QDCOUNT = 1
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;  // ANCOUNT
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;  // NSCOUNT
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;  // ARCOUNT

    const char *label = hostname;
    while (*label) {
      const char *dot = strchr(label, '.');
      size_t labelLen = dot ? (size_t)(dot - label) : strlen(label);
      if (labelLen == 0 || labelLen > 63) return 0;
      if (pos + labelLen + 1 >= bufSize) return 0;
      buf[pos++] = (uint8_t)labelLen;
      memcpy(buf + pos, label, labelLen);
      pos += labelLen;
      label += labelLen;
      if (*label == '.') label++;
    }
    if (pos + 1 >= bufSize) return 0;
    buf[pos++] = 0x00;  // root label

    if (pos + 4 > bufSize) return 0;
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;  // QCLASS = IN

    return pos;
  }

  /**
   * @brief Block until exactly @p n bytes have been read from the
   * Client, or the deadline passes / the connection closes.
   * @param dst Destination buffer, must hold at least @p n bytes.
   * @param n Number of bytes to read.
   * @param deadline Absolute millis() timestamp to stop waiting at.
   * @return true if all @p n bytes were read, false on timeout or if
   * the connection closed early.
   */
  bool readExact(uint8_t *dst, size_t n, uint32_t deadline) {
    size_t got = 0;
    while (got < n) {
      int avail = client_->available();
      if (avail > 0) {
        int r = client_->read(dst + got, n - got);
        if (r > 0) got += r;
      } else if (!client_->connected() && client_->available() == 0) {
        return false;
      }
      if (got < n && (int32_t)(millis() - deadline) >= 0) return false;
    }
    return true;
  }

  /**
   * @brief Read the TCP-framed DNS response and parse it.
   * @param expectedId Transaction ID the response must match.
   * @param qtype QTYPE that was queried (kTypeA or kTypeAAAA).
   * @param rdataOut Buffer to receive the matching record's raw RDATA.
   * @param rdataLen Expected RDATA length, used to match the answer.
   * @return true on success with @p rdataOut filled, false on failure.
   */
  bool readAndParse(uint16_t expectedId, uint16_t qtype, uint8_t *rdataOut,
                     size_t rdataLen) {
    uint32_t deadline = millis() + timeoutMs_;

    uint8_t lenPrefix[2];
    if (!readExact(lenPrefix, 2, deadline)) return fail(DNSResult::Timeout);
    uint16_t msgLen = ((uint16_t)lenPrefix[0] << 8) | lenPrefix[1];
    if (msgLen == 0 || msgLen > sizeof(buffer_)) {
      return fail(DNSResult::InvalidResponse);
    }
    if (!readExact(buffer_, msgLen, deadline)) return fail(DNSResult::Timeout);

    return parseResponse(buffer_, msgLen, expectedId, qtype, rdataOut, rdataLen);
  }

  /**
   * @brief Advance past one encoded DNS name (label sequence or
   * compression pointer), without decoding it.
   * @param buf Message buffer.
   * @param len Length of @p buf.
   * @param pos Offset of the name within @p buf.
   * @return Offset of the first byte following the name.
   */
  static size_t skipName(const uint8_t *buf, size_t len, size_t pos) {
    while (pos < len) {
      uint8_t l = buf[pos];
      if (l == 0) return pos + 1;
      if ((l & 0xC0) == 0xC0) return pos + 2;  // compressed pointer
      pos += 1 + l;
    }
    return pos;
  }

  /**
   * @brief Parse a decoded DNS message and extract the first answer
   * record matching @p qtype and @p rdataLen.
   * @param buf Decoded DNS message (no TCP length prefix).
   * @param len Length of @p buf.
   * @param expectedId Transaction ID the message must match.
   * @param qtype QTYPE that was queried (kTypeA or kTypeAAAA).
   * @param rdataOut Buffer to receive the matching record's raw RDATA.
   * @param rdataLen Expected RDATA length, used to match the answer.
   * @return true on success with @p rdataOut filled, false on failure
   * (mismatched ID, error RCODE, malformed message, or no match).
   */
  bool parseResponse(const uint8_t *buf, size_t len, uint16_t expectedId,
                      uint16_t qtype, uint8_t *rdataOut, size_t rdataLen) {
    if (len < 12) return fail(DNSResult::InvalidResponse);

    uint16_t id = ((uint16_t)buf[0] << 8) | buf[1];
    if (id != expectedId) return fail(DNSResult::InvalidResponse);
    if ((buf[2] & 0x80) == 0) return fail(DNSResult::InvalidResponse);  // not a reply
    if ((buf[3] & 0x0F) != 0) return fail(DNSResult::ServerError);      // RCODE != 0

    uint16_t qdcount = ((uint16_t)buf[4] << 8) | buf[5];
    uint16_t ancount = ((uint16_t)buf[6] << 8) | buf[7];

    size_t pos = 12;
    for (uint16_t i = 0; i < qdcount; i++) {
      pos = skipName(buf, len, pos);
      pos += 4;  // QTYPE + QCLASS
      if (pos > len) return fail(DNSResult::InvalidResponse);
    }

    for (uint16_t i = 0; i < ancount; i++) {
      pos = skipName(buf, len, pos);
      if (pos + 10 > len) return fail(DNSResult::InvalidResponse);

      uint16_t rtype = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
      pos += 8;  // TYPE(2) + CLASS(2) + TTL(4)
      uint16_t rdlen = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
      pos += 2;
      if (pos + rdlen > len) return fail(DNSResult::InvalidResponse);

      if (rtype == qtype && rdlen == rdataLen) {
        memcpy(rdataOut, buf + pos, rdataLen);
        lastResult_ = DNSResult::Ok;
        return true;
      }
      pos += rdlen;
    }

    return fail(DNSResult::NotFound);
  }
};
