/**
 * @file TinyDNSHuffmanStore.h
 * @brief Read-only, Huffman-coded set of blocked domains, stored in PROGMEM.
 *
 * The data is produced by tools/gen_huffman_blocklist.py. Format (version 1):
 *
 * - Domains are reversed label by label ("ads.example.com" becomes
 *   "com.example.ads"), sorted, and front-coded. Each record is a shared
 *   prefix length (0..255) and the remaining bytes, followed by a 0 byte.
 * - Every blockSize-th record is a restart point with shared length 0, so
 *   each block can be decoded without reading the records before it.
 * - Two bit streams, MSB first: the shared lengths ("prefix stream") and
 *   the record bytes ("suffix stream"). Each stream has its own canonical
 *   Huffman code, given as 256 code lengths (0 = unused symbol, max 15).
 * - The block index holds, per block, the bit offset of the block's first
 *   record in each stream as two big-endian uint32 values (8 bytes/block).
 *
 * Lookup: a binary search over the blocks decodes each block's first domain,
 * then the matching block is decoded record by record. Memory in RAM is the
 * two decode tables (about 0.6 KB) plus a few small buffers on the stack.
 *
 * Generate the store with tools/gen_huffman_blocklist.py. With
 * --format incbin the tables are binary files next to the header, embedded
 * with .incbin (GCC-based cores only). With --format carray they are C arrays.
 *
 * Usage:
 * @code
 * #include "blocklist_data.h"  // generated; defines adblock_store (PROGMEM)
 * TinyDNSHuffmanStore store(adblock_store);
 * store.begin();
 * bool blocked = store.contains("tracker.example.com");
 * @endcode
 *
 * @author Phil Schatzmann
 */
#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <string.h>

#if defined(__AVR__)
#include <avr/pgmspace.h>
#define TINY_DNS_PGM_READ8(addr) pgm_read_byte(addr)
#else
// On ESP32, RP2040, SAMD and similar cores, const data is read directly.
#define TINY_DNS_PGM_READ8(addr) (*(addr))
#endif

/**
 * @brief Description of one Huffman-coded store. Usually a generated
 * `static const` object, so all pointers refer to PROGMEM data.
 */
struct TinyDNSHuffmanStoreData {
  uint32_t count;              ///< Number of domains in the store.
  uint16_t blockSize;          ///< Records per restart block (> 0).
  uint32_t blockCount;         ///< ceil(count / blockSize).
  const uint8_t *prefixLens;   ///< 256 code lengths, shared-length alphabet.
  const uint8_t *suffixLens;   ///< 256 code lengths, byte alphabet.
  const uint8_t *index;        ///< blockCount * 8 bytes (see format above).
  const uint8_t *prefixBits;   ///< Prefix stream.
  uint32_t prefixBitCount;     ///< Valid bits in prefixBits.
  const uint8_t *suffixBits;   ///< Suffix stream.
  uint32_t suffixBitCount;     ///< Valid bits in suffixBits.
};

/**
 * @brief Exact-match lookup over a Huffman-coded domain store.
 *
 * The store is read-only and does not copy the data. It must outlive any
 * TinyDNSBlocklist that uses it.
 */
class TinyDNSHuffmanStore {
 public:
  /** @brief Longest domain name stored, including the terminating NUL. */
  static const size_t kMaxKeyLen = 254;

  explicit TinyDNSHuffmanStore(const TinyDNSHuffmanStoreData &data)
      : d_(data) {}

  /**
   * @brief Build the decode tables from the code lengths. Call once, from
   * setup(). Also checks the layout fields.
   * @return true if the store is usable.
   */
  bool begin() {
    ready_ = d_.blockSize > 0 && d_.count > 0 && d_.prefixLens && d_.suffixLens &&
             d_.index && d_.prefixBits && d_.suffixBits &&
             d_.blockCount == (d_.count + d_.blockSize - 1) / d_.blockSize &&
             buildTable(d_.prefixLens, prefix_) && buildTable(d_.suffixLens, suffix_);
    return ready_;
  }

  /** @brief True after a successful begin(). */
  bool ready() const { return ready_; }

  /** @brief Number of domains in the store. */
  uint32_t count() const { return d_.count; }

  /**
   * @brief Check whether @p domain is in the store (exact match, no suffix
   * walk). Case-insensitive; a trailing dot is ignored.
   * @return true if the domain is stored, false otherwise or on bad data.
   */
  bool contains(const char *domain) const {
    if (!ready_ || !domain) return false;
    char key[kMaxKeyLen];
    size_t keyLen = 0;
    if (!reverseKey(domain, key, sizeof(key), keyLen)) return false;

    // Find the number of blocks whose first key is <= key.
    uint32_t lo = 0, hi = d_.blockCount;
    char first[kMaxKeyLen];
    while (lo < hi) {
      uint32_t mid = lo + (hi - lo) / 2;
      size_t firstLen = 0;
      if (!firstKey(mid, first, sizeof(first), firstLen)) return false;
      if (strcmp(first, key) <= 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    if (lo == 0) return false;  // key sorts before the first domain

    // Scan the one block that can contain key.
    uint32_t block = lo - 1;
    Cursor cur = cursorFor(block);
    uint32_t remaining = recordsInBlock(block);
    char candidate[kMaxKeyLen];
    size_t candLen = 0;
    for (uint32_t i = 0; i < remaining; i++) {
      if (!nextKey(cur, candidate, sizeof(candidate), candLen)) return false;
      int cmp = strcmp(candidate, key);
      if (cmp == 0) return true;
      if (cmp > 0) return false;
    }
    return false;
  }

 protected:
  static const uint8_t kMaxCodeLen = 15;

  /** Canonical Huffman decode table: symbols sorted by (length, value). */
  struct Table {
    uint16_t count[kMaxCodeLen + 1];
    uint8_t symbol[256];
  };

  /** MSB-first bit reader over PROGMEM bytes. */
  struct BitReader {
    const uint8_t *data;
    uint32_t bitPos;
    uint32_t bitCount;
    bool error;

    int readBit() {
      if (bitPos >= bitCount) {
        error = true;
        return 0;
      }
      uint8_t byte = TINY_DNS_PGM_READ8(data + (bitPos >> 3));
      int b = (byte >> (7 - (bitPos & 7))) & 1;
      bitPos++;
      return b;
    }
  };

  struct Cursor {
    BitReader prefix;
    BitReader suffix;
  };

  TinyDNSHuffmanStoreData d_;
  Table prefix_;
  Table suffix_;
  bool ready_ = false;

  static uint32_t readBE32(const uint8_t *p) {
    return ((uint32_t)TINY_DNS_PGM_READ8(p) << 24) |
           ((uint32_t)TINY_DNS_PGM_READ8(p + 1) << 16) |
           ((uint32_t)TINY_DNS_PGM_READ8(p + 2) << 8) |
           (uint32_t)TINY_DNS_PGM_READ8(p + 3);
  }

  uint32_t recordsInBlock(uint32_t block) const {
    uint32_t start = block * (uint32_t)d_.blockSize;
    uint32_t left = d_.count - start;
    return left < d_.blockSize ? left : d_.blockSize;
  }

  /** Read code lengths from PROGMEM and build the canonical decode table. */
  bool buildTable(const uint8_t *lens, Table &t) const {
    memset(t.count, 0, sizeof(t.count));
    uint32_t used = 0;
    for (int sym = 0; sym < 256; sym++) {
      uint8_t len = TINY_DNS_PGM_READ8(lens + sym);
      if (len > kMaxCodeLen) return false;
      if (len) {
        t.count[len]++;
        used++;
      }
    }
    if (used == 0) return false;

    // Reject over-subscribed codes (Kraft sum above 1).
    int left = 1;
    for (int len = 1; len <= kMaxCodeLen; len++) {
      left <<= 1;
      left -= t.count[len];
      if (left < 0) return false;
    }

    uint16_t offs[kMaxCodeLen + 2];
    offs[1] = 0;
    for (int len = 1; len < kMaxCodeLen; len++) offs[len + 1] = offs[len] + t.count[len];
    for (int sym = 0; sym < 256; sym++) {
      uint8_t len = TINY_DNS_PGM_READ8(lens + sym);
      if (len) t.symbol[offs[len]++] = (uint8_t)sym;
    }
    return true;
  }

  /** Decode one symbol (puff-style canonical Huffman). Returns -1 on error. */
  int decodeSymbol(const Table &t, BitReader &r) const {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= kMaxCodeLen; len++) {
      code |= r.readBit();
      int count = t.count[len];
      if (code - first < count) {
        if (r.error) return -1;
        return t.symbol[index + (code - first)];
      }
      index += count;
      first += count;
      first <<= 1;
      code <<= 1;
    }
    return -1;
  }

  Cursor cursorFor(uint32_t block) const {
    const uint8_t *entry = d_.index + (size_t)block * 8;
    Cursor c;
    c.prefix = {d_.prefixBits, readBE32(entry), d_.prefixBitCount, false};
    c.suffix = {d_.suffixBits, readBE32(entry + 4), d_.suffixBitCount, false};
    return c;
  }

  /**
   * Decode the next record and apply it to @p key (length @p len).
   * Records start from a restart point, so @p key starts empty there.
   */
  bool nextKey(Cursor &c, char *key, size_t cap, size_t &len) const {
    int shared = decodeSymbol(prefix_, c.prefix);
    if (shared < 0 || (size_t)shared > len) return false;
    len = (size_t)shared;
    while (true) {
      int b = decodeSymbol(suffix_, c.suffix);
      if (b < 0) return false;
      if (b == 0) break;
      if (len + 1 >= cap) return false;
      key[len++] = (char)b;
    }
    key[len] = 0;
    return true;
  }

  bool firstKey(uint32_t block, char *key, size_t cap, size_t &len) const {
    Cursor c = cursorFor(block);
    len = 0;
    return nextKey(c, key, cap, len);
  }

  static bool isNameChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
  }

  /**
   * Turn "a.b.example.com" into "com.example.b.a" (lower case, no trailing
   * dot). Returns false for empty labels or invalid characters.
   */
  static bool reverseKey(const char *domain, char *out, size_t cap, size_t &outLen) {
    size_t n = strlen(domain);
    if (n > 0 && domain[n - 1] == '.') n--;
    if (n == 0 || n >= cap) return false;

    size_t out_pos = 0;
    size_t end = n;
    while (true) {
      size_t start = end;
      while (start > 0 && domain[start - 1] != '.') start--;
      if (start == end) return false;  // empty label
      if (out_pos > 0) out[out_pos++] = '.';
      for (size_t i = start; i < end; i++) {
        char c = domain[i];
        if (c >= 'A' && c <= 'Z') c = c + 32;
        if (!isNameChar(c)) return false;
        out[out_pos++] = c;
      }
      if (start == 0) break;
      end = start - 1;  // skip the dot
    }
    out[out_pos] = 0;
    outLen = out_pos;
    return true;
  }
};
