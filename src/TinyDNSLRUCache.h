/**
 * @file TinyDNSLRUCache.h
 * @brief LRU cache for DNS records with a runtime capacity, optionally
 * placed in PSRAM.
 *
 * Entries are keyed by (name, qtype). Names are compared
 * case-insensitively and stored lower-cased. When the cache is full,
 * the least recently used entry is evicted. Entries carry an absolute
 * expiry time in millis(), and expired entries are dropped on lookup.
 *
 * The entry table is allocated by begin(), not by the constructor, so
 * that PSRAM setup can run first. Memory placement:
 * - ESP32 with BOARD_HAS_PSRAM: heap_caps_calloc(MALLOC_CAP_SPIRAM),
 *   falling back to internal RAM.
 * - RP2350 with RP2350_PSRAM_CS (arduino-pico): pmalloc(), falling back
 *   to internal RAM.
 * - Otherwise: calloc() from internal RAM.
 * Define TINY_DNS_NO_PSRAM to always use internal RAM.
 *
 * Usage:
 * @code
 * TinyDNSLRUCache cache;
 * cache.begin(32);  // in setup()
 * uint8_t addr[4] = {93, 184, 216, 34};
 * cache.put("Example.com", 1, addr, 4, millis() + 300000UL);
 * const TinyDNSLRUCache::Entry *e = cache.get("example.com", 1, millis());
 * @endcode
 *
 * @author Phil Schatzmann
 */
#pragma once

#include <Arduino.h>
#include <stdlib.h>
#include <string.h>

#ifndef TINY_DNS_CACHE_SIZE
#define TINY_DNS_CACHE_SIZE 16
#endif

// PSRAM is used on ESP32 boards built with PSRAM enabled (BOARD_HAS_PSRAM),
// and on RP2350 boards with PSRAM attached (RP2350_PSRAM_CS, arduino-pico).
// Define TINY_DNS_NO_PSRAM to force internal RAM.
#if defined(ESP32) && defined(BOARD_HAS_PSRAM) && !defined(TINY_DNS_NO_PSRAM)
#include <esp_heap_caps.h>
#define TINY_DNS_USE_PSRAM 1
#endif

#if defined(ARDUINO_ARCH_RP2040) && defined(RP2350_PSRAM_CS) && !defined(TINY_DNS_NO_PSRAM)
#define TINY_DNS_USE_PSRAM_PICO 1
#endif

/**
 * @brief Least-recently-used cache with a runtime capacity.
 *
 * Capacity is limited to kMaxCapacity (254) because LRU links are
 * stored as 8-bit slot indices. Memory use is capacity * sizeof(Entry)
 * (about 90 bytes per entry). Each put() copies the name and RDATA into
 * the table, so callers keep ownership of their buffers. The cache is
 * not thread-safe; use it from one task or loop at a time.
 */
class TinyDNSLRUCache {
 public:
  static const size_t kMaxCapacity = 254;  ///< Largest supported capacity.
  static const size_t kMaxNameLen = 64;    ///< Max stored name length incl. NUL.

  /** @brief A single cached DNS record. */
  struct Entry {
    char name[kMaxNameLen];   ///< Lower-cased, NUL-terminated hostname.
    uint16_t qtype;           ///< DNS QTYPE (1 = A, 28 = AAAA).
    uint8_t rdata[16];        ///< Raw RDATA.
    uint8_t rdlen;            ///< Length of rdata (4 or 16).
    uint32_t expiresMs;      ///< millis() timestamp at which the entry expires.
    bool used;                ///< Slot is occupied.
    uint8_t prev;             ///< Previous slot in the LRU list.
    uint8_t next;             ///< Next slot in the LRU list.
  };

  /**
   * @brief Create an unallocated cache. Call begin() before use.
   * Allocation is deferred so it runs in setup(), after the board's
   * PSRAM is initialized; allocating in a global constructor can fail.
   */
  TinyDNSLRUCache() = default;

  ~TinyDNSLRUCache() { release(); }

  TinyDNSLRUCache(const TinyDNSLRUCache &) = delete;
  TinyDNSLRUCache &operator=(const TinyDNSLRUCache &) = delete;

  /**
   * @brief Allocate the entry table. Any previous storage is released.
   * @param capacity Number of entries (1..kMaxCapacity).
   * @return true if the table was allocated. On failure the cache has
   * capacity 0 and put() returns false, get() returns nullptr.
   */
  bool begin(size_t capacity = TINY_DNS_CACHE_SIZE) {
    release();
    return allocate(capacity);
  }

  /**
   * @brief Replace the storage with a new capacity. All entries are dropped.
   * @return true if the new storage was allocated.
   */
  bool resize(size_t capacity) { return begin(capacity); }

  /** @brief Remove all entries. */
  void clear() {
    for (size_t i = 0; i < capacity_; i++) {
      entries_[i].used = false;
      entries_[i].prev = NONE;
      entries_[i].next = NONE;
    }
    head_ = NONE;
    tail_ = NONE;
    count_ = 0;
  }

  /** @brief Number of entries currently stored. */
  size_t size() const { return count_; }

  /** @brief Maximum number of entries. */
  size_t capacity() const { return capacity_; }

  /**
   * @brief Look up a record and mark it as most recently used.
   * Expired entries are removed and reported as missing.
   * @param name Hostname (case-insensitive).
   * @param qtype DNS QTYPE.
   * @param now Current millis() value.
   * @return Pointer to the entry, or nullptr on miss. The pointer is
   * valid until the next put() or get() call.
   */
  const Entry *get(const char *name, uint16_t qtype, uint32_t now) {
    int i = find(name, qtype);
    if (i < 0) return nullptr;
    if ((int32_t)(now - entries_[i].expiresMs) >= 0) {
      remove(i);
      return nullptr;
    }
    unlink(i);
    pushFront(i);
    return &entries_[i];
  }

  /**
   * @brief Insert or replace a record, evicting the LRU entry if full.
   * @param name Hostname (stored lower-cased).
   * @param qtype DNS QTYPE.
   * @param rdata Raw RDATA bytes.
   * @param rdlen Length of @p rdata (at most 16).
   * @param expiresMs millis() timestamp at which the entry expires.
   * @return true if stored, false if the arguments were invalid.
   */
  bool put(const char *name, uint16_t qtype, const uint8_t *rdata,
           uint8_t rdlen, uint32_t expiresMs) {
    if (!entries_) return false;
    size_t nlen = strlen(name);
    if (nlen == 0 || nlen >= kMaxNameLen || rdlen == 0 || rdlen > 16) {
      return false;
    }

    int i = find(name, qtype);
    if (i >= 0) {
      unlink(i);
    } else if (count_ < capacity_) {
      i = firstFree();
      count_++;
    } else {
      i = tail_;  // evict least recently used
      unlink(i);
    }

    Entry &e = entries_[i];
    for (size_t k = 0; k < nlen; k++) e.name[k] = lower(name[k]);
    e.name[nlen] = 0;
    e.qtype = qtype;
    memcpy(e.rdata, rdata, rdlen);
    e.rdlen = rdlen;
    e.expiresMs = expiresMs;
    e.used = true;
    pushFront(i);
    return true;
  }

 private:
  static const uint8_t NONE = 0xFF;

  Entry *entries_ = nullptr;  ///< Heap (or PSRAM) entry table.
  size_t capacity_ = 0;       ///< Number of slots in entries_.
  uint8_t head_ = NONE;       ///< Most recently used slot.
  uint8_t tail_ = NONE;       ///< Least recently used slot.
  size_t count_ = 0;

  bool allocate(size_t capacity) {
    if (capacity == 0 || capacity > kMaxCapacity) return false;
    entries_ = static_cast<Entry *>(allocRaw(capacity * sizeof(Entry)));
    if (!entries_) return false;
    capacity_ = capacity;
    head_ = NONE;
    tail_ = NONE;
    count_ = 0;
    clear();
    return true;
  }

  void release() {
    freeRaw(entries_);
    entries_ = nullptr;
    capacity_ = 0;
    head_ = NONE;
    tail_ = NONE;
    count_ = 0;
  }

  static void *allocRaw(size_t bytes) {
#if defined(TINY_DNS_USE_PSRAM)
    void *p = heap_caps_calloc(1, bytes, MALLOC_CAP_SPIRAM);
    if (p) return p;  // PSRAM, falls through to internal RAM if unavailable
#elif defined(TINY_DNS_USE_PSRAM_PICO)
    // arduino-pico: pmalloc() allocates from PSRAM; release with free().
    void *p = pmalloc(bytes);
    if (p) {
      memset(p, 0, bytes);
      return p;
    }
#endif
    return calloc(1, bytes);
  }

  static void freeRaw(void *p) {
#if defined(TINY_DNS_USE_PSRAM)
    heap_caps_free(p);
#else
    free(p);  // also correct for pmalloc() blocks on arduino-pico
#endif
  }

  static char lower(char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

  static bool equalsNoCase(const char *stored, const char *name) {
    while (*stored && *name) {
      if (*stored != lower(*name)) return false;
      stored++;
      name++;
    }
    return *stored == 0 && *name == 0;
  }

  int find(const char *name, uint16_t qtype) const {
    for (size_t i = 0; i < capacity_; i++) {
      if (entries_[i].used && entries_[i].qtype == qtype &&
          equalsNoCase(entries_[i].name, name)) {
        return (int)i;
      }
    }
    return -1;
  }

  int firstFree() const {
    for (size_t i = 0; i < capacity_; i++) {
      if (!entries_[i].used) return (int)i;
    }
    return -1;
  }

  void remove(int i) {
    unlink(i);
    entries_[i].used = false;
    count_--;
  }

  void unlink(int i) {
    Entry &e = entries_[i];
    if (e.prev != NONE) {
      entries_[e.prev].next = e.next;
    } else {
      head_ = e.next;
    }
    if (e.next != NONE) {
      entries_[e.next].prev = e.prev;
    } else {
      tail_ = e.prev;
    }
    e.prev = NONE;
    e.next = NONE;
  }

  void pushFront(int i) {
    Entry &e = entries_[i];
    e.prev = NONE;
    e.next = head_;
    if (head_ != NONE) entries_[head_].prev = (uint8_t)i;
    head_ = (uint8_t)i;
    if (tail_ == NONE) tail_ = (uint8_t)i;
  }
};
