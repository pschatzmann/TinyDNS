/**
 * @file TinyDNSMemory.h
 * @brief Allocation helpers shared by the TinyDNS containers (LRU cache and
 * RAM blocklist). They place memory in PSRAM when the board has it.
 *
 * - ESP32 with BOARD_HAS_PSRAM: heap_caps_calloc(MALLOC_CAP_SPIRAM), falling
 *   back to internal RAM if PSRAM is unavailable.
 * - RP2350 with RP2350_PSRAM_CS (arduino-pico): pmalloc(), falling back to
 *   internal RAM.
 * - Otherwise: calloc() from internal RAM.
 *
 * Define TINY_DNS_NO_PSRAM to always use internal RAM. Allocation must happen
 * after PSRAM is initialized (in setup(), not in a global constructor).
 * Memory from tinyDnsAlloc() must be released with tinyDnsFree(); it is zeroed.
 *
 * @author Phil Schatzmann
 */
#pragma once

#include <Arduino.h>
#include <stdlib.h>
#include <string.h>

// PSRAM is used on ESP32 boards built with PSRAM enabled (BOARD_HAS_PSRAM),
// and on RP2350 boards with PSRAM attached (RP2350_PSRAM_CS, arduino-pico).
#if defined(ESP32) && defined(BOARD_HAS_PSRAM) && !defined(TINY_DNS_NO_PSRAM)
#include <esp_heap_caps.h>
#define TINY_DNS_USE_PSRAM 1
#endif

#if defined(ARDUINO_ARCH_RP2040) && defined(RP2350_PSRAM_CS) && !defined(TINY_DNS_NO_PSRAM)
#define TINY_DNS_USE_PSRAM_PICO 1
#endif

/**
 * @brief Allocate @p bytes of zeroed memory, in PSRAM when available.
 * @return Pointer to the memory, or nullptr if allocation failed.
 */
inline void *tinyDnsAlloc(size_t bytes) {
#if defined(TINY_DNS_USE_PSRAM)
  void *p = heap_caps_calloc(1, bytes, MALLOC_CAP_SPIRAM);
  if (p) return p;  // falls through to internal RAM if PSRAM is unavailable
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

/** @brief Release memory obtained from tinyDnsAlloc(). nullptr is allowed. */
inline void tinyDnsFree(void *p) {
  if (!p) return;
#if defined(TINY_DNS_USE_PSRAM)
  heap_caps_free(p);
#else
  free(p);  // also correct for pmalloc() blocks on arduino-pico
#endif
}
