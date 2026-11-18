/**
 * @file TinyDNS.h
 * @brief Umbrella header for the TinyDNS library.
 *
 * Includes:
 * - TinyDNSClient    (TinyDNSClient.h): DNS-over-TCP/TLS resolver client
 * - TinyDNSLRUCache  (TinyDNSLRUCache.h): fixed-size LRU cache
 * - TinyDNSBlocklist (TinyDNSBlocklist.h): suffix-matching blocklist and
 *                    allowlist, loadable from hosts-format files
 * - TinyDNSHuffmanStore (TinyDNSHuffmanStore.h): read-only Huffman-coded
 *                    blocklist in PROGMEM (see tools/gen_huffman_blocklist.py)
 * - TinyDNSServer    (TinyDNSServer.h): caching DNS-over-TCP server with
 *                    optional static host table (TinyDNSHost) and
 *                    blocklist sinkhole policy
 *
 * @author Phil Schatzmann
 */
#pragma once

#include "TinyDNSBlocklist.h"
#include "TinyDNSHuffmanStore.h"
#include "TinyDNSClient.h"
#include "TinyDNSLRUCache.h"
#include "TinyDNSServer.h"
