/**
 * @file TinyDNS.h
 * @brief Umbrella header for the TinyDNS library.
 *
 * Includes:
 * - TinyDNSClient    (TinyDNSClient.h): DNS-over-TCP/TLS resolver client
 * - TinyDNSLRUCache  (TinyDNSLRUCache.h): fixed-size LRU cache
 * - TinyDNSServer    (TinyDNSServer.h): caching DNS-over-TCP server with
 *                    optional static host table (TinyDNSHost)
 *
 * @author Phil Schatzmann
 */
#pragma once

#include "TinyDNSClient.h"
#include "TinyDNSLRUCache.h"
#include "TinyDNSServer.h"
