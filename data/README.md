# Data

## hagezi-pro.txt.gz

Gzip-compressed copy of HaGeZi's Multi PRO blocklist, AdBlock syntax
(`||domain^`), version 2026.1117.2333.07 (about 252k domains). The file is
the input for building the ad blocker example. The library does not read
gzip itself.

- Source: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt
- Project: https://github.com/hagezi/dns-blocklists
- License: GNU GPL v3 (https://github.com/hagezi/dns-blocklists/blob/main/LICENSE).
  This file is GPL-3 licensed, not MIT like the rest of this library.

## Generating a blocklist

The generator reads the gzip file directly and writes a Huffman-coded store
(about 1.8 MB for this list, roughly 7 bytes per domain):

```bash
python3 tools/gen_huffman_blocklist.py data/hagezi-pro.txt.gz \
    -o examples/AdBlocker/blocklist_data.h --name adblock_store --format incbin
```

The generated files are stored in `examples/AdBlocker/` and are used by the
sketch. Loading the same list as plain text into RAM (`TinyDNSBlocklist`)
needs roughly 14 MB of RAM, so use the flash store on microcontrollers.
