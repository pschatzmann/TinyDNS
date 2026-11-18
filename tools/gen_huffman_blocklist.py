#!/usr/bin/env python3
"""Build a Huffman-coded blocklist (TinyDNSHuffmanStore) as a C header.

Usage:
  gen_huffman_blocklist.py INPUT [-o OUT.h] [--name NAME]
                           [--block-size 32] [--emit-names]
                           [--format carray|incbin]

--format carray (default) writes all tables as C arrays in the header.
--format incbin writes the large tables as binary files next to the header,
named <header>.<table>.bin, and embeds them with an assembler .incbin
directive, so no hex text is generated. The header refers to them as
__FILE__ ".<table>.bin", so the files are found wherever the header is
compiled from and no absolute paths are stored. Keep the .bin files next to
the header. incbin works with GCC-based cores (ESP32, RP2040, SAMD, ...), not
with AVR.

INPUT (plain or .gz) holds block rules in AdBlock ("||domain^"), hosts ("0.0.0.0 domain")
or plain ("domain") format. Allow rules ("@@||...") are ignored. The rules
are normalized the same way as the C++ parser (lower case, no trailing dot,
labels of [a-z0-9_-], reserved hosts names skipped).

The output header defines `static const TinyDNSHuffmanStoreData NAME` in
PROGMEM-backed arrays. See src/TinyDNSHuffmanStore.h for the format.
"""

import argparse
import re
import sys
from collections import Counter

MAX_CODE_LEN = 15
MAX_NAME_LEN = 253
RESERVED = {
    "localhost", "localhost.localdomain", "local", "localdomain",
    "broadcasthost", "ip6-localhost", "ip6-loopback", "ip6-localnet",
    "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
}
SINKHOLES = {"0.0.0.0", "127.0.0.1", "::", "::1"}
LABEL_RE = re.compile(r"[a-z0-9_-]+")


def normalize(name):
    """Return the lower-case name, or None if it is not a valid domain."""
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > MAX_NAME_LEN:
        return None
    labels = name.lower().split(".")
    for label in labels:
        if not LABEL_RE.fullmatch(label):
            return None
    return ".".join(labels)


def is_ip_literal(token):
    if ":" in token:
        return True
    return "." in token and all(c.isdigit() or c == "." for c in token)


def parse_block_domains(lines):
    """Collect block-rule domains from AdBlock, hosts, or plain lines."""
    names = set()
    for raw in lines:
        line = raw.strip()
        if not line or line[0] in "![":
            continue
        if line.startswith("@@"):
            continue  # allow rules are not part of the blocked set
        if line.startswith("||"):
            if line.endswith("^"):
                name = normalize(line[2:-1])
                if name:
                    names.add(name)
            continue
        if "##" in line or "#@#" in line or "#?#" in line:
            continue  # cosmetic filter
        line = line.split("#", 1)[0]
        tokens = line.split()
        if not tokens:
            continue
        if is_ip_literal(tokens[0]):
            if tokens[0] not in SINKHOLES:
                continue
            tokens = tokens[1:]
        for token in tokens:
            if token.startswith("*."):
                token = token[2:]
            if token.lower() in RESERVED:
                continue
            name = normalize(token)
            if name:
                names.add(name)
    return names


def package_merge(freq, max_len):
    """Length-limited Huffman code lengths (package-merge). freq: sym->count."""
    syms = sorted(freq, key=lambda s: (freq[s], s))
    if len(syms) == 1:
        return {syms[0]: 1}
    leaves = [(freq[s], [s]) for s in syms]
    current = list(leaves)
    for _ in range(max_len - 1):
        packages = []
        for i in range(0, len(current) - 1, 2):
            packages.append((current[i][0] + current[i + 1][0],
                             current[i][1] + current[i + 1][1]))
        current = sorted(leaves + packages, key=lambda x: x[0])
    depth = {s: 0 for s in syms}
    for _, members in current[: 2 * len(syms) - 2]:
        for s in members:
            depth[s] += 1
    return depth


def canonical_codes(lengths):
    """Canonical codes (RFC 1951 style): sym -> (code, length)."""
    bl_count = [0] * (MAX_CODE_LEN + 2)
    for length in lengths.values():
        bl_count[length] += 1
    next_code = [0] * (MAX_CODE_LEN + 2)
    code = 0
    for bits in range(1, MAX_CODE_LEN + 1):
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code
    codes = {}
    for sym in sorted(lengths, key=lambda s: (lengths[s], s)):
        length = lengths[sym]
        codes[sym] = (next_code[length], length)
        next_code[length] += 1
    return codes


class BitWriter:
    def __init__(self):
        self.buf = bytearray()
        self.nbits = 0

    def put(self, value, length):
        for i in range(length - 1, -1, -1):
            if self.nbits % 8 == 0:
                self.buf.append(0)
            if (value >> i) & 1:
                self.buf[-1] |= 0x80 >> (self.nbits % 8)
            self.nbits += 1


def build_store(names, block_size):
    """Return the encoded streams and tables for the sorted, reversed names."""
    keys = sorted({".".join(reversed(n.split("."))) for n in names})
    count = len(keys)

    # Front coding with restart points (shared = 0 at each block start)
    records = []
    prev = b""
    for i, key in enumerate(keys):
        data = key.encode()
        shared = 0
        if i % block_size:
            limit = min(len(prev), len(data), 255)
            while shared < limit and prev[shared] == data[shared]:
                shared += 1
        records.append((shared, data[shared:]))
        prev = data

    prefix_freq = Counter(shared for shared, _ in records)
    suffix_freq = Counter()
    for _, suffix in records:
        suffix_freq.update(suffix)
        suffix_freq[0] += 1  # record terminator

    prefix_lens = package_merge(prefix_freq, MAX_CODE_LEN)
    suffix_lens = package_merge(suffix_freq, MAX_CODE_LEN)
    prefix_codes = canonical_codes(prefix_lens)
    suffix_codes = canonical_codes(suffix_lens)

    prefix_bits, suffix_bits = BitWriter(), BitWriter()
    index = bytearray()
    for i, (shared, suffix) in enumerate(records):
        if i % block_size == 0:
            if prefix_bits.nbits >= 2**32 or suffix_bits.nbits >= 2**32:
                raise ValueError("bit stream too large for 32-bit offsets")
            index += prefix_bits.nbits.to_bytes(4, "big")
            index += suffix_bits.nbits.to_bytes(4, "big")
        code, length = prefix_codes[shared]
        prefix_bits.put(code, length)
        for byte in suffix + b"\0":
            code, length = suffix_codes[byte]
            suffix_bits.put(code, length)

    lens_p = [prefix_lens.get(s, 0) for s in range(256)]
    lens_s = [suffix_lens.get(s, 0) for s in range(256)]
    return {
        "count": count,
        "block_size": block_size,
        "block_count": (count + block_size - 1) // block_size,
        "prefix_lens": lens_p,
        "suffix_lens": lens_s,
        "index": bytes(index),
        "prefix_bits": bytes(prefix_bits.buf),
        "prefix_bit_count": prefix_bits.nbits,
        "suffix_bits": bytes(suffix_bits.buf),
        "suffix_bit_count": suffix_bits.nbits,
        "keys": keys,
    }


def check_kraft(lengths):
    total = sum(2.0 ** -l for l in lengths if l)
    if abs(total - 1.0) > 1e-9 and sum(1 for l in lengths if l) > 1:
        raise ValueError("code is not complete (Kraft sum %f)" % total)


def c_bytes(values):
    lines = []
    for i in range(0, len(values), 16):
        lines.append("    " + ", ".join("0x%02X" % v for v in values[i:i + 16]) + ",")
    return "\n".join(lines)


INCBIN_MACRO = r"""// Embeds a binary file in the .rodata section (flash on most MCUs) and
// declares it as `extern const uint8_t sym[]`. GCC/Clang assembler syntax.
#define TINY_DNS_INCBIN(sym, file)                                      \
  __asm__(".section .rodata\n"                                          \
          ".balign 4\n"                                                 \
          ".global " #sym "\n"                                          \
          #sym ":\n"                                                    \
          ".incbin \"" file "\"\n"                                      \
          ".global " #sym "_end\n"                                      \
          #sym "_end:\n"                                                \
          ".previous\n");                                               \
  extern const uint8_t sym[]
"""


def emit_header(store, name, emit_names):
    upper = name.upper()
    out = []
    out.append("// Generated by tools/gen_huffman_blocklist.py. Do not edit.")
    out.append("#pragma once")
    out.append("")
    out.append('#include "TinyDNSHuffmanStore.h"')
    out.append("")
    out.append("// %s: %d domains, %d per block, %d blocks."
               % (name, store["count"], store["block_size"], store["block_count"]))
    out.append("")
    out.append("static const uint8_t PROGMEM %s_prefix_lens[256] = {" % name)
    out.append(c_bytes(store["prefix_lens"]))
    out.append("};")
    out.append("static const uint8_t PROGMEM %s_suffix_lens[256] = {" % name)
    out.append(c_bytes(store["suffix_lens"]))
    out.append("};")
    out.append("static const uint8_t PROGMEM %s_index[%d] = {"
               % (name, len(store["index"])))
    out.append(c_bytes(list(store["index"])))
    out.append("};")
    out.append("static const uint8_t PROGMEM %s_prefix_bits[%d] = {"
               % (name, len(store["prefix_bits"])))
    out.append(c_bytes(list(store["prefix_bits"])))
    out.append("};")
    out.append("static const uint8_t PROGMEM %s_suffix_bits[%d] = {"
               % (name, len(store["suffix_bits"])))
    out.append(c_bytes(list(store["suffix_bits"])))
    out.append("};")
    out.append("")
    out.append("static const TinyDNSHuffmanStoreData %s = {" % name)
    out.append("    %dUL, %d, %dUL," % (store["count"], store["block_size"], store["block_count"]))
    out.append("    %s_prefix_lens, %s_suffix_lens, %s_index," % (name, name, name))
    out.append("    %s_prefix_bits, %dUL, %s_suffix_bits, %dUL," % (
        name, store["prefix_bit_count"], name, store["suffix_bit_count"]))
    out.append("};")
    if emit_names:
        out.append("")
        out.append("// Domains in this store (used by the tests).")
        out.append("static const char *const %s_names[] = {" % name)
        for key in store["keys"]:
            domain = ".".join(reversed(key.split(".")))
            out.append('    "%s",' % domain)
        out.append("};")
        out.append("static const unsigned %s_names_count = %d;" % (name, store["count"]))
    out.append("")
    del upper
    return "\n".join(out)


def emit_incbin_header(store, name, header_path):
    """Write the binary tables next to the header and a header that .incbin's them."""
    import os
    header_dir = os.path.dirname(os.path.abspath(header_path))
    header_base = os.path.basename(header_path)
    tables = (("index", store["index"]),
              ("prefix_bits", store["prefix_bits"]),
              ("suffix_bits", store["suffix_bits"]))
    for key, data in tables:
        with open(os.path.join(header_dir, "%s.%s.bin" % (header_base, key)), "wb") as f:
            f.write(data)

    out = []
    out.append("// Generated by tools/gen_huffman_blocklist.py (--format incbin).")
    out.append("// Do not edit. Keep the %s.*.bin files next to this header." % header_base)
    out.append("#pragma once")
    out.append("")
    out.append('#include "TinyDNSHuffmanStore.h"')
    out.append("")
    out.append(INCBIN_MACRO.rstrip("\n"))
    out.append("")
    out.append("// %s: %d domains, %d per block, %d blocks."
               % (name, store["count"], store["block_size"], store["block_count"]))
    out.append("")
    out.append("static const uint8_t PROGMEM %s_prefix_lens[256] = {" % name)
    out.append(c_bytes(store["prefix_lens"]))
    out.append("};")
    out.append("static const uint8_t PROGMEM %s_suffix_lens[256] = {" % name)
    out.append(c_bytes(store["suffix_lens"]))
    out.append("};")
    for key, _ in tables:
        out.append('TINY_DNS_INCBIN(%s_%s, __FILE__ ".%s.bin");' % (name, key, key))
    out.append("")
    out.append("static const TinyDNSHuffmanStoreData %s = {" % name)
    out.append("    %dUL, %d, %dUL," % (store["count"], store["block_size"], store["block_count"]))
    out.append("    %s_prefix_lens, %s_suffix_lens, %s_index," % (name, name, name))
    out.append("    %s_prefix_bits, %dUL, %s_suffix_bits, %dUL," % (
        name, store["prefix_bit_count"], name, store["suffix_bit_count"]))
    out.append("};")
    out.append("")
    with open(header_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))



def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("input", help="blocklist file (AdBlock, hosts or plain)")
    parser.add_argument("-o", "--output", help="output header (default: stdout)")
    parser.add_argument("--name", default="tiny_dns_blocklist",
                        help="C identifier for the generated store")
    parser.add_argument("--block-size", type=int, default=32,
                        help="records per restart block (default 32)")
    parser.add_argument("--emit-names", action="store_true",
                        help="also emit the domain names (for tests)")
    parser.add_argument("--format", choices=("carray", "incbin"), default="carray",
                        help="carray: all tables in the header; incbin: tables as "
                             ".bin files embedded with .incbin (default carray)")
    args = parser.parse_args()

    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.name):
        parser.error("--name must be a C identifier")
    if not 1 <= args.block_size <= 65535:
        parser.error("--block-size must be 1..65535")

    if args.input.endswith(".gz"):
        import gzip
        with gzip.open(args.input, "rt", encoding="utf-8", errors="replace") as f:
            names = parse_block_domains(f)
    else:
        with open(args.input, encoding="utf-8", errors="replace") as f:
            names = parse_block_domains(f)
    if not names:
        print("no block domains found in %s" % args.input, file=sys.stderr)
        return 1

    store = build_store(names, args.block_size)
    check_kraft(store["prefix_lens"])
    check_kraft(store["suffix_lens"])
    if args.format == "incbin":
        if not args.output:
            parser.error("--format incbin needs -o/--output")
        emit_incbin_header(store, args.name, args.output)
    else:
        header = emit_header(store, args.name, args.emit_names)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(header)
        else:
            sys.stdout.write(header)

    total = (len(store["index"]) + len(store["prefix_bits"]) + len(store["suffix_bits"]))
    print("domains=%d blocks=%d data_bytes=%d (%.2f B/domain)"
          % (store["count"], store["block_count"], total, total / store["count"]),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
