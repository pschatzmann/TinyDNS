// Host-side stand-in for the Arduino core. Used only by the CMake tests.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <string>

// Mock clock, defined in test_main.cpp. Tests advance it directly.
extern uint32_t g_mockMillis;
inline uint32_t millis() { return g_mockMillis; }

// Minimal subset of the Arduino String API used by the library.
class String {
 public:
  String() = default;
  String(const char *s) : s_(s ? s : "") {}
  String(const std::string &s) : s_(s) {}

  size_t length() const { return s_.size(); }
  const char *c_str() const { return s_.c_str(); }

  int indexOf(const char *needle) const {
    size_t p = s_.find(needle);
    return p == std::string::npos ? -1 : (int)p;
  }
  int indexOf(char c, size_t from = 0) const {
    size_t p = s_.find(c, from);
    return p == std::string::npos ? -1 : (int)p;
  }
  String substring(size_t from) const { return String(s_.substr(from)); }
  String substring(size_t from, size_t to) const {
    return String(s_.substr(from, to - from));
  }
  String operator+(const String &o) const { return String(s_ + o.s_); }

 private:
  std::string s_;
};
