// Host-side stand-in for the Arduino Client interface.
#pragma once

#include <Arduino.h>
#include <IPAddress.h>

class Client {
 public:
  virtual ~Client() = default;
  virtual int connect(IPAddress ip, uint16_t port) = 0;
  virtual size_t write(const uint8_t *buf, size_t size) = 0;
  virtual int available() = 0;
  virtual int read(uint8_t *buf, size_t size) = 0;
  virtual bool connected() = 0;
  virtual void stop() = 0;
  virtual void flush() {}
};
