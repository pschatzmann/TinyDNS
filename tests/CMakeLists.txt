add_executable(tinydns_tests test_main.cpp)

# stubs/ provides minimal Arduino.h, IPAddress.h and Client.h for the host.
# src/ is the library itself, compiled unchanged.
target_include_directories(tinydns_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stubs
  ${CMAKE_CURRENT_SOURCE_DIR}/../src)

add_test(NAME tinydns COMMAND tinydns_tests)
