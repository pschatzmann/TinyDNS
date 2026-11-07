cmake_minimum_required(VERSION 3.16)
project(TinyDNS LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Host-side unit tests. Disable with: cmake -DBUILD_TESTING=OFF ...
include(CTest)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
