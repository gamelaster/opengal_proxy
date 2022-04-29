cmake_minimum_required(VERSION 3.21)
project(opengal_proxy)

set(CMAKE_CXX_STANDARD 20)

add_executable(opengal_proxy src/main.cpp src/HeadunitProxy.cpp src/HeadunitProxy.hpp src/MobileDeviceProxy.cpp src/MobileDeviceProxy.hpp src/Packet.hpp src/Utils.hpp src/Proxy.cpp src/Proxy.hpp src/PcapDumper.cpp src/PcapDumper.hpp)

find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)

# https://github.com/microsoft/vcpkg/blob/master/ports/pcapplusplus/CMakeLists.txt
if (WIN32)
    find_path(PCAP_INCLUDES NAMES pcap.h)
    find_library(PCAP_LIBRARY_RELEASE NAMES wpcap PATH_SUFFIXES lib REQUIRED)
    find_library(PCAP_LIBRARY_DEBUG NAMES wpcap PATH_SUFFIXES lib REQUIRED)
else()
    find_path(PCAP_INCLUDES NAMES pcap.h)
    find_library(PCAP_LIBRARY_RELEASE NAMES pcap PATH_SUFFIXES lib REQUIRED)
    find_library(PCAP_LIBRARY_DEBUG NAMES pcap PATH_SUFFIXES lib REQUIRED)
endif()

target_link_libraries(opengal_proxy PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt
        ${PCAP_LIBRARY_RELEASE})

find_path(READERWRITERQUEUE_INCLUDE_DIRS "readerwriterqueue/atomicops.h")
target_include_directories(opengal_proxy PRIVATE ${READERWRITERQUEUE_INCLUDE_DIRS})
