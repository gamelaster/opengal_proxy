cmake_minimum_required(VERSION 3.21)
project(opengal_proxy)

set(CMAKE_CXX_STANDARD 20)

add_executable(opengal_proxy src/main.cpp src/HeadunitProxy.cpp src/HeadunitProxy.hpp src/MobileDeviceProxy.cpp src/MobileDeviceProxy.hpp src/Packet.hpp src/Utils.hpp)

find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)

target_link_libraries(opengal_proxy PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt)