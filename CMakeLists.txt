cmake_minimum_required(VERSION 3.21)
project(proxy_c)

set(CMAKE_CXX_STANDARD 20)

add_executable(proxy_c main.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(proxy_c PRIVATE OpenSSL::SSL OpenSSL::Crypto)
