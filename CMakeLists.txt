cmake_minimum_required(VERSION 3.21)
project(opengal_proxy)

set(CMAKE_CXX_STANDARD 20)

add_executable(opengal_proxy src/main.cpp src/HeadunitProxy.cpp src/HeadunitProxy.hpp src/MobileDeviceProxy.cpp src/MobileDeviceProxy.hpp src/Packet.hpp src/Utils.hpp src/Proxy.cpp src/Proxy.hpp src/SocketUtils.hpp src/ImGUIAnalyzer.cpp src/ImGUIAnalyzer.hpp)

find_package(OpenSSL REQUIRED)
find_package(SDL2 REQUIRED)
find_package(fmt CONFIG REQUIRED)

# https://github.com/microsoft/vcpkg/blob/master/ports/pcapplusplus/CMakeLists.txt
if (WIN32)
    find_path(PCAP_INCLUDES NAMES pcap.h)
    find_library(PCAP_LIBRARY_RELEASE NAMES wpcap PATH_SUFFIXES lib REQUIRED)
    find_library(PCAP_LIBRARY_DEBUG NAMES wpcap PATH_SUFFIXES lib REQUIRED)

    target_sources(opengal_proxy PRIVATE src/PcapDumper.cpp src/PcapDumper.hpp)
else()
    find_path(PCAP_INCLUDES NAMES pcap.h)
    find_library(PCAP_LIBRARY_RELEASE NAMES pcap PATH_SUFFIXES lib REQUIRED)
    find_library(PCAP_LIBRARY_DEBUG NAMES pcap PATH_SUFFIXES lib REQUIRED)
endif()

target_link_libraries(opengal_proxy PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt
        ${PCAP_LIBRARY_RELEASE}
        ${SDL2_LIBRARIES})

find_path(READERWRITERQUEUE_INCLUDE_DIRS "readerwriterqueue/atomicops.h")
target_include_directories(opengal_proxy PRIVATE
        ${READERWRITERQUEUE_INCLUDE_DIRS}
        ${SDL2_INCLUDE_DIRS})

# ImGUI
target_sources(opengal_proxy PRIVATE
        vendor/imgui/imgui.cpp
        vendor/imgui/imgui_draw.cpp
        vendor/imgui/imgui_tables.cpp
        vendor/imgui/imgui_widgets.cpp
        vendor/imgui/backends/imgui_impl_opengl3.cpp
        vendor/imgui/backends/imgui_impl_sdl2.cpp)
target_include_directories(opengal_proxy PRIVATE
        vendor/imgui
        vendor/imgui/backends)
if (WIN32)

else()
    target_link_libraries(opengal_proxy PRIVATE GL)
endif()