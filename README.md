# OpenGAL Proxy
Is proxy server, with which you can easily sniff packets transmitted between Android Auto Headunit and Mobile Device. 

# Building
## Requirements
Windows:
```
vcpkg install openssl fmt readerwriterqueue winpcap
```
Linux/Arch:
```
Install openssl, fmt, readerwriterqueue and winpcap from your distro repositories (or install manually)
```

## Getting certificates and keys

To eliminate a chance of Google making DMCA violation against this repository,
you need to source the required certificates and keys by yourself.

If you need help, contact me at `som (:D) marekkraus.sk`.

## Compiling
```bash
git submodule update --init --recursive
mkdir build
cd build
cmake ..
cmake -b .
```

# Supported features

- [X] Proxy packets between MD and HU
- [X] ~~Save packets into pcap file~~
- [ ] ~~Wireshark's extcap support~~
- [ ] ImGUI Analyzer

# Supported platforms

- [X] Windows
- [X] Linux

# Supported transports

- [X] TCP via ADB
- [ ] Direct TCP connection (wireless)
- [ ] USB AOA

# Known limitations

- Current TCP via ADB transport needs some improvements in packet reading. In some occassions, where are there big payloads (1080p HU resolution),
sometimes only half of packet is read and proxy don't handle this situation. 720p works well.

# How it works

TBD
