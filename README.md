# OpenGAL Proxy
Is proxy server, with which you can easily sniff packets transmitted between Android Auto Headunit and Mobile Device. 

# Building

Windows:
```
vcpkg install openssl fmt readerwriterqueue winpcap
mkdir build
cd build
cmake ..
cmake -b .
```

# Supported features

- [X] Proxy packets between MD and HU
- [ ] Save packets into pcap file

# Supported platforms

- [X] Windows
- [ ] Linux

# Supported transports

- [X] TCP via ADB
- [ ] Direct TCP connection (wireless)
- [ ] USB AOA

# Known limitations

- Current TCP via ADB transport needs some improvements in packet reading. In some occassions, where are there big payloads (1080p HU resolution),
sometimes only half of packet is read and proxy don't handle this situation. 720p works well.

# How it works

TBD
