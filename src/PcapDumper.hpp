// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2022 Marek Kraus <gamelaster@outlook.com>

#pragma once

#include <string>
#include <pcap/pcap.h>
#include "Packet.hpp"
#include <thread>
#include <readerwriterqueue/readerwriterqueue.h>

using namespace moodycamel;

enum class SharedPacketForDumpSender {
  MOBILE_DEVICE,
  HEADUNIT
};

struct SharedPacketForDump {
  SharedPacket packet;
  SharedPacketForDumpSender sender;
};

class PcapDumper
{
public:
  virtual ~PcapDumper();
  void Run(const std::string& path);
  void DumpPacket(SharedPacketForDump packet);
private:
  [[noreturn]] void DumperPacketThread();

  pcap* pcap = NULL;
  pcap_dumper* pcapDumper = NULL;
  std::thread dumperThread;
  BlockingReaderWriterQueue<SharedPacketForDump> dumperPacketQueue;
  std::vector<uint8_t> dumpPacketBuffer = std::vector<uint8_t>(65535 * 2);
};

