// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2022 Marek Kraus <gamelaster@outlook.com>

#include "PcapDumper.hpp"

#ifdef WIN32
// Credits: https://stackoverflow.com/a/26085827/2046497
int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
  // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
  // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
  // until 00:00:00 January 1, 1970
  static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

  SYSTEMTIME  system_time;
  FILETIME    file_time;
  uint64_t    time;

  GetSystemTime( &system_time );
  SystemTimeToFileTime( &system_time, &file_time );
  time =  ((uint64_t)file_time.dwLowDateTime )      ;
  time += ((uint64_t)file_time.dwHighDateTime) << 32;

  tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
  tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
  return 0;
}
#endif

void PcapDumper::Run(const std::string& path)
{
  this->pcap = pcap_open_dead(DLT_NULL, 65535);
  this->pcapDumper = pcap_dump_open(this->pcap, path.c_str());

  this->dumperThread = std::thread(&PcapDumper::DumperPacketThread, this);
  this->dumperThread.detach();
}

PcapDumper::~PcapDumper()
{
  pcap_close(this->pcap);
  pcap_dump_close(this->pcapDumper);
}

[[noreturn]] void PcapDumper::DumperPacketThread()
{
  while (true) {
    SharedPacketForDump dumpPacket;
    auto& packet = dumpPacket.packet;
    this->dumperPacketQueue.wait_dequeue(dumpPacket);

    this->dumpPacketBuffer[0] = 0;
    this->dumpPacketBuffer[1] = 0;
    this->dumpPacketBuffer[2] = 0;
    this->dumpPacketBuffer[3] = 0;
    this->dumpPacketBuffer[4] = static_cast<uint8_t>(dumpPacket.sender);

    uint32_t headerSize = 4;
    uint32_t payloadSize;
    if ((packet->flags & PacketFlags::BATCH) == PacketFlags::FRAG_FIRST) {
      headerSize = 8;
    }
    this->dumpPacketBuffer[8 + 0] = packet->channel;
    this->dumpPacketBuffer[8 + 1] = static_cast<uint8_t>(packet->flags);
    auto payloadPosition = this->dumpPacketBuffer.begin() + 8 + headerSize;
    std::copy(packet->payload.begin(), packet->payload.end(), payloadPosition);
    payloadSize = packet->payload.size();
    this->dumpPacketBuffer[8 + 2] = (payloadSize >> 8) & 0xFF;
    this->dumpPacketBuffer[8 + 3] = payloadSize & 0xFF;
    if ((packet->flags & PacketFlags::BATCH) == PacketFlags::FRAG_FIRST) {
      this->dumpPacketBuffer[8 + 4] = (packet->finalLength >> 24) & 0xFF;
      this->dumpPacketBuffer[8 + 5] = (packet->finalLength >> 16) & 0xFF;
      this->dumpPacketBuffer[8 + 6] = (packet->finalLength >> 8) & 0xFF;
      this->dumpPacketBuffer[8 + 7] = packet->finalLength & 0xFF;
    }

    auto dumpPacketSize = 8 + headerSize + payloadSize;

    static struct pcap_pkthdr packet_header;
    gettimeofday(&packet_header.ts, NULL);
    packet_header.caplen = dumpPacketSize;
    packet_header.len = dumpPacketSize;
    pcap_dump((u_char*)(this->pcapDumper), &packet_header, const_cast<const u_char*>(&this->dumpPacketBuffer[0]));
  }
}

void PcapDumper::DumpPacket(SharedPacketForDump packet)
{
  this->dumperPacketQueue.enqueue(packet);
}
