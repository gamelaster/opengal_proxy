#pragma once

#include <vector>
#include <cstdint>

enum class PacketMessageType : uint16_t
{
  MESSAGE_VERSION_REQUEST = 1,
  MESSAGE_VERSION_RESPONSE = 2,
  MESSAGE_ENCAPSULATED_SSL = 3,
  MESSAGE_AUTH_COMPLETE = 4,
  MESSAGE_SERVICE_DISCOVERY_REQUEST = 5,
  MESSAGE_SERVICE_DISCOVERY_RESPONSE = 6,
  MESSAGE_CHANNEL_OPEN_REQUEST = 7,
  MESSAGE_CHANNEL_OPEN_RESPONSE = 8,
  MESSAGE_CHANNEL_CLOSE_NOTIFICATION = 9,
  MESSAGE_PING_REQUEST = 11,
  MESSAGE_PING_RESPONSE = 12,
  MESSAGE_NAV_FOCUS_REQUEST = 13,
  MESSAGE_NAV_FOCUS_NOTIFICATION = 14,
  MESSAGE_BYEBYE_REQUEST = 15,
  MESSAGE_BYEBYE_RESPONSE = 16,
  MESSAGE_VOICE_SESSION_NOTIFICATION = 17,
  MESSAGE_AUDIO_FOCUS_REQUEST = 18,
  MESSAGE_AUDIO_FOCUS_NOTIFICATION = 19,
  MESSAGE_CAR_CONNECTED_DEVICES_REQUEST = 20,
  MESSAGE_CAR_CONNECTED_DEVICES_RESPONSE = 21,
  MESSAGE_USER_SWITCH_REQUEST = 22,
  MESSAGE_BATTERY_STATUS_NOTIFICATION = 23,
  MESSAGE_CALL_AVAILABILITY_STATUS = 24,
  MESSAGE_USER_SWITCH_RESPONSE = 25,
  MESSAGE_SERVICE_DISCOVERY_UPDATE = 26,
  MESSAGE_UNEXPECTED_MESSAGE = 255,
  MESSAGE_FRAMING_ERROR = 65535,
};

enum class PacketFlags : uint8_t
{
  FRAG_FIRST = 0b0001,
  FRAG_LAST = 0b0010,
  BATCH = 0b0011,
  ENCRYPTED = 0b1000,
};

static PacketFlags operator &(PacketFlags lhs, PacketFlags rhs)
{
  return static_cast<PacketFlags> (
      static_cast<std::underlying_type<PacketFlags>::type>(lhs) &
          static_cast<std::underlying_type<PacketFlags>::type>(rhs)
  );
}

class Packet
{
public:
  inline PacketMessageType GetMessageType() {
    return static_cast<PacketMessageType>((this->payload[0] << 8) | (this->payload[1]));
  }

  inline void SetMessageType(PacketMessageType type) {
    this->payload[0] = (static_cast<uint16_t>(type) >> 8) & 0xFF;
    this->payload[1] = static_cast<uint16_t>(type) & 0xFF;
  }

  std::uint8_t channel;
  PacketFlags flags;
  // PacketMessageType GetMessageType;
  std::vector<uint8_t> payload;
  uint32_t finalLength;
  bool isPayloadDecrypted = false;
};

using SharedPacket = std::shared_ptr<Packet>;