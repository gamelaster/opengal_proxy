#pragma once
#include <thread>
#include <functional>
#include <queue>
#include <openssl/ssl.h>
#include "Packet.hpp"
#include <readerwriterqueue/readerwriterqueue.h>

#include <cstdint>
#ifdef WIN32
#include <WinSock2.h>
#endif

using namespace moodycamel;

class Proxy
{
public:
  virtual void DoSSLHandshake();
  void Run();
  SharedPacket DequeueIncomingPacket();
  void EnqueueOutgoingPacket(SharedPacket packet);
protected:
  std::string tag = "XXX";
  void ProcessAndWritePacket(const SharedPacket& packet);
  void BeginInitializeSSL(const SSL_METHOD* sslMethod);
  void FinishInitializeSSL();
  uint32_t ReadPacket();
  void WritePacket(uint32_t length);
  void DecryptIncomingPacket(const SharedPacket& packet, const std::vector<uint8_t>::iterator& payloadPosition, uint32_t payloadSize) const;
  uint32_t EncryptPacket(std::vector<uint8_t>::iterator payloadBeginPos, std::vector<uint8_t>::iterator payloadEndPos, std::vector<uint8_t>::iterator destinationPayloadPos);
  [[noreturn]] void IncomingPacketReadThread();
  [[noreturn]] void OutgoingPacketWriteThread();

  SOCKET sock;

  std::thread incomingPacketReadThread;
  BlockingReaderWriterQueue<SharedPacket> incomingPacketQueue;
  std::thread outgoingPacketWriteThread;
  BlockingReaderWriterQueue<SharedPacket> outgoingPacketQueue;

  /**
   * According to source code, default max fragment size is 16128, but MD can have it larger up to 65539.
   * For now, I will keep the maximum uint16_t size.
   */
  std::vector<uint8_t> incomingPacketBuffer = std::vector<uint8_t>(65535 * 4);
  std::vector<uint8_t> outgoingPacketBuffer = std::vector<uint8_t>(65535 * 4);

  // region SSL stuff
  struct {
    X509* rootCertificate;
    X509* publicCertificate;
    EVP_PKEY* privateCertificate;
    BIO* readBio;
    BIO* writeBio;
    SSL* ssl;
    X509_STORE* x509Store;
    SSL_CTX* sslContext;
  } sslState;
  // endregion
};
