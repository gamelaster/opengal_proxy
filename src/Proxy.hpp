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
protected:
  std::string tag = "XXX";
  virtual void SendPacket(Packet& packet);
  virtual SharedPacket ReadPacket();
  void BeginInitializeSSL(const SSL_METHOD* sslMethod);
  void FinishInitializeSSL();
  SOCKET sock;
  std::thread readThread;
  std::thread writeThread;

  std::vector<uint8_t> readPacketBuffer = std::vector<uint8_t>(65535);
  std::vector<uint8_t> sendPacketBuffer = std::vector<uint8_t>(65535);

  // region SSL stuff
  struct {
    X509* rootCertificate;
    X509* devicePublicKey;
    EVP_PKEY* devicePrivateKey;
    BIO* readBio;
    BIO* writeBio;
    SSL* ssl;
    X509_STORE* x509Store;
    SSL_CTX* sslContext;
  } sslState;
  // endregion
};
