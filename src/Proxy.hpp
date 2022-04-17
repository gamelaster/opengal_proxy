#pragma once
#include <thread>
#include <functional>
#include <openssl/ssl.h>
#include "Packet.hpp"

#include <cstdint>
#ifdef WIN32
#include <WinSock2.h>
#endif

class Proxy
{
public:
  void OnMessageCallback(std::function<bool(std::shared_ptr<Packet>)>&& callback) {
    this->onMessageCallback = std::move(callback);
  };

  virtual void DoSSLHandshake();
  virtual void Run();
protected:
  virtual void SendPacket(Packet& packet);
  virtual Packet ReadPacket();
  virtual void ReadThread();
  void BeginInitializeSSL(const SSL_METHOD* sslMethod);
  void FinishInitializeSSL();

  SOCKET sock;
  std::thread readThread;
  std::function<bool(std::shared_ptr<Packet>)> onMessageCallback;

  std::vector<uint8_t> readPacketBuffer = std::vector<uint8_t>(65535);
  std::vector<uint8_t> writePacketBuffer = std::vector<uint8_t>(65535);

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
