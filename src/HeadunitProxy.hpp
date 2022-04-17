#pragma once
#include <thread>
#include <functional>
#include <openssl/ssl.h>
#include "Packet.hpp"

#include <cstdint>
#ifdef WIN32
#include <winsock2.h>
#endif

class HeadunitProxy
{
public:
  HeadunitProxy();
  void ConnectToDevice(uint16_t port);
  void OnMessageCallback(std::function<bool(std::shared_ptr<Packet>)>&& callback) {
    this->onMessageCallback = std::move(callback);
  };
  void SendVersionRequest(std::pair<uint16_t, uint16_t> version);
  std::tuple<uint16_t, uint16_t, uint16_t> ReceiveVersionResponse();
  void DoSSLHandshake();

  void Run();
private:
  void SendPacket(Packet& packet);
  Packet ReadPacket();
  void ReadThread();
  void InitializeSSL();

  std::vector<uint8_t> readPacketBuffer = std::vector<uint8_t>(65535);
  std::vector<uint8_t> writePacketBuffer = std::vector<uint8_t>(65535);

  SOCKET mdSocket;
  std::thread readThread;
  std::function<bool(std::shared_ptr<Packet>)> onMessageCallback;

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
