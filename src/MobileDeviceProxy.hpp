#pragma once
#include <thread>
#include <functional>
#include <openssl/ssl.h>
#include "Packet.hpp"

#include <cstdint>
#ifdef WIN32
#include <winsock2.h>

#endif

class MobileDeviceProxy
{
public:
  MobileDeviceProxy();
  void ListenAndWait(uint16_t port);
  void OnMessageCallback(std::function<bool(std::shared_ptr<Packet>)>&& callback) {
    this->onMessageCallback = std::move(callback);
  };
  std::pair<uint16_t, uint16_t> ReceiveVersionRequest();
  void SendVersionResponse(std::tuple<uint16_t, uint16_t, uint16_t> version);
  void DoSSLHandshake();
  void Run();
private:
  void SendPacket(Packet& packet);
  Packet ReadPacket();
  void ReadThread();
  void InitializeSSL();

  std::vector<uint8_t> readPacketBuffer = std::vector<uint8_t>(65535);
  std::vector<uint8_t> writePacketBuffer = std::vector<uint8_t>(65535);

  SOCKET serverSocket;
  SOCKET huSocket;
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
