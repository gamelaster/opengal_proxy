#include "MobileDeviceProxy.hpp"
#include "Certificates.hpp"
#include "Utils.hpp"
#include <openssl/err.h>

MobileDeviceProxy::MobileDeviceProxy()
{
  this->InitializeSSL();
  this->tag = "MDP";
}

void MobileDeviceProxy::ListenAndWait(uint16_t port)
{
  if ((this->serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    throw std::runtime_error(fmt::format("[MDP] Failed to create socket, reason: {0}", WSAGetLastError()));
  }

  struct sockaddr_in serverAddress;
  serverAddress.sin_addr.s_addr = inet_addr("0.0.0.0");
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(port);

  if (bind(this->serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
    throw std::runtime_error(fmt::format("[MDP] Failed to bind, reason: {0}", WSAGetLastError()));
  }

  int error = listen(this->serverSocket, 3);
  if (error != 0) {
    throw std::runtime_error(fmt::format("[MDP] Failed to listen, reason: {0}", WSAGetLastError()));
  }

  fmt::printfl("[MDP] Listening on port {0}, waiting for real HU to connect...\n", port);

  struct sockaddr_in clientAddress;
  int addressLength = sizeof(struct sockaddr_in);
  this->sock = accept(this->serverSocket, (struct sockaddr *)&clientAddress, &addressLength); // TODO: Error handling
  fmt::printfl("[MDP] Real HU connected!\n");
}

std::pair<uint16_t, uint16_t> MobileDeviceProxy::ReceiveVersionRequest()
{
  fmt::printfl("[MDP] Waiting for receiving Version Request from real HU...");
  auto pkt = this->ReadPacket();
  if (pkt.GetMessageType() != PacketMessageType::MESSAGE_VERSION_REQUEST) {
    throw std::runtime_error("Not received message request.");
  }
  auto versionPair = std::make_pair(
      static_cast<uint16_t>((pkt.payload[4] << 8) | (pkt.payload[5])),
      static_cast<uint16_t>((pkt.payload[2] << 8) | (pkt.payload[3])));

  fmt::printfl(" Received request for version {0}.{1}.\n", versionPair.first, versionPair.second);
  return versionPair;
}

void MobileDeviceProxy::SendVersionResponse(std::tuple<uint16_t, uint16_t, uint16_t> version)
{
  Packet pkt;
  pkt.channel = 0x00;
  pkt.flags = PacketFlags::BATCH;
  pkt.payload = std::vector<uint8_t>(8);
  pkt.SetMessageType(PacketMessageType::MESSAGE_VERSION_RESPONSE);
  pkt.payload[2] = (std::get<1>(version) >> 8) & 0xFF;
  pkt.payload[3] = (std::get<1>(version)) & 0xFF;
  pkt.payload[4] = (std::get<0>(version) >> 8) & 0xFF;
  pkt.payload[5] = (std::get<0>(version)) & 0xFF;
  pkt.payload[6] = (std::get<2>(version) >> 8) & 0xFF;
  pkt.payload[7] = (std::get<2>(version)) & 0xFF;
  this->SendPacket(pkt);
}

void MobileDeviceProxy::DoSSLHandshake()
{
  for (int i = 0; i < 2; i++) {
    fmt::printfl("[MDP] Waiting for receiving SSL Handshake from real HU...");
    auto pkt = this->ReadPacket();
    if (pkt.GetMessageType() != PacketMessageType::MESSAGE_ENCAPSULATED_SSL) {
      throw std::runtime_error("Not received encapsulated SSL.");
    }
    BIO_write(this->sslState.readBio, &pkt.payload[2], pkt.payload.size() - 2);
    int acceptResult = SSL_accept(this->sslState.ssl);
    int error = SSL_get_error(sslState.ssl, acceptResult);
    if (error == SSL_ERROR_SSL) {
      ERR_print_errors_fp(stderr);
    }
    const char* state = SSL_state_string_long(sslState.ssl);
    fmt::printfl(" Received! SSL State={0} {1}, {2}\n", state, acceptResult, error);
    if (acceptResult != 1 && error != SSL_ERROR_WANT_READ) {
      throw std::runtime_error("Something failed during handshake");
    }
    if (acceptResult == 1) {
      const char* version = SSL_get_version(this->sslState.ssl);
      const SSL_CIPHER* currentCipher = SSL_get_current_cipher(this->sslState.ssl);
      const char* currentCipherName = SSL_CIPHER_get_name(currentCipher);
      fmt::printfl("[MDP] Handshake finished, SSL version={0}, cipher={1}\n", version, currentCipherName);
    }
    int sslDataLength = BIO_pending(sslState.writeBio);
    Packet respPkt;
    respPkt.channel = 0x00;
    respPkt.flags = PacketFlags::BATCH;
    respPkt.payload = std::vector<uint8_t>(sslDataLength + 2);
    respPkt.SetMessageType(PacketMessageType::MESSAGE_ENCAPSULATED_SSL);
    BIO_read(this->sslState.writeBio, &respPkt.payload[2], sslDataLength);
    this->SendPacket(respPkt);
  }
}

void MobileDeviceProxy::InitializeSSL()
{
  this->BeginInitializeSSL(TLS_server_method());

  BIO* bio = BIO_new_mem_buf(Certificates::GALRootCertificate, strlen(Certificates::GALRootCertificate));
  this->sslState.rootCertificate = PEM_read_bio_X509(bio, 0, 0, 0); // TODO: Error handling
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::MobileDevicePublicCertificate, strlen(Certificates::MobileDevicePublicCertificate));
  this->sslState.devicePublicKey = PEM_read_bio_X509(bio, 0, 0, 0);
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::MobileDevicePrivateKey, strlen(Certificates::MobileDevicePrivateKey));
  this->sslState.devicePrivateKey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
  BIO_free(bio);

  this->FinishInitializeSSL();

  SSL_CTX_set_cipher_list(this->sslState.sslContext, "ECDHE-RSA-AES128-GCM-SHA256");
  SSL_CTX_set_ecdh_auto(this->sslState.sslContext, 1);

  SSL_set_accept_state(this->sslState.ssl);
  SSL_accept(this->sslState.ssl);
  SSL_set_bio(this->sslState.ssl, this->sslState.readBio, this->sslState.writeBio);
}
