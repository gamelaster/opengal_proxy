#include "MobileDeviceProxy.hpp"
#include "Certificates.hpp"
#include "Utils.hpp"
#include <openssl/err.h>

MobileDeviceProxy::MobileDeviceProxy()
{
  this->InitializeSSL();
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
  this->huSocket = accept(this->serverSocket, (struct sockaddr *)&clientAddress, &addressLength); // TODO: Error handling
  fmt::printfl("[MDP] Real HU connected!\n");
}

void MobileDeviceProxy::ReadThread()
{
  while (true) {
    auto pkt = this->ReadPacket();
    auto sharedPacket = std::make_shared<Packet>();
    sharedPacket->flags = pkt.flags;
    sharedPacket->channel = pkt.channel;
    if ((sharedPacket->flags & PacketFlags::ENCRYPTED) == PacketFlags::ENCRYPTED) {

    } else {
      sharedPacket->payload = pkt.payload;
    }
    this->onMessageCallback(sharedPacket);
  }
}

void MobileDeviceProxy::Run()
{
  this->readThread = std::thread(&MobileDeviceProxy::ReadThread, this);
  this->readThread.detach();
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

void MobileDeviceProxy::SendPacket(Packet& packet)
{
  uint16_t packetSize = 4;
  this->writePacketBuffer[0] = packet.channel;
  this->writePacketBuffer[1] = static_cast<uint8_t>(packet.flags);
  this->writePacketBuffer[2] = (packet.payload.size() >> 8) & 0xFF;
  this->writePacketBuffer[3] = packet.payload.size() & 0xFF;
  packetSize += packet.payload.size();
  std::copy(packet.payload.begin(), packet.payload.end(), this->writePacketBuffer.begin() + 4);

  if (send(this->huSocket, reinterpret_cast<const char*>(&this->writePacketBuffer[0]), packetSize, 0) < 0) {
    throw std::runtime_error("Failed to send packet");
  }
}

Packet MobileDeviceProxy::ReadPacket()
{
  int recvSize;
  if ((recvSize = recv(this->huSocket, reinterpret_cast<char*>(&this->readPacketBuffer[0]), this->readPacketBuffer.capacity(), 0)) == SOCKET_ERROR) {
    throw std::runtime_error(fmt::format("Receive failed, reason: {0}", WSAGetLastError()));
  }
  auto contentSize = static_cast<uint16_t>((this->readPacketBuffer[2] << 8) | (this->readPacketBuffer[3]));
  if (contentSize + 4 != recvSize) {
    throw std::runtime_error("Content size and receive size mismatch.");
  }
  Packet p;
  p.channel = this->readPacketBuffer[0];
  p.flags = static_cast<PacketFlags>(this->readPacketBuffer[1]);
  //p.GetMessageType = static_cast<PacketMessageType>((this->readPacketBuffer[4] << 8) | (this->readPacketBuffer[5]));
  p.payload = std::vector(this->readPacketBuffer.begin() + 4, this->readPacketBuffer.begin() + 4 + contentSize);
  return p;
}

void MobileDeviceProxy::InitializeSSL()
{
  OPENSSL_init_ssl(NULL, NULL);
  BIO* bio = BIO_new_mem_buf(Certificates::GALRootCertificate, strlen(Certificates::GALRootCertificate));
  this->sslState.rootCertificate = PEM_read_bio_X509(bio, 0, 0, 0); // TODO: Error handling
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::MobileDevicePublicCertificate, strlen(Certificates::MobileDevicePublicCertificate));
  this->sslState.devicePublicKey = PEM_read_bio_X509(bio, 0, 0, 0);
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::MobileDevicePrivateKey, strlen(Certificates::MobileDevicePrivateKey));
  this->sslState.devicePrivateKey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
  BIO_free(bio);

  this->sslState.sslContext = SSL_CTX_new(TLS_server_method());
  if (!this->sslState.sslContext) {
    throw std::runtime_error("SSL_CTX_new failed");
  }

  if (SSL_CTX_use_certificate(this->sslState.sslContext, sslState.devicePublicKey) != 1) {
    throw std::runtime_error("Set Client Cert failed");
  }

  if (SSL_CTX_use_PrivateKey(this->sslState.sslContext, sslState.devicePrivateKey) != 1) {
    throw std::runtime_error("Set Private Key failed");
  }

  if (SSL_CTX_set_min_proto_version(this->sslState.sslContext, 771LL) != 1) {
    throw std::runtime_error("Failed to set minimum TLS protocol");
  }

  SSL_CTX_set_options(this->sslState.sslContext, SSL_OP_NO_TLSv1_3);
  this->sslState.ssl = SSL_new(this->sslState.sslContext);
  if (!this->sslState.ssl) {
    throw std::runtime_error("Failed to alloc SSL");
  }

  if (SSL_check_private_key(this->sslState.ssl) != 1) {
    throw std::runtime_error("SSL check private key failed!");
  }

  this->sslState.readBio = BIO_new(BIO_s_mem());
  if (!this->sslState.readBio) {
    throw std::runtime_error("Failed to alloc read bio.");
  }

  this->sslState.writeBio = BIO_new(BIO_s_mem());
  if (!this->sslState.writeBio) {
    throw std::runtime_error("Failed to alloc write bio.");
  }

  SSL_set_bio(this->sslState.ssl, this->sslState.readBio, this->sslState.writeBio);

  this->sslState.x509Store = X509_STORE_new();
  if (!this->sslState.x509Store) {
    throw std::runtime_error("Failed to alloc x509 store.");
  }

  if (X509_STORE_add_cert(this->sslState.x509Store, sslState.rootCertificate) != 1) {
    throw std::runtime_error("Failed to set x509 root cert.");
  }
  X509_STORE_set_flags(this->sslState.x509Store, 0LL);

  SSL_set_accept_state(this->sslState.ssl);
  SSL_accept(this->sslState.ssl);
  SSL_set_bio(this->sslState.ssl, this->sslState.readBio, this->sslState.writeBio);
}
