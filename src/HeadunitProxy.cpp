#include "HeadunitProxy.hpp"
#include "Utils.hpp"
#include <openssl/err.h>
#include "Certificates.hpp"

HeadunitProxy::HeadunitProxy()
{
  this->InitializeSSL();
}

void HeadunitProxy::ConnectToDevice(uint16_t port)
{
  struct sockaddr_in serverAddress;
  if ((this->mdSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    throw std::runtime_error("Failed to create socket");
  }

  serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(port);

  if (connect(this->mdSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
    throw std::runtime_error(fmt::format("Failed to connect to phone, reason: {0}", WSAGetLastError()));
  }
}

void HeadunitProxy::Run()
{
  this->readThread = std::thread(&HeadunitProxy::ReadThread, this);
  this->readThread.detach();
}

void HeadunitProxy::ReadThread()
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

void HeadunitProxy::SendVersionRequest(std::pair<uint16_t, uint16_t> version)
{
  Packet pkt;
  pkt.channel = 0x00;
  pkt.flags = PacketFlags::BATCH;
  pkt.payload = std::vector<uint8_t>(6);
  pkt.SetMessageType(PacketMessageType::MESSAGE_VERSION_REQUEST);
  pkt.payload[2] = (version.second >> 8) & 0xFF;
  pkt.payload[3] = (version.second) & 0xFF;
  pkt.payload[4] = (version.first >> 8) & 0xFF;
  pkt.payload[5] = (version.first) & 0xFF;
  fmt::printfl("[HUP] Sending version request to real MD...\n");
  this->SendPacket(pkt);
}

std::tuple<uint16_t, uint16_t, uint16_t> HeadunitProxy::ReceiveVersionResponse()
{
  fmt::printfl("[HUP] Waiting for receiving Version Response from real MD...");
  auto pkt = this->ReadPacket();
  if (pkt.GetMessageType() != PacketMessageType::MESSAGE_VERSION_RESPONSE) {
    throw std::runtime_error("Not received message response.");
  }

  auto versionTuple = std::make_tuple(
      static_cast<uint16_t>((pkt.payload[4] << 8) | (pkt.payload[5])),
      static_cast<uint16_t>((pkt.payload[2] << 8) | (pkt.payload[3])),
      static_cast<uint16_t>((pkt.payload[6] << 8) | (pkt.payload[7])));

  fmt::printfl(" Received response with version {0}.{1} (unknown flag {2}).\n", std::get<0>(versionTuple), std::get<1>(versionTuple), std::get<2>(versionTuple));
  return versionTuple;
}

void HeadunitProxy::DoSSLHandshake()
{
  for (int i = 0; i < 3; i++) {
    int handshakeResult = SSL_do_handshake(this->sslState.ssl);
    int error = SSL_get_error(sslState.ssl, handshakeResult);
    if (error == SSL_ERROR_SSL) {
      ERR_print_errors_fp(stderr);
    }
    const char* state = SSL_state_string_long(sslState.ssl);
    fmt::printfl("[HUP] Doing SSL Handshake! SSL State={0} {1}, {2}\n", state, handshakeResult, error);
    if (handshakeResult == 1) {
      const char* version = SSL_get_version(this->sslState.ssl);
      const SSL_CIPHER* currentCipher = SSL_get_current_cipher(this->sslState.ssl);
      const char* currentCipherName = SSL_CIPHER_get_name(currentCipher);
      fmt::printfl("[HUP] Handshake finished, SSL version={0}, cipher={1}\n", version, currentCipherName);
    } else if (error == SSL_ERROR_WANT_READ) {
      int sslDataLength = BIO_pending(sslState.writeBio);
      Packet pkt;
      pkt.channel = 0x00;
      pkt.flags = PacketFlags::BATCH;
      pkt.payload = std::vector<uint8_t>(sslDataLength + 2);
      pkt.SetMessageType(PacketMessageType::MESSAGE_ENCAPSULATED_SSL);
      BIO_read(this->sslState.writeBio, &pkt.payload[2], sslDataLength);
      this->SendPacket(pkt);
      auto respPkt = this->ReadPacket();
      if (respPkt.GetMessageType() != PacketMessageType::MESSAGE_ENCAPSULATED_SSL) {
        throw std::runtime_error("Not received encapsulated SSL.");
      }
      BIO_write(this->sslState.readBio, &respPkt.payload[2], respPkt.payload.size() - 2);
    } else {
      throw std::runtime_error("Something failed during handshake");
    }
  }
}

void HeadunitProxy::SendPacket(Packet& packet)
{
  uint16_t packetSize = 4;
  this->writePacketBuffer[0] = packet.channel;
  this->writePacketBuffer[1] = static_cast<uint8_t>(packet.flags);
  this->writePacketBuffer[2] = (packet.payload.size() >> 8) & 0xFF;
  this->writePacketBuffer[3] = packet.payload.size() & 0xFF;
  packetSize += packet.payload.size();
  std::copy(packet.payload.begin(), packet.payload.end(), this->writePacketBuffer.begin() + 4);

  if (send(this->mdSocket, reinterpret_cast<const char*>(&this->writePacketBuffer[0]), packetSize, 0) < 0) {
    throw std::runtime_error("Failed to send packet");
  }
}

Packet HeadunitProxy::ReadPacket()
{
  int recvSize;
  if ((recvSize = recv(this->mdSocket, reinterpret_cast<char*>(&this->readPacketBuffer[0]), this->readPacketBuffer.capacity(), 0)) == SOCKET_ERROR) {
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

void HeadunitProxy::InitializeSSL()
{
  OPENSSL_init_ssl(NULL, NULL);
  BIO* bio = BIO_new_mem_buf(Certificates::GALRootCertificate, strlen(Certificates::GALRootCertificate));
  this->sslState.rootCertificate = PEM_read_bio_X509(bio, 0, 0, 0); // TODO: Error handling
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::HeadunitPublicCertificate, strlen(Certificates::HeadunitPublicCertificate));
  this->sslState.devicePublicKey = PEM_read_bio_X509(bio, 0, 0, 0);
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::HeadunitPrivateKey, strlen(Certificates::HeadunitPrivateKey));
  this->sslState.devicePrivateKey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
  BIO_free(bio);

  this->sslState.sslContext = SSL_CTX_new(TLS_client_method());
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

  SSL_set_connect_state(sslState.ssl);

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
}
