#include "Proxy.hpp"
#include "Utils.hpp"

void Proxy::DoSSLHandshake()
{

}

void Proxy::Run()
{

}

void Proxy::SendPacket(Packet& packet)
{
  uint16_t packetSize = 4;
  this->writePacketBuffer[0] = packet.channel;
  this->writePacketBuffer[1] = static_cast<uint8_t>(packet.flags);
  this->writePacketBuffer[2] = (packet.payload.size() >> 8) & 0xFF;
  this->writePacketBuffer[3] = packet.payload.size() & 0xFF;
  packetSize += packet.payload.size();
  std::copy(packet.payload.begin(), packet.payload.end(), this->writePacketBuffer.begin() + 4);

  if (send(this->sock, reinterpret_cast<const char*>(&this->writePacketBuffer[0]), packetSize, 0) < 0) {
    throw std::runtime_error("Failed to send packet");
  }
}

Packet Proxy::ReadPacket()
{
  int recvSize;
  if ((recvSize = recv(this->sock, reinterpret_cast<char*>(&this->readPacketBuffer[0]), this->readPacketBuffer.capacity(), 0)) == SOCKET_ERROR) {
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

void Proxy::ReadThread()
{

}

void Proxy::BeginInitializeSSL(const SSL_METHOD* sslMethod)
{
  OPENSSL_init_ssl(NULL, NULL);

  this->sslState.sslContext = SSL_CTX_new(sslMethod);
  if (!this->sslState.sslContext) {
    throw std::runtime_error("SSL_CTX_new failed");
  }
}

void Proxy::FinishInitializeSSL()
{
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
}

