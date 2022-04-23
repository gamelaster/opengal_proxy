#include <openssl/err.h>
#include "Proxy.hpp"
#include "Utils.hpp"

void Proxy::DoSSLHandshake()
{

}

SharedPacket Proxy::DequeueIncomingPacket()
{
  SharedPacket packet;
  this->incomingPacketQueue.wait_dequeue(packet);
  return packet;
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
  if (SSL_CTX_use_certificate(this->sslState.sslContext, sslState.publicCertificate) != 1) {
    throw std::runtime_error("Set Client Cert failed");
  }

  if (SSL_CTX_use_PrivateKey(this->sslState.sslContext, sslState.privateCertificate) != 1) {
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

void Proxy::Run()
{
  this->incomingPacketReadThread = std::thread(&Proxy::IncomingPacketReadThread, this);
  this->incomingPacketReadThread.detach();
  this->outgoingPacketWriteThread = std::thread(&Proxy::OutgoingPacketWriteThread, this);
  this->outgoingPacketWriteThread.detach();
}

[[noreturn]] void Proxy::IncomingPacketReadThread()
{
  while (true) {
    auto readLength = this->ReadPacket();
    uint32_t offset = 0;
    while (offset < readLength) {
      auto leftSize = readLength - offset;
      auto payloadSize = static_cast<uint16_t>((this->incomingPacketBuffer[offset + 2] << 8) | (this->incomingPacketBuffer[offset + 3]));
      if (payloadSize + 4 > leftSize) {
        throw std::runtime_error("Content size and receive size mismatch.");
      }
      auto p = std::make_shared<Packet>();
      p->channel = this->incomingPacketBuffer[offset + 0];
      p->flags = static_cast<PacketFlags>(this->incomingPacketBuffer[offset + 1]);
      auto payloadPosition = this->incomingPacketBuffer.begin() + offset + 4;
      if ((p->flags & PacketFlags::ENCRYPTED) == PacketFlags::ENCRYPTED) {
        this->DecryptIncomingPacket(p, payloadPosition, payloadSize);
      } else {
        p->payload = std::vector(this->incomingPacketBuffer.begin() + offset + 4, this->incomingPacketBuffer.begin() + offset + 4 + payloadSize);
      }
      this->incomingPacketQueue.enqueue(p);
      offset += payloadSize + 4;
    }
  }
}

void Proxy::DecryptIncomingPacket(const SharedPacket& packet, const std::vector<uint8_t>::iterator& payloadPosition, uint32_t payloadSize) const
{
  if (BIO_write(this->sslState.readBio, &(*payloadPosition), payloadSize) != payloadSize) {
    throw std::runtime_error("Failed to write data to read bio");
  }
  packet->payload = std::vector<uint8_t>(payloadSize);
  auto readResult = SSL_read(this->sslState.ssl, &packet->payload[0], packet->payload.size());
  if (readResult < 0) {
    int error = SSL_get_error(this->sslState.ssl, readResult);
    if (error != SSL_ERROR_WANT_READ) {
      ERR_print_errors_fp(stderr);
      ERR_clear_error();
      // TODO: Exception?
    }
  }
  packet->payload.resize(readResult);
}

uint32_t Proxy::ReadPacket()
{
  // TODO: Make this abstract to support multiple transports like USB or wireless (not via ADB)
  int recvSize;
  if ((recvSize = recv(this->sock, reinterpret_cast<char*>(&this->incomingPacketBuffer[0]), this->incomingPacketBuffer.capacity(), 0)) == SOCKET_ERROR) {
    throw std::runtime_error(fmt::format("Receive failed, reason: {0}", WSAGetLastError()));
  }
  return recvSize;
}

void Proxy::OutgoingPacketWriteThread()
{
  SharedPacket packet;
  while (true) {
    this->outgoingPacketQueue.wait_dequeue(packet);
    this->ProcessAndWritePacket(packet);
  }
}

void Proxy::ProcessAndWritePacket(const SharedPacket& packet)
{
  uint32_t headerSize = 4;
  uint32_t payloadSize = 0;
  this->outgoingPacketBuffer[0] = packet->channel;
  this->outgoingPacketBuffer[1] = static_cast<uint8_t>(packet->flags);
  auto payloadPosition = this->outgoingPacketBuffer.begin() + 4;
  if ((packet->flags & PacketFlags::ENCRYPTED) == PacketFlags::ENCRYPTED) {
    payloadSize = this->EncryptPacket(packet->payload.begin(), packet->payload.end(), payloadPosition);
  } else {
    std::copy(packet->payload.begin(), packet->payload.end(), payloadPosition);
    payloadSize = packet->payload.size();
  }
  this->outgoingPacketBuffer[2] = (payloadSize >> 8) & 0xFF;
  this->outgoingPacketBuffer[3] = payloadSize & 0xFF;
  this->WritePacket(headerSize + payloadSize);
}

uint32_t Proxy::EncryptPacket(std::vector<uint8_t>::iterator payloadBeginPos, std::vector<uint8_t>::iterator payloadEndPos, std::vector<uint8_t>::iterator destinationPayloadPos)
{
  auto payloadSize = payloadEndPos - payloadBeginPos;
  if (SSL_write(this->sslState.ssl, &(*payloadBeginPos), payloadSize) != payloadSize) {
    throw std::runtime_error("Failed to write data to write bio");
  }
  auto finalPayloadSize = BIO_pending(this->sslState.writeBio);
  auto readResult = BIO_read(this->sslState.writeBio, &(*destinationPayloadPos), finalPayloadSize);
  if (readResult < 0) {
    int error = SSL_get_error(this->sslState.ssl, readResult);
    if (error != SSL_ERROR_WANT_READ) {
      ERR_print_errors_fp(stderr);
      ERR_clear_error();
      // TODO: Exception?
    }
  }
  return finalPayloadSize;
}

void Proxy::WritePacket(uint32_t length)
{
  if (send(this->sock, reinterpret_cast<const char*>(&this->outgoingPacketBuffer[0]), length, 0) < 0) {
    throw std::runtime_error("Failed to send packet");
  }
}

void Proxy::EnqueueOutgoingPacket(SharedPacket packet)
{
  this->outgoingPacketQueue.enqueue(packet);
}

