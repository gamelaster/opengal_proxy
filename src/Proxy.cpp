#include <openssl/err.h>
#include "Proxy.hpp"
#include "Utils.hpp"

void Proxy::DoSSLHandshake()
{

}

void Proxy::SendPacket(Packet& packet)
{
  uint16_t packetSize = 4;
  this->sendPacketBuffer[0] = packet.channel;
  this->sendPacketBuffer[1] = static_cast<uint8_t>(packet.flags);
  this->sendPacketBuffer[2] = (packet.payload.size() >> 8) & 0xFF;
  this->sendPacketBuffer[3] = packet.payload.size() & 0xFF;
  packetSize += packet.payload.size();
  std::copy(packet.payload.begin(), packet.payload.end(), this->sendPacketBuffer.begin() + 4);

  if (send(this->sock, reinterpret_cast<const char*>(&this->sendPacketBuffer[0]), packetSize, 0) < 0) {
    throw std::runtime_error("Failed to send packet");
  }
}

Packet Proxy::ReadPacket()
{
  int recvSize;
  if ((recvSize = recv(this->sock, reinterpret_cast<char*>(&this->readPacketBuffer[0]), this->readPacketBuffer.capacity(), 0)) == SOCKET_ERROR) {
    throw std::runtime_error(fmt::format("Receive failed, reason: {0}", WSAGetLastError()));
  }
  uint16_t offset = 0;
  while (offset < recvSize) {
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
}

SharedPacket Proxy::ReadAndProcessPacket()
{
  fmt::printfl("[{0}] Receiving packet...\n", this->tag);
  auto pkt = this->ReadPacket();
  fmt::printfl("[{0}] Packet received!\n", this->tag);
  auto sharedPacket = std::make_shared<Packet>();
  sharedPacket->flags = pkt.flags;
  sharedPacket->channel = pkt.channel;
  if ((sharedPacket->flags & PacketFlags::ENCRYPTED) == PacketFlags::ENCRYPTED) {
    if ((sharedPacket->flags & PacketFlags::BATCH) == PacketFlags::FRAG_FIRST) {
      throw std::runtime_error("FRAG_FIRST not implemented :(");
    }
    if (BIO_write(this->sslState.readBio, &pkt.payload[0], pkt.payload.size()) != pkt.payload.size()) {
      throw std::runtime_error("Failed to write data to read bio");
    }
    sharedPacket->payload = std::vector<uint8_t>(pkt.payload.size());
    auto readResult = SSL_read(this->sslState.ssl, &sharedPacket->payload[0], sharedPacket->payload.size());
    // fmt::printfl("[{0}] SSL pending: {1}, size: {2}, returned: {3}\n", this->tag, SSL_pending(this->sslState.ssl), sharedPacket->payload.size(), readResult);
    sharedPacket->payload.resize(readResult);
    if (readResult < 0) {
      int error = SSL_get_error(this->sslState.ssl, readResult);
      if (error != SSL_ERROR_WANT_READ) {
        ERR_print_errors_fp(stderr);
        ERR_clear_error();
        // TODO: Exception?
      }
    }
    Utils::Dump("test.bin", sharedPacket->payload);
  } else {
    sharedPacket->payload = pkt.payload;
  }
  return sharedPacket;
}

void Proxy::ProcessAndWritePacket(const SharedPacket& sharedPacket)
{
  auto pkt = Packet();
  pkt.flags = sharedPacket->flags;
  pkt.channel = sharedPacket->channel;
  if ((sharedPacket->flags & PacketFlags::ENCRYPTED) == PacketFlags::ENCRYPTED) {
    if (SSL_write(this->sslState.ssl, &sharedPacket->payload[0], sharedPacket->payload.size()) != sharedPacket->payload.size()) {
      throw std::runtime_error("Failed to write data to write bio");
    }
    pkt.payload = std::vector<uint8_t>(BIO_pending(this->sslState.writeBio));
    // fmt::printfl("[{0}] Write BIO pending: {1}, size: {2}\n", this->tag, BIO_pending(this->sslState.writeBio), sharedPacket->payload.size());
    auto readResult = BIO_read(this->sslState.writeBio, &pkt.payload[0], pkt.payload.size());
    if (readResult < 0) {
      int error = SSL_get_error(this->sslState.ssl, readResult);
      if (error != SSL_ERROR_WANT_READ) {
        ERR_print_errors_fp(stderr);
        ERR_clear_error();
        // TODO: Exception?
      }
    }
  } else {
    pkt.payload = sharedPacket->payload;
  }
  this->SendPacket(pkt);
}

void Proxy::ProxyPacket(const SharedPacket& pkt)
{
  this->packetWriteQueue.enqueue(pkt);
}

[[noreturn]] void Proxy::ReadThread()
{
  SharedPacket pkt;
  while (true) {
    pkt = this->ReadAndProcessPacket();
    this->onMessageCallback(pkt);
  }
}

[[noreturn]] void Proxy::WriteThread()
{
  SharedPacket pkt;
  while (true) {
    this->packetWriteQueue.wait_dequeue(pkt);
    this->ProcessAndWritePacket(pkt);
  }
}

void Proxy::Run()
{
  this->readThread = std::thread(&Proxy::ReadThread, this);
  this->readThread.detach();
  this->writeThread = std::thread(&Proxy::WriteThread, this);
  this->writeThread.detach();
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

