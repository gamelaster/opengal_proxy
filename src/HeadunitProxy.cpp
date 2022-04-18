#include "HeadunitProxy.hpp"
#include "Utils.hpp"
#include <openssl/err.h>
#include "Certificates.hpp"

HeadunitProxy::HeadunitProxy()
  : Proxy()
{
  this->InitializeSSL();
  this->tag = "HUP";
}

void HeadunitProxy::ConnectToDevice(uint16_t port)
{
  struct sockaddr_in serverAddress;
  if ((this->sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    throw std::runtime_error("Failed to create sock");
  }

  serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(port);

  if (connect(this->sock, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
    throw std::runtime_error(fmt::format("Failed to connect to phone, reason: {0}", WSAGetLastError()));
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

void HeadunitProxy::InitializeSSL()
{
  this->BeginInitializeSSL(TLS_client_method());

  BIO* bio = BIO_new_mem_buf(Certificates::GALRootCertificate, strlen(Certificates::GALRootCertificate));
  this->sslState.rootCertificate = PEM_read_bio_X509(bio, 0, 0, 0); // TODO: Error handling
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::HeadunitPublicCertificate, strlen(Certificates::HeadunitPublicCertificate));
  this->sslState.devicePublicKey = PEM_read_bio_X509(bio, 0, 0, 0);
  BIO_free(bio);

  bio = BIO_new_mem_buf(Certificates::HeadunitPrivateKey, strlen(Certificates::HeadunitPrivateKey));
  this->sslState.devicePrivateKey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
  BIO_free(bio);

  this->FinishInitializeSSL();

  SSL_set_connect_state(sslState.ssl);
}
