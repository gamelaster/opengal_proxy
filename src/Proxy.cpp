#include <openssl/err.h>
#include "Proxy.hpp"
#include "Utils.hpp"

void Proxy::DoSSLHandshake()
{

}

void Proxy::SendPacket(Packet& packet)
{

}

SharedPacket Proxy::ReadPacket()
{
  return std::make_shared<Packet>();
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

