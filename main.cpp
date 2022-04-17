#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <stdint.h>
#include <stdexcept>
#include <openssl/ssl.h>
#include "src/Certificates.hpp"
#include <openssl/err.h>
#include <openssl/applink.c>

#pragma comment(lib,"ws2_32.lib")

static SOCKET activeSock;

void dump(const char* filename, void* buffer, int length)
{
  FILE* f = fopen(filename, "wb");
  fwrite(buffer, 1, length, f);
  fclose(f);
}

void connectToPhone(const char* ip, uint16_t port)
{
  struct sockaddr_in server;
  if((activeSock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    throw std::runtime_error("Failed to create socket");
  }

  printf("Socket created.\n");

  server.sin_addr.s_addr = inet_addr(ip);
  server.sin_family = AF_INET;
  server.sin_port = htons(port);

  if (connect(activeSock, (struct sockaddr *) &server, sizeof(server)) < 0) {
    throw std::runtime_error("Failed to connect to phone");
  }
}

void sendVersionRequest() {
  char msg[10];
  msg[0] = 0x00;   // channel ID ???
  msg[1] = 0b0011; // not encrypted FIRST | LAST = BULK
  msg[2] = 0x00;   // size
  msg[3] = 0x06;   // size
  msg[4] = 0x00;   // MSG ID (VERSION_REQUEST)
  msg[5] = 0x01;   // MSG ID (VERSION_REQUEST)
  msg[6] = 0x00;   // Version Minor
  msg[7] = 0x01;   // Version Minor
  msg[8] = 0x00;   // Version Major
  msg[9] = 0x07;   // Version Major

  if (send(activeSock, msg, 10, 0) < 0) {
    throw std::runtime_error("Failed to send version request packet");
  }
}

void receiveVersionResponse() {
  uint8_t reply[100];
  int recvSize = 0;

  if ((recvSize = recv(activeSock, reinterpret_cast<char*>(reply), 100, 0)) == SOCKET_ERROR) {
    throw std::runtime_error("Receive failed");
  }

  printf("Phone API version: %d.%d (encrypt? %d)\n", reply[9], reply[7], reply[11]);
}

// region SSL
struct {
  X509* rootCertificateX509;
  X509* clientCertificateX509;
  EVP_PKEY* privateKeyPKEY;
  BIO* readBio;
  BIO* writeBio;
  SSL* ssl;
  X509_STORE* x509Store;
  SSL_CTX* sslContext;
} sslState;



void initializeSsl(bool isServer = false)
{
  OPENSSL_init_ssl(NULL, NULL);
  BIO* bio = BIO_new_mem_buf(AARootCertificate, strlen(AARootCertificate));
  sslState.rootCertificateX509 = PEM_read_bio_X509(bio, 0, 0, 0);
  BIO_free(bio);

  if (!isServer) {
    bio = BIO_new_mem_buf(AAClientCertificate, strlen(AAClientCertificate));
    sslState.clientCertificateX509 = PEM_read_bio_X509(bio, 0, 0, 0);
    BIO_free(bio);

    bio = BIO_new_mem_buf(AAPrivateKey, strlen(AAPrivateKey));
    sslState.privateKeyPKEY = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
    BIO_free(bio);
  } else {
    bio = BIO_new_mem_buf(AAPhoneCert, strlen(AAPhoneCert));
    sslState.clientCertificateX509 = PEM_read_bio_X509(bio, 0, 0, 0);
    BIO_free(bio);

    bio = BIO_new_mem_buf(AAPhonePrivateKey, strlen(AAPhonePrivateKey));
    sslState.privateKeyPKEY = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
    BIO_free(bio);
  }

  sslState.sslContext = SSL_CTX_new(isServer ? TLS_server_method() : TLS_client_method());
  if (!sslState.sslContext) {
    throw std::runtime_error("SSL_CTX_new failed");
  }


  if (SSL_CTX_use_certificate(sslState.sslContext, sslState.clientCertificateX509) != 1) {
    throw std::runtime_error("Set Client Cert failed");
  }

  if (SSL_CTX_use_PrivateKey(sslState.sslContext, sslState.privateKeyPKEY) != 1) {
    throw std::runtime_error("Set Private Key failed");
  }

  if (SSL_CTX_set_min_proto_version(sslState.sslContext, 771LL) != 1) {
    throw std::runtime_error("Failed to set minimum TLS protocol");
  }

  SSL_CTX_set_options(sslState.sslContext, SSL_OP_NO_TLSv1_3);
  sslState.ssl = SSL_new(sslState.sslContext);
  if (!sslState.ssl) {
    throw std::runtime_error("Failed to alloc SSL");
  }

  if (SSL_check_private_key(sslState.ssl) != 1) {
    throw std::runtime_error("SSL check private key failed!");
  }

  if (isServer) {
    SSL_set_accept_state(sslState.ssl);
    SSL_accept(sslState.ssl);
  } else {
    SSL_set_connect_state(sslState.ssl);
  }

  sslState.readBio = BIO_new(BIO_s_mem());
  if (!sslState.readBio) {
    throw std::runtime_error("Failed to alloc read bio.");
  }

  sslState.writeBio = BIO_new(BIO_s_mem());
  if (!sslState.writeBio) {
    throw std::runtime_error("Failed to alloc write bio.");
  }

  SSL_set_bio(sslState.ssl, sslState.readBio, sslState.writeBio);

  sslState.x509Store = X509_STORE_new();
  if (!sslState.x509Store) {
    throw std::runtime_error("Failed to alloc x509 store.");
  }

  if (X509_STORE_add_cert(sslState.x509Store, sslState.rootCertificateX509) != 1) {
    throw std::runtime_error("Failed to set x509 root cert.");
  }
  X509_STORE_set_flags(sslState.x509Store, 0LL);
}

void sslHandshake(uint8_t* cert, int length, bool isServer = false) {
  static bool wtf = false;
  if (isServer && !wtf) {
    SSL_set_accept_state(sslState.ssl);
    SSL_set_bio(sslState.ssl, sslState.readBio, sslState.writeBio);
    wtf = true;
  }
  if (cert != NULL) {
    BIO_write(sslState.readBio, cert, length);
  }
  int handshakeResult;
  if (!isServer) {
    handshakeResult = SSL_do_handshake(sslState.ssl);
  } else {
    handshakeResult = SSL_accept(sslState.ssl);
  }
  int error = SSL_get_error(sslState.ssl, handshakeResult);
  ERR_print_errors_fp(stderr);
  const char* state = SSL_state_string_long(sslState.ssl);
  printf("ssl state=%s %d, %d\n", state, handshakeResult, error);
  if (handshakeResult == 1) {
    const char* version = SSL_get_version(sslState.ssl);
    const SSL_CIPHER* currentCipher = SSL_get_current_cipher(sslState.ssl);
    const char* currentCipherName = SSL_CIPHER_get_name(currentCipher);
    printf("SSL version=%s Cipher name=%s\n", version, currentCipherName);
    if (isServer) {
      int pendingData = BIO_pending(sslState.writeBio);
      if (pendingData > 0) {
        int frameSize = pendingData + 2 + 4;
        int contentSize = pendingData + 2;
        uint8_t* frame = static_cast<uint8_t*>(malloc(frameSize));
        frame[0] = 0x00;
        frame[1] = 0b11; // FIRST | LAST = BULK
        frame[2] = (contentSize >> 8) & 0xFF; // size
        frame[3] = (contentSize & 0xFF); // size
        frame[4] = 0x00; // CMD ID
        frame[5] = 0x03; // CMD ID
        BIO_read(sslState.writeBio, frame + 6, pendingData);
        if (send(activeSock, reinterpret_cast<const char*>(frame), frameSize, 0) < 0) {
          throw std::runtime_error("Failed to send SSL Handshake packet");
        }
        free(frame);
      }
    }
  } else if (error == SSL_ERROR_WANT_READ) {
    int pendingData = BIO_pending(sslState.writeBio);
    if (pendingData > 0) {
      int frameSize = pendingData + 2 + 4;
      int contentSize = pendingData + 2;
      uint8_t* frame = static_cast<uint8_t*>(malloc(frameSize));
      frame[0] = 0x00;
      frame[1] = 0b11; // FIRST | LAST = BULK
      frame[2] = (contentSize >> 8) & 0xFF; // size
      frame[3] = (contentSize & 0xFF); // size
      frame[4] = 0x00; // CMD ID
      frame[5] = 0x03; // CMD ID
      BIO_read(sslState.writeBio, frame + 6, pendingData);
      if (send(activeSock, reinterpret_cast<const char*>(frame), frameSize, 0) < 0) {
        throw std::runtime_error("Failed to send SSL Handshake packet");
      }
      free(frame);
    }
  } else {
    throw std::runtime_error("Something failed during handshake");
  }
}
// end region


int main(int argc , char *argv[])
{
#if 1
  initializeSsl(true);
  WSADATA wsa;

  if (WSAStartup(MAKEWORD(2, 2),&wsa) != 0) {
    printf("Failed to init WinSock %d", WSAGetLastError());
    return 1;
  }
  SOCKET sock;
  if((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    throw std::runtime_error("Failed to create socket");
  }
  struct sockaddr_in server, client;

  server.sin_addr.s_addr = inet_addr("0.0.0.0");
  server.sin_family = AF_INET;
  server.sin_port = htons(5277);

  if(bind(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
    printf("Bind failed with error code : %d" , WSAGetLastError());
    exit(EXIT_FAILURE);
  }

  listen(sock, 3);
  int c = sizeof(struct sockaddr_in);

  activeSock = accept(sock, (struct sockaddr *)&client, &c);
  printf("Connected!\n");

  { // Receive Version Request
    int recv_size = 0;
    uint8_t reply[100];
    if ((recv_size = recv(activeSock, reinterpret_cast<char*>(reply), 100, 0)) == SOCKET_ERROR) {
      throw std::runtime_error("Receive failed");
    }
  }

  { // Send Version Response
    uint8_t buf[] = {0x00, 0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00};
    send(activeSock, reinterpret_cast<const char*>(buf), 12, 0);
  }

  for (int i = 0; i < 2; i++) {
    int recv_size = 0;
    uint8_t reply[4000];
    if ((recv_size = recv(activeSock, reinterpret_cast<char*>(reply), 4000, 0)) == SOCKET_ERROR) {
      throw std::runtime_error("Receive failed");
    }
    // TODO: verify response
    int contentSize = (reply[2] << 8) | (reply[3]);
    sslHandshake(reply + 4 + 2, contentSize - 2, true);
  }
  {
    int recv_size = 0;
    uint8_t reply[4000];
    if ((recv_size = recv(activeSock, reinterpret_cast<char*>(reply), 4000, 0)) == SOCKET_ERROR) {
      throw std::runtime_error("Receive failed");
    }
    dump("aaaaaa.bin", reply, recv_size);
  }

#else
  initializeSsl();
  WSADATA wsa;

  if (WSAStartup(MAKEWORD(2, 2),&wsa) != 0) {
    printf("Failed to init WinSock %d", WSAGetLastError());
    return 1;
  }

  connectToPhone("127.0.0.1", 5278);
  puts("Connected");

  sendVersionRequest();
  receiveVersionResponse();

  sslHandshake(NULL, 0);
  for (int i = 0; i < 2; i++) {
    int recv_size = 0;
    uint8_t reply[4000];
    if ((recv_size = recv(activeSock, reinterpret_cast<char*>(reply), 4000, 0)) == SOCKET_ERROR) {
      throw std::runtime_error("Receive failed");
    }
    // TODO: verify response
    int contentSize = (reply[2] << 8) | (reply[3]);
    sslHandshake(reply + 4 + 2, contentSize - 2);
  }
  // TODO: Verify peer, HU verifies if the MD is legit AA app ... sslWrapper::verifyPeer

#if 0
  auto peerCertificate = SSL_get_peer_certificate(sslState.ssl);
  /*EVP_PKEY *pkey = NULL;
  if ((pkey = X509_get_pubkey(peerCertificate)) == NULL)
    printf("Error getting public key from certificate\n");

  /*if(!X509_(outbio, pkey))
    printf("Error writing public key data in PEM format");*/
  BIO* outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  PEM_write_bio_X509(outbio, peerCertificate);
  X509_free(peerCertificate);
#endif

#endif

  return 0;
}