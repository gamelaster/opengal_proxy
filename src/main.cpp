#include <fmt/printf.h>
#include <cstdint>
#include "MobileDeviceProxy.hpp"
#include "HeadunitProxy.hpp"
#include <openssl/applink.c>
#include "Utils.hpp"

#ifdef WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#endif

int main(int argc, char** argv)
{
  const uint16_t realMobileDevicePort = 5278;
  const uint16_t mobileDeviceProxyPort = 5277;

#ifdef WIN32
  {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
      fmt::print(stderr, "Failed to init WinSock {0}\n", WSAGetLastError());
      return -1;
    }
  }
#endif

  fmt::printfl("OpenGAL Proxy v1.0\nAuthor: Marek gamelaster/gamiee Kraus\n");
  try {
    auto mdp = MobileDeviceProxy();
    auto hup = HeadunitProxy();

    mdp.ListenAndWait(mobileDeviceProxyPort);
    hup.ConnectToDevice(realMobileDevicePort);

    auto requestedVersion = mdp.ReceiveVersionRequest();
    hup.SendVersionRequest(requestedVersion);

    auto responseVersion = hup.ReceiveVersionResponse();
    mdp.SendVersionResponse(responseVersion);

    hup.DoSSLHandshake();
    mdp.DoSSLHandshake();

    /* hup.OnMessageCallback([&mdp](std::shared_ptr<Packet> pkt) {
      mdp.SendPacketFromMD(pkt);
      return true;
    });

    mdp.OnMessageCallback([&hup](std::shared_ptr<Packet> pkt) {
      hup.SendPacketFromMD(pkt);
      return true;
    }); */

    hup.Run();
    mdp.Run();

    fmt::printfl("Press any key to shutdown the proxy.\n");
    getchar();

  } catch (std::exception& ex) {
    fmt::printfl(ex.what());
    exit(-1);
  }

  // TODO: Close connections :)

#ifdef WIN32
  WSACleanup();
#endif
}