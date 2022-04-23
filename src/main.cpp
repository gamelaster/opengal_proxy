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
    mdp.Run();
    hup.ConnectToDevice(realMobileDevicePort);
    hup.Run();

    auto requestedVersion = mdp.ReceiveVersionRequest();
    hup.SendVersionRequest(requestedVersion);

    auto responseVersion = hup.ReceiveVersionResponse();
    mdp.SendVersionResponse(responseVersion);

    hup.DoSSLHandshake();
    mdp.DoSSLHandshake();

    auto hupProxy = std::thread([&] {
      while (true) {
        auto pkt = hup.DequeueIncomingPacket();
        fmt::printfl("[HUP] Sending packet ch {1}, {0} ({2:x}) to real HU.\n", pkt->GetMessageType(), pkt->channel, pkt->flags);
        mdp.EnqueueOutgoingPacket(pkt);
      }
    });
    hupProxy.detach();

    auto mdpProxy = std::thread([&] {
      while (true) {
        auto pkt = mdp.DequeueIncomingPacket();
        fmt::printfl("[MDP] Sending packet ch {1}, {0} ({2:x}) to real MD.\n", pkt->GetMessageType(), pkt->channel, pkt->flags);
        hup.EnqueueOutgoingPacket(pkt);
      }
    });
    mdpProxy.detach();

    fmt::printfl("Press any key to shutdown the proxy.\n");
    getchar();

  } catch (std::exception& ex) {
    fmt::printfl(ex.what());
    exit(-1);
  }

  // TODO: Close connections, join threads etc... :)

#ifdef WIN32
  WSACleanup();
#endif
}