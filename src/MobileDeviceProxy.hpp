// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2022 Marek Kraus <gamelaster@outlook.com>

#pragma once
#include "Proxy.hpp"

class MobileDeviceProxy final : public Proxy
{
public:
  MobileDeviceProxy();
  void ListenAndWait(uint16_t port);

  std::pair<uint16_t, uint16_t> ReceiveVersionRequest();
  void SendVersionResponse(std::tuple<uint16_t, uint16_t, uint16_t> version);

  void DoSSLHandshake() override;
private:
  void InitializeSSL();

  SOCKET serverSocket;
};
