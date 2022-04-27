// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2022 Marek Kraus <gamelaster@outlook.com>

#pragma once
#include "Proxy.hpp"

class HeadunitProxy final : public Proxy
{
public:
  HeadunitProxy();
  void ConnectToDevice(uint16_t port);

  void SendVersionRequest(std::pair<uint16_t, uint16_t> version);
  std::tuple<uint16_t, uint16_t, uint16_t> ReceiveVersionResponse();

  void DoSSLHandshake() override;
protected:
  void InitializeSSL();
};
