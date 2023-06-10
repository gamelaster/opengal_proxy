// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2023 Marek Kraus <gamelaster@outlook.com>

#pragma once
#include <thread>
#include <imgui.h>
#include <SDL.h>
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <SDL_opengles2.h>
#else
#include <SDL_opengl.h>
#endif
#include <imgui_impl_sdl2.h>
#include <imgui_impl_opengl3.h>
#include "Packet.hpp"
#include <mutex>
#include <map>
#include <vector>

class ImGUIAnalyzer
{
public:
  enum class PacketSource { // TODO: Move elsewhere
    MOBILE_DEVICE,
    HEADUNIT
  };
  virtual ~ImGUIAnalyzer() {
    this->Destroy();
  }
  void Initialize();
  void Run();
  void Destroy();
  bool AddPacket(PacketSource source, const SharedPacket& packet);
private:
  void RenderThread();
  std::thread guiThread;
  SDL_Window* window;
  SDL_GLContext glContext;

  class ChannelInfo {
  public:
    bool cancelProxyHeadunit = false;
    bool cancelProxyPhone = false;
    uint64_t packetsFromPhoneCount = 0;
    uint64_t packetsFromHeadunitCount = 0;
  };
  std::mutex channelsMutex;
  std::map<uint16_t, ChannelInfo> channelsInfo;
};
