// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2023 Marek Kraus <gamelaster@outlook.com>

#include "ImGUIAnalyzer.hpp"
#include "Utils.hpp"
#include <fmt/format.h>

void ImGUIAnalyzer::Initialize()
{
  if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
    throw std::runtime_error(fmt::format("[GUI] Failed to init SDL, reason: {0}", SDL_GetError()));
  }
  // Decide GL+GLSL versions
#if defined(IMGUI_IMPL_OPENGL_ES2)
  // GL ES 2.0 + GLSL 100
  const char* glsl_version = "#version 100";
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#elif defined(__APPLE__)
  // GL 3.2 Core + GLSL 150
  const char* glsl_version = "#version 150";
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG); // Always required on Mac
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
#else
  // GL 3.0 + GLSL 130
  const char* glsl_version = "#version 130";
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#endif

  // From 2.0.18: Enable native IME.
#ifdef SDL_HINT_IME_SHOW_UI
  SDL_SetHint(SDL_HINT_IME_SHOW_UI, "1");
#endif

  // Create window with graphics context
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
  SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
  SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
  SDL_WindowFlags windowFlags = (SDL_WindowFlags)(SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
  this->window = SDL_CreateWindow("OpenGAL Proxy", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 720, windowFlags);
  this->glContext = SDL_GL_CreateContext(this->window);
  SDL_GL_MakeCurrent(window, this->glContext);
  SDL_GL_SetSwapInterval(1); // Enable vsync

  // Setup Dear ImGui context
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
  ImGui::StyleColorsDark();
  ImGui_ImplSDL2_InitForOpenGL(window, glContext);
  ImGui_ImplOpenGL3_Init(glsl_version);
}

void ImGUIAnalyzer::Destroy()
{
  if (this->window != NULL) {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();

    SDL_GL_DeleteContext(glContext);
    SDL_DestroyWindow(window);
  }
}

void ImGUIAnalyzer::Run()
{
  this->guiThread = std::thread(&ImGUIAnalyzer::RenderThread, this);
  this->guiThread.detach();
}

void ImGUIAnalyzer::RenderThread()
{
  SDL_GL_MakeCurrent(this->window, this->glContext);
  const ImVec4 clearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
  bool done = false;
  ImGuiIO& io = ImGui::GetIO();
  while (!done) {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
      ImGui_ImplSDL2_ProcessEvent(&event);
      if (event.type == SDL_QUIT)
        done = true;
      if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window))
        done = true;
    }
    // Start the Dear ImGui frame
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame();
    ImGui::NewFrame();

    if (ImGui::Begin("Channels")) {
      if (ImGui::BeginTable("channels_table", 4)) {
        ImGui::TableSetupColumn("Channel ID");
        ImGui::TableSetupColumn("From Phone Packets");
        ImGui::TableSetupColumn("From Headunit Packets");
        ImGui::TableSetupColumn("Cancel");
        ImGui::TableHeadersRow();
        std::lock_guard lock(this->channelsMutex);
        ImGui::PushID("channels");
        for (auto it = this->channelsInfo.begin(); it != this->channelsInfo.end(); ++it) {
          auto& channelId = it->first;
          auto& info = it->second;
          ImGui::PushID(channelId);
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::Text("%lu", channelId);
          ImGui::TableSetColumnIndex(1);
          ImGui::Text("%lu", info.packetsFromPhoneCount);
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%lu", info.packetsFromHeadunitCount);
          ImGui::TableSetColumnIndex(3);
//          ImGui::Text("%08X", &info);
          ImGui::Checkbox("Phone", &info.cancelProxyPhone);
          ImGui::SameLine();
          ImGui::Checkbox("Headunit", &info.cancelProxyHeadunit);
          ImGui::PopID();
        }
        ImGui::PopID();
        ImGui::EndTable();
      }
      ImGui::End();
    }

    ImGui::Render();
    glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
    glClearColor(clearColor.x * clearColor.w, clearColor.y * clearColor.w, clearColor.z * clearColor.w, clearColor.w);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    SDL_GL_SwapWindow(window);
  }
}

bool ImGUIAnalyzer::AddPacket(ImGUIAnalyzer::PacketSource source, const SharedPacket& packet)
{
  std::lock_guard lock(this->channelsMutex);
  auto& info = this->channelsInfo[packet->channel];
  if (source == PacketSource::HEADUNIT) {
    info.packetsFromHeadunitCount++;
    return info.cancelProxyHeadunit;
  } else {
    info.packetsFromPhoneCount++;
    return info.cancelProxyPhone;
  }
}
