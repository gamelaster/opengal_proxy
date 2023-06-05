// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2022 Marek Kraus <gamelaster@outlook.com>

#pragma once

#include <fmt/printf.h>
#include <fmt/core.h>
#include <cstdint>
#include <stdio.h>

// Because libfmt doesn't flush by default... *sigh
namespace fmt {
  template<typename S, typename... Args, typename Char = enable_if_t<detail::is_string<S>::value, char_t<S>>>
  inline void printfl(const S& formatString, Args&&... args) {
    fmt::vprint(formatString, fmt::make_format_args<buffer_context<char_t<S>>>(args...));
    std::fflush(stdout);
  }
};

namespace Utils {
  inline void Dump(std::string_view file, std::vector<uint8_t> data) {
    FILE* f = fopen(file.data(), "wb");
    fwrite(&data[0], 1, data.size(), f);
    fclose(f);
  }
}