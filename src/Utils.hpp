#pragma once

#include <fmt/printf.h>
#include <fmt/core.h>
#include <cstdint>
#include <stdio.h>

// Because libfmt doesn't flush by default... *sigh
namespace fmt {
  template<typename S, typename... Args>
  inline void printfl(const S& formatString, Args&&... args) {
    fmt::vprint(formatString, fmt::make_args_checked<Args...>(formatString, args...));
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