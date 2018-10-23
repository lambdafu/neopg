// Language support
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <cstdint>
#include <memory>

// (The following comment makes things happen in Doxygen.)
/// The NeoPG namespace.
namespace NeoPG {

// Allow byte literals such as 0xff_b.
constexpr std::uint8_t operator"" _b(unsigned long long v) {
  return static_cast<std::uint8_t>(v);
}

// https://herbsutter.com/gotw/_102/
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

}  // namespace NeoPG
